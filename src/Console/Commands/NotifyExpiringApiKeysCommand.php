<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Notification;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;
use Qiick\ApiKeys\Events\ApiKeyExpiryNoticeSent;
use Qiick\ApiKeys\Events\ApiKeyLegacyFormatWarningSent;
use Qiick\ApiKeys\ExpiryRecipient;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;

/**
 * @api Daily idempotent expiry notices and legacy-format T−90 warnings.
 *
 * Expiry: non-revoked `api_key` rows with `expires_at` within
 * `api-keys.expiry.notice_days` and null `expiry_notified_at`.
 * Claim takes a lease on `expiry_notice_claimed_at` (app clock, not DB
 * `NOW()`); success stamps `expiry_notified_at`. A dead worker after claim
 * is reclaimable once `api-keys.expiry.claim_lease_seconds` elapses. Keep
 * that lease above worst-case send latency, and keep worker clocks on
 * shared NTP UTC — skew or a send longer than the lease can double-notify.
 *
 * N2: when `now` is within `api-keys.legacy.warn_days_before` of
 * `accept_until`, warns owners of active `token_version` 0 rows once per
 * key/cut-off via {@see LegacyFormatWarningGate}, with the same protocol and
 * the same lease: resolve recipients, claim, send, then mark sent or release.
 */
final class NotifyExpiringApiKeysCommand extends Command
{
    protected $signature = 'api-keys:notify-expiring';

    protected $description = 'Notify recipients about API keys nearing expiry and legacy-format EOL';

    public function handle(
        ApiKeyRepository $repository,
        ExpiryRecipientResolver $recipientResolver,
        Clock $clock,
        Dispatcher $events,
        LegacyFormatWarningGate $legacyWarningGate,
    ): int {
        $configuredNoticeDays = config('api-keys.expiry.notice_days', 7);
        $noticeDays = filter_var(
            $configuredNoticeDays,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0]],
        );
        if (! is_int($noticeDays)) {
            $this->error('api-keys.expiry.notice_days must be an integer >= 0.');

            return self::FAILURE;
        }

        $configuredLeaseSeconds = config('api-keys.expiry.claim_lease_seconds', 900);
        $leaseSeconds = filter_var(
            $configuredLeaseSeconds,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]],
        );
        if (! is_int($leaseSeconds)) {
            $this->error('api-keys.expiry.claim_lease_seconds must be an integer >= 1.');

            return self::FAILURE;
        }

        $now = $clock->now();
        $until = $now->add(new \DateInterval('P'.$noticeDays.'D'));
        $roles = $this->recipientRoles();
        $notificationClass = config(
            'api-keys.expiry.notification',
            ApiKeyExpiringNotification::class,
        );

        if (! is_string($notificationClass) || ! class_exists($notificationClass)) {
            $this->error('api-keys.expiry.notification must be a notification class.');

            return self::FAILURE;
        }

        $notified = 0;

        foreach ($repository->expiringUnnotified($until) as $record) {
            $expiresAt = $record->expiresAt();
            if ($expiresAt === null) {
                continue;
            }

            $recipients = iterator_to_array($recipientResolver->recipientsFor($record, $roles), false);
            if ($recipients === []) {
                continue;
            }

            // Lease claim before send; dead workers are reclaimable after TTL.
            if (! $repository->claimExpiryNotice($record, $now, $leaseSeconds)) {
                continue;
            }

            $notification = new $notificationClass($record, $expiresAt);

            try {
                Notification::send($recipients, $notification);
            } catch (\Throwable $exception) {
                $repository->releaseExpiryNotice($record);
                $this->error('Expiry notice failed for '.$record->publicId().': '.$exception->getMessage());

                continue;
            }

            $repository->markExpiryNotified($record, $now);
            $events->dispatch(new ApiKeyExpiryNoticeSent(
                apiKeyId: $record->publicId(),
                expiresAt: $expiresAt,
                notifiedAt: $now,
            ));
            $notified++;
        }

        $this->info("Expiry notices sent: {$notified}");

        $legacyWarned = $this->sendLegacyFormatWarnings(
            $repository,
            $recipientResolver,
            $legacyWarningGate,
            $events,
            $roles,
            $now,
            $leaseSeconds,
        );
        $this->info("Legacy-format warnings sent: {$legacyWarned}");

        return self::SUCCESS;
    }

    /**
     * @param  list<ExpiryRecipient>  $roles
     */
    private function sendLegacyFormatWarnings(
        ApiKeyRepository $repository,
        ExpiryRecipientResolver $recipientResolver,
        LegacyFormatWarningGate $legacyWarningGate,
        Dispatcher $events,
        array $roles,
        \DateTimeImmutable $now,
        int $leaseSeconds,
    ): int {
        $acceptUntil = $this->legacyAcceptUntil();
        if ($acceptUntil === null) {
            return 0;
        }

        $warnDays = filter_var(
            config('api-keys.legacy.warn_days_before', 90),
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0]],
        );
        if (! is_int($warnDays) || $warnDays === 0) {
            return 0;
        }

        $windowStart = $acceptUntil->sub(new \DateInterval('P'.$warnDays.'D'));
        if ($now < $windowStart || $now >= $acceptUntil) {
            return 0;
        }

        $notificationClass = config(
            'api-keys.legacy.warning_notification',
            ApiKeyLegacyFormatWarningNotification::class,
        );
        if (! is_string($notificationClass) || ! class_exists($notificationClass)) {
            $this->error('api-keys.legacy.warning_notification must be a notification class.');

            return 0;
        }

        $warned = 0;

        foreach ($repository->findActiveLegacy() as $record) {
            $idempotencyKey = 'api-keys:legacy-format-warning:'
                .$record->publicId()
                .':'
                .$acceptUntil->format(\DateTimeInterface::ATOM);

            // Resolve before claiming: a key with no recipient yet must stay claimable.
            $recipients = iterator_to_array($recipientResolver->recipientsFor($record, $roles), false);
            if ($recipients === []) {
                continue;
            }

            $leaseOwner = $legacyWarningGate->claim($idempotencyKey, $leaseSeconds);
            if ($leaseOwner === null) {
                continue;
            }

            try {
                Notification::send($recipients, new $notificationClass($record, $acceptUntil));
            } catch (\Throwable $exception) {
                $legacyWarningGate->release($idempotencyKey, $leaseOwner);
                $this->error('Legacy-format warning failed for '.$record->publicId().': '.$exception->getMessage());

                continue;
            }

            $legacyWarningGate->markSent($idempotencyKey, $leaseOwner);
            $events->dispatch(new ApiKeyLegacyFormatWarningSent(
                apiKeyId: $record->publicId(),
                acceptUntil: $acceptUntil,
                warnedAt: $now,
            ));
            $warned++;
        }

        return $warned;
    }

    private function legacyAcceptUntil(): ?\DateTimeImmutable
    {
        $acceptUntil = config('api-keys.legacy.accept_until');
        if (! is_string($acceptUntil) || $acceptUntil === '') {
            return null;
        }

        $parsed = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $acceptUntil);
        if ($parsed instanceof \DateTimeImmutable) {
            return $parsed;
        }

        if (str_ends_with($acceptUntil, 'Z')) {
            $normalized = substr($acceptUntil, 0, -1).'+00:00';
            $parsedZulu = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $normalized);
            if ($parsedZulu instanceof \DateTimeImmutable) {
                return $parsedZulu;
            }
        }

        return null;
    }

    /**
     * @return list<ExpiryRecipient>
     */
    private function recipientRoles(): array
    {
        $configured = config('api-keys.expiry.recipients', ['owner', 'issuer']);
        if (! is_array($configured)) {
            return [ExpiryRecipient::Owner, ExpiryRecipient::Issuer];
        }

        $roles = [];

        foreach ($configured as $value) {
            if (! is_string($value)) {
                continue;
            }

            $role = ExpiryRecipient::tryFrom($value);
            if ($role !== null) {
                $roles[] = $role;
            }
        }

        return $roles;
    }
}
