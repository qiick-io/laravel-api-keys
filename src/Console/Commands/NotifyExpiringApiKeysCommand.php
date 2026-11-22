<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Notification;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;
use Qiick\ApiKeys\Events\ApiKeyExpiryNoticeSent;
use Qiick\ApiKeys\ExpiryRecipient;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;

/**
 * @api Daily idempotent expiry notices for non-revoked API keys.
 *
 * Finds rows with `expires_at` within `api-keys.expiry.notice_days` and null
 * `expiry_notified_at`, notifies resolved recipients, then stamps the column.
 */
final class NotifyExpiringApiKeysCommand extends Command
{
    protected $signature = 'api-keys:notify-expiring';

    protected $description = 'Notify recipients about API keys nearing expiry';

    public function handle(
        ApiKeyRepository $repository,
        ExpiryRecipientResolver $recipientResolver,
        Clock $clock,
        Dispatcher $events,
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

            $notification = new $notificationClass($record, $expiresAt);
            Notification::send($recipients, $notification);
            $repository->markExpiryNotified($record, $now);
            $events->dispatch(new ApiKeyExpiryNoticeSent(
                apiKeyId: $record->publicId(),
                expiresAt: $expiresAt,
                notifiedAt: $now,
            ));
            $notified++;
        }

        $this->info("Expiry notices sent: {$notified}");

        return self::SUCCESS;
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
