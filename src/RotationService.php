<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\LifetimePolicy;

/**
 * @api Issues a new secret for an existing key_prefix and optional grace window.
 *
 * Invalid, negative, or above-max grace hours become 0 (no previous secret). A
 * second rotation replaces the previous grace secret — only the secret displaced
 * by the latest rotate stays valid until `previousKeyValidUntil`.
 *
 * Refuses revoked or expired keys and `oauth_grant` rows. Validates `key_prefix`
 * against the codec’s canonical shape (or an accepting legacy matcher at `$now`).
 * A legacy prefix is migrated to a **fresh canonical** token (`issue()`). With
 * `$graceHours` > 0 the old prefix is kept as `previous_key_prefix` so the legacy
 * plaintext keeps working through the normal grace window (F10 / Luca 2026-11-22).
 *
 * **Product obligation:** call `rotate` inside a DB transaction with
 * `lockForUpdate` on the key row, then write every returned field **unconditionally**
 * (including nulls when grace is 0). The package does not persist.
 */
final class RotationService
{
    public const int DEFAULT_MAX_GRACE_HOURS = 168; // @pest-mutate-ignore: IncrementInteger,DecrementInteger

    public function __construct(
        private int $maxGraceHours = self::DEFAULT_MAX_GRACE_HOURS,
        private ?LifetimePolicy $lifetimePolicy = null,
    ) {}

    /**
     * @param  int  $graceHours  Prefer values from {@see normalizeGraceHours}
     */
    public function rotate(
        ApiKeyRecord $record,
        TokenCodec $codec,
        Clock $clock,
        int $graceHours,
        ?\DateTimeImmutable $newExpiresAt = null,
    ): Rotation {
        $now = $clock->now();

        if ($record->credentialKind() === CredentialKind::OauthGrant) {
            throw new \InvalidArgumentException('Cannot rotate an OAuth grant API key row.');
        }

        if ($record->revokedAt() !== null) {
            throw new \InvalidArgumentException('Cannot rotate a revoked API key.');
        }

        if ($record->expiresAt() !== null && $now >= $record->expiresAt()) {
            throw new \InvalidArgumentException('Cannot rotate an expired API key.');
        }

        $expiresAt = $newExpiresAt ?? $record->expiresAt();
        if ($this->lifetimePolicy !== null && ! $this->lifetimePolicy->allowsExpiry($expiresAt, $now)) {
            throw new \InvalidArgumentException('Cannot rotate: expiry exceeds the lifetime policy.');
        }

        $keyPrefix = $record->keyPrefix();
        if (! $codec->isValidKeyPrefix($keyPrefix, $now)) {
            throw new \InvalidArgumentException(
                'API key prefix is not recognised by the codec (canonical or legacy).',
            );
        }

        $graceHours = self::normalizeGraceHours($graceHours, $this->maxGraceHours);
        $canonical = $codec->isCanonicalKeyPrefix($keyPrefix);
        $issued = $canonical ? $codec->reissueForPrefix($keyPrefix) : $codec->issue();

        if ($graceHours <= 0) {
            return new Rotation(
                newPlainText: $issued->plainText,
                newKeyPrefix: $issued->keyPrefix,
                newKeyHash: $issued->keyHash,
                previousKeyHash: null,
                previousKeyValidUntil: null,
                lastRotatedAt: $now,
                tokenVersion: $issued->tokenVersion,
                previousKeyPrefix: null,
            );
        }

        return new Rotation(
            newPlainText: $issued->plainText,
            newKeyPrefix: $issued->keyPrefix,
            newKeyHash: $issued->keyHash,
            previousKeyHash: $record->keyHash(),
            previousKeyValidUntil: $now->add(new \DateInterval('PT'.$graceHours.'H')),
            lastRotatedAt: $now,
            tokenVersion: $issued->tokenVersion,
            previousKeyPrefix: $canonical ? null : $keyPrefix,
        );
    }

    /**
     * Config grace as a whole number of hours in `[0, $maxGraceHours]`.
     * Non-integers, negatives, or values above the max → 0 (fail closed: never
     * extend the old secret on a misconfiguration; avoids DateInterval overflow).
     * A negative ceiling also fails closed (`$parsed > $maxGraceHours`).
     */
    public static function normalizeGraceHours(
        mixed $configValue,
        int $maxGraceHours = self::DEFAULT_MAX_GRACE_HOURS,
    ): int {
        if (is_bool($configValue)) {
            return 0;
        }

        // min_range 0 is intentional: grace of exactly 0 must parse as int 0, not false.
        $parsed = filter_var(
            $configValue,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0]], // @pest-mutate-ignore: IncrementInteger
        );

        if (! is_int($parsed)) {
            return 0;
        }

        if ($parsed > $maxGraceHours) {
            return 0;
        }

        return $parsed;
    }

    public function maxGraceHours(): int
    {
        return $this->maxGraceHours;
    }
}
