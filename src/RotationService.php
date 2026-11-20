<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\Clock;

/**
 * @api Issues a new secret for an existing key_prefix and optional grace window.
 *
 * Invalid, negative, or above-max grace hours become 0 (no previous secret). A
 * second rotation replaces the previous grace secret — only the secret displaced
 * by the latest rotate stays valid until `previousKeyValidUntil`.
 *
 * Refuses revoked or expired keys. Validates `key_prefix` against the codec’s
 * canonical shape (or an accepting legacy matcher at `$now`) so a typo cannot
 * brick a row. A legacy prefix is migrated to a **fresh canonical** token
 * (`issue()`), not reissued behind `ek_…`.
 *
 * **Product obligation:** call `rotate` inside a DB transaction with
 * `lockForUpdate` on the key row, then write `key_prefix`, `key_hash`,
 * `previous_key_hash`, and `previous_key_valid_until` **unconditionally**
 * (including nulls when grace is 0; including the new canonical prefix when
 * migrating off legacy). The package does not persist.
 */
final class RotationService
{
    public const int DEFAULT_MAX_GRACE_HOURS = 168; // @pest-mutate-ignore: IncrementInteger,DecrementInteger

    public function __construct(
        private int $maxGraceHours = self::DEFAULT_MAX_GRACE_HOURS,
    ) {}

    /**
     * @param  int  $graceHours  Prefer values from {@see normalizeGraceHours}
     */
    public function rotate(
        ApiKeyRecord $record,
        TokenCodec $codec,
        Clock $clock,
        int $graceHours,
    ): Rotation {
        $now = $clock->now();

        if ($record->revokedAt() !== null) {
            throw new \InvalidArgumentException('Cannot rotate a revoked API key.');
        }

        if ($record->expiresAt() !== null && $now >= $record->expiresAt()) {
            throw new \InvalidArgumentException('Cannot rotate an expired API key.');
        }

        $keyPrefix = $record->keyPrefix();
        if (! $codec->isValidKeyPrefix($keyPrefix, $now)) {
            throw new \InvalidArgumentException(
                'API key prefix is not recognised by the codec (canonical or legacy).',
            );
        }

        $graceHours = self::normalizeGraceHours($graceHours, $this->maxGraceHours);
        // Legacy → canonical migration: never reissue behind an ek_-shaped prefix.
        $issued = $codec->isCanonicalKeyPrefix($keyPrefix)
            ? $codec->reissueForPrefix($keyPrefix)
            : $codec->issue();

        if ($graceHours <= 0) {
            return new Rotation(
                newPlainText: $issued->plainText,
                newKeyPrefix: $issued->keyPrefix,
                newKeyHash: $issued->keyHash,
                previousKeyHash: null,
                previousKeyValidUntil: null,
            );
        }

        return new Rotation(
            newPlainText: $issued->plainText,
            newKeyPrefix: $issued->keyPrefix,
            newKeyHash: $issued->keyHash,
            previousKeyHash: $record->keyHash(),
            previousKeyValidUntil: $now->add(new \DateInterval('PT'.$graceHours.'H')),
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
