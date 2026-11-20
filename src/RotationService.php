<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Issues a new secret for an existing key_prefix and optional grace window.
 *
 * Invalid or negative grace hours become 0 (no previous secret). A second
 * rotation replaces the previous grace secret — only the secret displaced by
 * the latest rotate stays valid until `previousKeyValidUntil`.
 */
final class RotationService
{
    /**
     * @param  int  $graceHours  Prefer values from {@see normalizeGraceHours}
     */
    public function rotate(
        string $keyPrefix,
        string $currentKeyHash,
        \DateTimeImmutable $now,
        int $graceHours,
        TokenCodec $codec,
    ): Rotation {
        $graceHours = self::normalizeGraceHours($graceHours);
        $issued = $codec->reissueForPrefix($keyPrefix);

        if ($graceHours <= 0) {
            return new Rotation(
                newPlainText: $issued->plainText,
                newKeyHash: $issued->keyHash,
                previousKeyHash: null,
                previousKeyValidUntil: null,
            );
        }

        return new Rotation(
            newPlainText: $issued->plainText,
            newKeyHash: $issued->keyHash,
            previousKeyHash: $currentKeyHash,
            previousKeyValidUntil: $now->add(new \DateInterval('PT'.$graceHours.'H')),
        );
    }

    /**
     * Config grace as a whole number of hours. Non-integers / negatives → 0
     * (fail closed: never extend the old secret on a misconfiguration).
     */
    public static function normalizeGraceHours(mixed $configValue): int
    {
        if (is_bool($configValue)) {
            return 0;
        }

        // min_range 0 is intentional: grace of exactly 0 must parse as int 0, not false.
        $parsed = filter_var(
            $configValue,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0]], // @pest-mutate-ignore: IncrementInteger
        );

        return is_int($parsed) ? $parsed : 0;
    }
}
