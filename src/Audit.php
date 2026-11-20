<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Support\Str;

/**
 * @api Merge the fleet audit property for activity written under an API key.
 *
 * The property name is exactly `api_key_id` and the value is the key's **public
 * UUID** (never the internal bigint). See knowledge decision 2026-11-20
 * core hardening.
 */
final class Audit
{
    private const string NIL_UUID = '00000000-0000-0000-0000-000000000000';

    /**
     * @param  array<string, mixed>  $properties
     * @return array<string, mixed>
     */
    public static function withApiKeyId(array $properties, string $apiKeyPublicId): array
    {
        $normalized = strtolower($apiKeyPublicId);

        if ($normalized === self::NIL_UUID) {
            throw new \InvalidArgumentException(
                'api_key_id must not be the nil UUID.',
            );
        }

        if (! Str::isUuid($normalized)) {
            throw new \InvalidArgumentException(
                'api_key_id must be the key public UUID; numeric and non-UUID ids are rejected.',
            );
        }

        if (array_key_exists('api_key_id', $properties)) {
            $existing = $properties['api_key_id'];
            if (! is_string($existing) || strtolower($existing) !== $normalized) {
                throw new \InvalidArgumentException(
                    'properties already contain a different api_key_id.',
                );
            }
        }

        $properties['api_key_id'] = $normalized;

        return $properties;
    }
}
