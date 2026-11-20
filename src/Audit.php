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
    /**
     * @param  array<string, mixed>  $properties
     * @return array<string, mixed>
     */
    public static function withApiKeyId(array $properties, string $apiKeyPublicId): array
    {
        if (! Str::isUuid($apiKeyPublicId)) {
            throw new \InvalidArgumentException(
                'api_key_id must be the key public UUID; numeric and non-UUID ids are rejected.',
            );
        }

        $properties['api_key_id'] = $apiKeyPublicId;

        return $properties;
    }
}
