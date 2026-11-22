<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Support\Facades\Cache;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;

/**
 * @api Durable claim store via Laravel's cache (N2 idempotency).
 */
final class CacheLegacyFormatWarningGate implements LegacyFormatWarningGate
{
    public function claim(string $idempotencyKey): bool
    {
        return Cache::add($idempotencyKey, true);
    }
}
