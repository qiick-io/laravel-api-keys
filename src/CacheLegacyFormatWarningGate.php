<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Support\Facades\Cache;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;

/**
 * @api Durable claim store via Laravel's cache (N2 idempotency).
 *
 * One cache entry per warning: a lease value with a TTL while a worker sends,
 * replaced by a permanent "sent" marker. `Cache::add` is atomic on every
 * shared store, so two workers never hold the same lease. The cache must be
 * shared by all workers and must not be flushed or evicted (a lost "sent"
 * marker means one repeat warning, never a lost one).
 */
final class CacheLegacyFormatWarningGate implements LegacyFormatWarningGate
{
    private const string LEASED = 'leased';

    private const string SENT = 'sent';

    public function claim(string $idempotencyKey, int $leaseSeconds): bool
    {
        return Cache::add($idempotencyKey, self::LEASED, $leaseSeconds);
    }

    public function release(string $idempotencyKey): void
    {
        Cache::forget($idempotencyKey);
    }

    public function markSent(string $idempotencyKey): void
    {
        Cache::forever($idempotencyKey, self::SENT);
    }
}
