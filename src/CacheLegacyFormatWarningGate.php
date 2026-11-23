<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Illuminate\Support\Facades\Cache;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;

/**
 * @api Durable claim store via Laravel's cache (N2 idempotency).
 *
 * The lease is a cache lock: `Cache::lock()` acquires atomically on every
 * lock-capable store and releases only for its owner token, so a late worker
 * cannot free a lease another worker took over. A permanent "sent" marker
 * sits next to it. The cache must be shared by all workers and must not be
 * flushed or evicted (a lost marker means one repeat warning, never a lost one).
 */
final class CacheLegacyFormatWarningGate implements LegacyFormatWarningGate
{
    public function claim(string $idempotencyKey, int $leaseSeconds): ?string
    {
        $lease = Cache::lock($this->leaseKey($idempotencyKey), $leaseSeconds);

        if (! $lease->get()) {
            return null;
        }

        // Checked under the lease: a worker that just marked it sent has released by now.
        if (Cache::has($idempotencyKey)) {
            $lease->release();

            return null;
        }

        return $lease->owner();
    }

    public function release(string $idempotencyKey, string $ownerToken): void
    {
        Cache::restoreLock($this->leaseKey($idempotencyKey), $ownerToken)->release();
    }

    public function markSent(string $idempotencyKey, string $ownerToken): void
    {
        Cache::forever($idempotencyKey, 'sent');
        $this->release($idempotencyKey, $ownerToken);
    }

    private function leaseKey(string $idempotencyKey): string
    {
        return $idempotencyKey.':lease';
    }
}
