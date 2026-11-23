<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Idempotency for the legacy-format T−90 warning (N2).
 *
 * Same protocol as the expiry notice on {@see ApiKeyRepository}: the command
 * resolves recipients, takes a lease with {@see claim()}, sends, then calls
 * {@see markSent()} on success or {@see release()} on failure. A worker that
 * dies between claim and send leaves a lease that expires after
 * `$leaseSeconds`, so the warning is never lost to a crash or a transient
 * transport error, and repeated daily runs never re-send a sent warning.
 */
interface LegacyFormatWarningGate
{
    /**
     * Atomically takes a lease of `$leaseSeconds` on the warning. Returns
     * false while another worker holds a live lease or once it was sent.
     */
    public function claim(string $idempotencyKey, int $leaseSeconds): bool;

    /**
     * Drops the lease after a failed send so the next run retries.
     */
    public function release(string $idempotencyKey): void;

    /**
     * Records the warning as sent, permanently: {@see claim()} never succeeds again.
     */
    public function markSent(string $idempotencyKey): void;
}
