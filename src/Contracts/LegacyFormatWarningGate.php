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
 *
 * Every lease carries an owner token: a worker whose lease already expired and
 * was taken over must not be able to release the new owner's lease.
 */
interface LegacyFormatWarningGate
{
    /**
     * Atomically takes a lease of `$leaseSeconds` on the warning and returns
     * its owner token, or null while another worker holds a live lease or
     * once the warning was sent.
     */
    public function claim(string $idempotencyKey, int $leaseSeconds): ?string;

    /**
     * Drops the lease after a failed send so the next run retries; a no-op
     * unless `$ownerToken` still owns it.
     */
    public function release(string $idempotencyKey, string $ownerToken): void;

    /**
     * Records the warning as sent, permanently: {@see claim()} never succeeds
     * again. Then drops the owner's lease.
     */
    public function markSent(string $idempotencyKey, string $ownerToken): void;
}
