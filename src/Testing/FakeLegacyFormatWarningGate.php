<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;

/**
 * @api In-memory {@see LegacyFormatWarningGate} for tests.
 *
 * Leases never expire on their own here; a test that needs a dead worker's
 * lease to lapse uses the cache-backed gate with time travel instead.
 */
final class FakeLegacyFormatWarningGate implements LegacyFormatWarningGate
{
    use EnsuresTestingEnvironmentTrait;

    /** @var array<string, true> */
    public array $leasedKeys = [];

    /** @var array<string, true> */
    public array $sentKeys = [];

    public function __construct()
    {
        self::ensureTestingEnvironment();
    }

    public function claim(string $idempotencyKey, int $leaseSeconds): bool
    {
        if (isset($this->leasedKeys[$idempotencyKey]) || isset($this->sentKeys[$idempotencyKey])) {
            return false;
        }

        $this->leasedKeys[$idempotencyKey] = true;

        return true;
    }

    public function release(string $idempotencyKey): void
    {
        unset($this->leasedKeys[$idempotencyKey]);
    }

    public function markSent(string $idempotencyKey): void
    {
        unset($this->leasedKeys[$idempotencyKey]);
        $this->sentKeys[$idempotencyKey] = true;
    }
}
