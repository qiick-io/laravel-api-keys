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

    /** @var array<string, string> owner token by idempotency key */
    public array $leaseOwnersByKey = [];

    /** @var array<string, true> */
    public array $sentKeys = [];

    private int $issuedTokens = 0;

    public function __construct()
    {
        self::ensureTestingEnvironment();
    }

    public function claim(string $idempotencyKey, int $leaseSeconds): ?string
    {
        if (isset($this->leaseOwnersByKey[$idempotencyKey]) || isset($this->sentKeys[$idempotencyKey])) {
            return null;
        }

        $this->issuedTokens++;

        return $this->leaseOwnersByKey[$idempotencyKey] = 'owner-'.$this->issuedTokens;
    }

    public function release(string $idempotencyKey, string $ownerToken): void
    {
        if (($this->leaseOwnersByKey[$idempotencyKey] ?? null) === $ownerToken) {
            unset($this->leaseOwnersByKey[$idempotencyKey]);
        }
    }

    public function markSent(string $idempotencyKey, string $ownerToken): void
    {
        $this->sentKeys[$idempotencyKey] = true;
        $this->release($idempotencyKey, $ownerToken);
    }
}
