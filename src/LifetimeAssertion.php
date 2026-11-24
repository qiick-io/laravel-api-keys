<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\LifetimePolicy;

/**
 * @api Enforces a {@see LifetimePolicy} where the package does not write the row.
 *
 * Issuance is product-owned ({@see TokenCodec::issue()} persists nothing), so the
 * product calls this before inserting a new key; {@see RotationService} calls it
 * on rotate. One message for both paths keeps the refusal uniform.
 */
final class LifetimeAssertion
{
    /**
     * @throws \InvalidArgumentException when the policy refuses `$expiresAt`
     *                                   (including a missing expiry under a policy)
     */
    public static function assertAllows(LifetimePolicy $policy, ?\DateTimeImmutable $expiresAt, \DateTimeImmutable $now): void
    {
        if (! $policy->allowsExpiry($expiresAt, $now)) {
            throw new \InvalidArgumentException('The API key expiry exceeds the lifetime policy.');
        }
    }
}
