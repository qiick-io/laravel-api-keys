<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Optional organisation max-lifetime check on issue and rotate.
 *
 * No snapshot column: `expires_at` already holds the enforced value. Return
 * false to refuse issuance/rotation that would exceed the policy.
 */
interface LifetimePolicy
{
    public function allowsExpiry(?\DateTimeImmutable $expiresAt, \DateTimeImmutable $now): bool;
}
