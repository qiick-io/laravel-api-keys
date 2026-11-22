<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\LifetimePolicy;

/**
 * @api Max-lifetime check from `api-keys.max_lifetime_days`.
 *
 * Null config disables the policy (always allows). A null expiry is allowed
 * only when the policy is disabled; when configured, keys must expire within
 * the window.
 */
final class ConfigLifetimePolicy implements LifetimePolicy
{
    public function __construct(
        private ?int $maxLifetimeDays,
    ) {}

    public function allowsExpiry(?\DateTimeImmutable $expiresAt, \DateTimeImmutable $now): bool
    {
        if ($this->maxLifetimeDays === null || $this->maxLifetimeDays <= 0) {
            return true;
        }

        if ($expiresAt === null) {
            return false;
        }

        $latest = $now->add(new \DateInterval('P'.$this->maxLifetimeDays.'D'));

        return $expiresAt <= $latest;
    }
}
