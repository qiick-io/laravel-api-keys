<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\KeyAuthorizer;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\ResourceRestrictions;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\ScopeSet;

/**
 * @api Configurable {@see KeyAuthorizer} for tests.
 *
 * Fail-closed for ownerless and creator-less keys unless the test sets an
 * explicit ceiling (C1: the product decides; the fake stays safe by default).
 */
final class FakeKeyAuthorizer implements KeyAuthorizer
{
    use EnsuresTestingEnvironmentTrait;

    /**
     * @param  list<string>  $creatorMayGrant
     * @param  array<string|int, list<string>>  $creatorMayGrantById
     * @param  list<RateLimitDecision>  $rateLimits
     */
    public function __construct(
        private AuthorizationDecision $actor = new AuthorizationDecision(true),
        private AuthorizationDecision $scopes = new AuthorizationDecision(true),
        private AuthorizationDecision $resources = new AuthorizationDecision(true),
        private array $rateLimits = [],
        private array $creatorMayGrant = [],
        private array $creatorMayGrantById = [],
        private bool $allowOwnerlessCeiling = false,
    ) {
        self::ensureTestingEnvironment();
    }

    public function authorizeActor(ApiKeyRecord $record, KeyContext $context): AuthorizationDecision
    {
        return $this->actor;
    }

    public function authorizeScopes(
        ApiKeyRecord $record,
        ScopeSet $granted,
        ?Scope $required,
        KeyContext $context,
    ): AuthorizationDecision {
        return $this->scopes;
    }

    public function scopesCreatorMayGrant(ApiKeyRecord $record, array $knownScopes, KeyContext $context): array
    {
        $ceilingId = $record->ownerIdentifier() ?? $record->createdByIdentifier();

        if ($this->creatorMayGrantById !== [] && $ceilingId !== null && array_key_exists($ceilingId, $this->creatorMayGrantById)) {
            return $this->creatorMayGrantById[$ceilingId];
        }

        if ($this->creatorMayGrant !== []) {
            return $this->creatorMayGrant;
        }

        if ($ceilingId === null && ! $this->allowOwnerlessCeiling) {
            return [];
        }

        return $knownScopes;
    }

    public function rateLimit(ApiKeyRecord $record, KeyContext $context): array
    {
        return $this->rateLimits;
    }

    public function authorizeResources(
        ApiKeyRecord $record,
        ResourceRestrictions $resources,
        KeyContext $context,
    ): AuthorizationDecision {
        return $this->resources;
    }

    public function denyActor(string $message = 'The API key owner is no longer active.'): self
    {
        $clone = clone $this;
        $clone->actor = AuthorizationDecision::deny($message);

        return $clone;
    }

    public function denyScopes(): self
    {
        $clone = clone $this;
        $clone->scopes = AuthorizationDecision::deny('ceiling');

        return $clone;
    }

    public function denyResources(): self
    {
        $clone = clone $this;
        $clone->resources = AuthorizationDecision::deny('resources');

        return $clone;
    }

    /**
     * @param  list<RateLimitDecision>  $rateLimits
     */
    public function withRateLimits(array $rateLimits): self
    {
        $clone = clone $this;
        $clone->rateLimits = $rateLimits;

        return $clone;
    }

    /**
     * @deprecated Use {@see withRateLimits()}; kept for short test rewrites.
     */
    public function withRateLimit(?RateLimitDecision $rateLimit): self
    {
        return $this->withRateLimits($rateLimit === null ? [] : [$rateLimit]);
    }

    /**
     * @param  list<string>  $creatorMayGrant
     */
    public function withCreatorMayGrant(array $creatorMayGrant): self
    {
        $clone = clone $this;
        $clone->creatorMayGrant = $creatorMayGrant;

        return $clone;
    }

    /**
     * @param  array<string|int, list<string>>  $creatorMayGrantById
     */
    public function withCreatorMayGrantById(array $creatorMayGrantById): self
    {
        $clone = clone $this;
        $clone->creatorMayGrantById = $creatorMayGrantById;

        return $clone;
    }

    public function allowingOwnerlessCeiling(bool $allow = true): self
    {
        $clone = clone $this;
        $clone->allowOwnerlessCeiling = $allow;

        return $clone;
    }
}
