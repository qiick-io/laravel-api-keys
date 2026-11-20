<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\KeyAuthorizer;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\ScopeSet;

/**
 * @api Configurable {@see KeyAuthorizer} for tests.
 */
final class FakeKeyAuthorizer implements KeyAuthorizer
{
    public function __construct(
        private AuthorizationDecision $actor = new AuthorizationDecision(true),
        private AuthorizationDecision $scopes = new AuthorizationDecision(true),
        private ?RateLimitDecision $rateLimit = null,
        /** @var list<string> */
        private array $creatorMayGrant = [],
    ) {}

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

    public function scopesCreatorMayGrant(string|int $creatorId, array $knownScopes, KeyContext $context): array
    {
        return $this->creatorMayGrant !== [] ? $this->creatorMayGrant : $knownScopes;
    }

    public function rateLimit(ApiKeyRecord $record, KeyContext $context): ?RateLimitDecision
    {
        return $this->rateLimit;
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

    public function withRateLimit(?RateLimitDecision $rateLimit): self
    {
        $clone = clone $this;
        $clone->rateLimit = $rateLimit;

        return $clone;
    }
}
