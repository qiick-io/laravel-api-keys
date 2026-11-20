<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\ScopeSet;

/**
 * @api Broader authorisation. Must evaluate *current* owner permissions/grants
 * on every call — never cache issuance-time ceilings.
 */
interface KeyAuthorizer
{
    public function authorizeActor(ApiKeyRecord $record, KeyContext $context): AuthorizationDecision;

    public function authorizeScopes(
        ApiKeyRecord $record,
        ScopeSet $granted,
        ?Scope $required,
        KeyContext $context,
    ): AuthorizationDecision;

    /**
     * Current ceiling the owner/creator may still grant.
     *
     * `$knownScopes` is the expanded offer from the key (stored atoms plus an
     * implied `:read` when `:write` is present). Implementations MUST return
     * every atom the principal may still hold — including implied reads when
     * the owner retains write (or only read). Omitting a read that the owner
     * still has prevents write→read demotion and can empty the granted set.
     *
     * @param  list<string>  $knownScopes
     * @return list<string>
     */
    public function scopesCreatorMayGrant(string|int $creatorId, array $knownScopes, KeyContext $context): array;

    /**
     * Optional per-key limit. When returned, bucketKey MUST be derived from
     * record id (and optionally IP) — never from request body / user input.
     */
    public function rateLimit(ApiKeyRecord $record, KeyContext $context): ?RateLimitDecision;
}
