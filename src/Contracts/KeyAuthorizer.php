<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\ResourceRestrictions;
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
     * Receives the full record so the product decides ownerless / creator-less
     * keys (the package no longer empties the set itself). `$knownScopes` is the
     * expanded offer from the key (stored atoms plus an implied `:read` when
     * `:write` is present). Implementations MUST return every atom the principal
     * may still hold — including implied reads when the owner retains write.
     *
     * @param  list<string>  $knownScopes
     * @return list<string>
     */
    public function scopesCreatorMayGrant(ApiKeyRecord $record, array $knownScopes, KeyContext $context): array;

    /**
     * Optional per-key limits (minute, day, month). Empty list → package builds
     * defaults from the record's rate_limit_per_* columns.
     *
     * Each `bucketKey` MUST be derived from record id (and optionally IP) —
     * never from request body / user input.
     *
     * @return list<RateLimitDecision>
     */
    public function rateLimit(ApiKeyRecord $record, KeyContext $context): array;

    /**
     * Product resource checks from {@see ResourceRestrictions} (BOLA).
     * The package never evaluates `restrictions.resources` itself.
     */
    public function authorizeResources(
        ApiKeyRecord $record,
        ResourceRestrictions $resources,
        KeyContext $context,
    ): AuthorizationDecision;
}
