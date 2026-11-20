<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\KeyAuthorizer;
use Qiick\ApiKeys\Contracts\ScopeVocabulary;
use Qiick\ApiKeys\Contracts\UsageSideEffect;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;

/**
 * @api Verifies a presented API key in the fixed evaluation order.
 *
 * No HTTP middleware ships with this package — products call this from their own.
 *
 * Order: format → lookup + hash_equals (dummy on miss) → revoked/expired →
 * actor → IP → scopes + authorizer ceiling → rate limit → usage.
 *
 * Never puts `$presentedToken` in exception messages.
 */
final class ApiKeyAuthenticator
{
    public function __construct(
        private TokenCodec $codec,
        private ApiKeyRepository $repository,
        private KeyAuthorizer $authorizer,
        private ScopeVocabulary $vocabulary,
        private IpAllowlist $ipAllowlist,
        private UsageRecorder $usageRecorder,
        private Clock $clock,
        private AttemptLimiter $attemptLimiter,
        private ?UsageSideEffect $usageSideEffect = null,
        private int $usageThrottleSeconds = 60, // @pest-mutate-ignore
        private bool $bypassThrottleOnIpChange = true, // @pest-mutate-ignore
        private int $defaultRateLimitPerMinute = 60, // @pest-mutate-ignore
    ) {}

    /**
     * @throws ApiKeyRejection
     */
    public function authenticate(
        string $presentedToken,
        KeyContext $context,
        ?Scope $requiredScope = null,
    ): AuthenticationResult {
        $keyPrefix = $this->codec->prefixOf($presentedToken);
        if ($keyPrefix === null) {
            throw ApiKeyRejection::invalidToken();
        }

        $candidates = [];
        foreach ($this->repository->findCandidatesByPrefix($keyPrefix) as $candidate) {
            $candidates[] = $candidate;
        }

        if ($candidates === []) {
            // Timing equalisation; observable behaviour is the shared invalid_token body (A2b).
            $this->codec->performDummyMatch($presentedToken); // @pest-mutate-ignore RemoveMethodCall

            throw ApiKeyRejection::invalidToken();
        }

        $now = $this->clock->now();
        $matched = null;
        $matchKind = TokenMatch::None;

        foreach ($candidates as $candidate) {
            $kind = $this->codec->match(
                $presentedToken,
                $candidate->keyHash(),
                $candidate->previousKeyHash(),
                $candidate->previousKeyValidUntil(),
                $now,
            );

            if ($kind !== TokenMatch::None) {
                $matched = $candidate;
                $matchKind = $kind;
                break;
            }
        }

        if ($matched === null) {
            throw ApiKeyRejection::invalidToken();
        }

        if ($matched->revokedAt() !== null) {
            throw ApiKeyRejection::invalidToken('The API key has been revoked.');
        }

        if ($matched->expiresAt() !== null && $now >= $matched->expiresAt()) {
            throw ApiKeyRejection::invalidToken('The API key has expired.');
        }

        $actor = $this->authorizer->authorizeActor($matched, $context);
        if (! $actor->allowed) {
            throw ApiKeyRejection::invalidToken(
                $actor->denialMessage ?? 'The API key is not valid.',
            );
        }

        $clientIp = $context->ip ?? ''; // @pest-mutate-ignore EmptyStringToNotEmpty

        if (! $this->ipAllowlist->allows($clientIp, $matched->rawIpAllowlist())) {
            throw ApiKeyRejection::ipNotAllowed();
        }

        $granted = ScopeSet::parseStored($matched->rawScopes(), $this->vocabulary);
        if ($granted->isEmpty()) {
            throw ApiKeyRejection::noUsableScopes();
        }

        if ($requiredScope !== null && ! $granted->allows($requiredScope)) {
            throw ApiKeyRejection::insufficientScope($requiredScope->value());
        }

        $scopeDecision = $this->authorizer->authorizeScopes(
            $matched,
            $granted,
            $requiredScope,
            $context,
        );
        if (! $scopeDecision->allowed) {
            if ($requiredScope !== null) {
                throw ApiKeyRejection::insufficientScope($requiredScope->value());
            }

            throw ApiKeyRejection::noUsableScopes();
        }

        $this->enforceRateLimit($matched, $context);

        $wasFirstUse = $matched->lastUsedAt() === null;
        if ($this->usageRecorder->shouldRecord(
            $now,
            $matched->lastUsedAt(),
            $matched->lastUsedIp(),
            $context->ip,
            $this->usageThrottleSeconds,
            $this->bypassThrottleOnIpChange,
        )) {
            $this->repository->recordUsage($matched, $context->ip, $now);
            $this->usageSideEffect?->afterRecorded($matched, $context->ip, $wasFirstUse);
        }

        return new AuthenticationResult(
            $matched,
            $granted,
            $matchKind === TokenMatch::Previous,
        );
    }

    /**
     * @throws ApiKeyRejection
     */
    private function enforceRateLimit(ApiKeyRecord $record, KeyContext $context): void
    {
        $decision = $this->authorizer->rateLimit($record, $context);

        if ($decision === null) {
            $limit = $record->rateLimitPerMinute() ?? $this->defaultRateLimitPerMinute;
            if ($limit <= 0) {
                return;
            }

            $decision = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id(),
                maxAttempts: $limit,
                decaySeconds: 60, // @pest-mutate-ignore
            );
        }

        if ($this->attemptLimiter->tooManyAttempts($decision->bucketKey, $decision->maxAttempts)) {
            throw ApiKeyRejection::rateLimited(
                $this->attemptLimiter->availableIn($decision->bucketKey),
                $decision->maxAttempts,
                remaining: 0, // @pest-mutate-ignore
            );
        }

        $this->attemptLimiter->hit($decision->bucketKey, $decision->decaySeconds);
    }
}
