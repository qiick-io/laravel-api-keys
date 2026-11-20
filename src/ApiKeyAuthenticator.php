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
 * Order: failed-attempt guard → format → lookup + hash_equals (dummy on miss) →
 * revoked/expired → actor → IP → scopes + authorizer ceiling → rate limit → usage.
 *
 * Never puts `$presentedToken` in exception messages.
 */
final class ApiKeyAuthenticator
{
    /**
     * @param  (callable(\Throwable): void)|null  $exceptionReporter
     */
    public function __construct(
        private TokenCodec $codec,
        private ApiKeyRepository $repository,
        private KeyAuthorizer $authorizer,
        private ScopeVocabulary $vocabulary,
        private IpAllowlist $ipAllowlist,
        private UsageRecorder $usageRecorder,
        private Clock $clock,
        private AttemptLimiter $attemptLimiter,
        private ?FailedAttemptLimiter $failedAttemptLimiter = null,
        private ?UsageSideEffect $usageSideEffect = null,
        private int $usageThrottleSeconds = 60,
        private bool $bypassThrottleOnIpChange = true,
        private int $defaultRateLimitPerMinute = 60,
        private mixed $exceptionReporter = null,
    ) {}

    /**
     * @throws ApiKeyRejection
     */
    public function authenticate(
        #[\SensitiveParameter] string $presentedToken,
        KeyContext $context,
        ?Scope $requiredScope = null,
    ): AuthenticationResult {
        $clientIp = $context->ip;

        if (
            $this->failedAttemptLimiter !== null
            && $this->failedAttemptLimiter->tooManyAttempts($clientIp)
        ) {
            throw ApiKeyRejection::rateLimited(
                $this->failedAttemptLimiter->availableIn($clientIp),
                $this->failedAttemptLimiter->maxPerMinute(),
                remaining: 0,
            );
        }

        $now = $this->clock->now();
        // Pass $now so legacy matchers respect accept_until (A13).
        $keyPrefix = $this->codec->prefixOf($presentedToken, $now);
        if ($keyPrefix === null) {
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken();
        }

        // Repository failures are infrastructure errors, not auth attempts — do not hit the brake.
        $candidates = [];
        foreach ($this->repository->findCandidatesByPrefix($keyPrefix) as $candidate) {
            $candidates[] = $candidate;
        }

        if ($candidates === []) {
            $this->codec->performDummyMatch($presentedToken);
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken();
        }

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
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken();
        }

        if ($matched->revokedAt() !== null) {
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken('The API key has been revoked.');
        }

        if ($matched->expiresAt() !== null && $now >= $matched->expiresAt()) {
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken('The API key has expired.');
        }

        $actor = $this->authorizer->authorizeActor($matched, $context);
        if (! $actor->allowed) {
            $this->hitFailedAttempt($clientIp);

            throw ApiKeyRejection::invalidToken(
                $actor->denialMessage ?? 'The API key is not valid.',
            );
        }

        // Cast keeps a strict string for IpAllowlist; empty fallback is for null IP only.
        if (! $this->ipAllowlist->allows((string) ($clientIp ?? ''), $matched->rawIpAllowlist())) { // @pest-mutate-ignore: RemoveStringCast,EmptyStringToNotEmpty
            throw ApiKeyRejection::ipNotAllowed();
        }

        $expanded = ScopeSet::parseStoredExpanded($matched->rawScopes(), $this->vocabulary);
        if ($expanded->isEmpty()) {
            throw ApiKeyRejection::noUsableScopes();
        }

        $granted = $this->narrowToOwnerCeiling($matched, $expanded, $context);
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
            $this->recordUsageQuietly($matched, $context->ip, $now, $wasFirstUse);
        }

        return new AuthenticationResult(
            $matched,
            $granted,
            $matchKind === TokenMatch::Previous,
        );
    }

    private function hitFailedAttempt(?string $clientIp): void
    {
        $this->failedAttemptLimiter?->hit($clientIp);
    }

    /**
     * Fail closed with no owner/creator. Narrow against the expanded offer
     * (writes imply reads) before collapsing highest-per-resource.
     */
    private function narrowToOwnerCeiling(
        ApiKeyRecord $record,
        ScopeSet $expanded,
        KeyContext $context,
    ): ScopeSet {
        $ceilingId = $record->ownerIdentifier() ?? $record->createdByIdentifier();
        if ($ceilingId === null) {
            return new ScopeSet([]);
        }

        $allowedValues = $this->authorizer->scopesCreatorMayGrant(
            $ceilingId,
            $expanded->valuesOfferedToAuthorizer(),
            $context,
        );

        return $expanded->narrowedTo($allowedValues)->collapsed();
    }

    private function recordUsageQuietly(
        ApiKeyRecord $record,
        ?string $ip,
        \DateTimeImmutable $usedAt,
        bool $wasFirstUse,
    ): void {
        try {
            $this->repository->recordUsage($record, $ip, $usedAt);
            $this->usageSideEffect?->afterRecorded($record, $ip, $wasFirstUse);
        } catch (\Throwable $exception) {
            $this->reportException($exception);
        }
    }

    private function reportException(\Throwable $exception): void
    {
        if (is_callable($this->exceptionReporter)) {
            ($this->exceptionReporter)($exception);

            return;
        }

        // Laravel helper when present; host apps without it still authenticate.
        if (\function_exists('report')) { // @pest-mutate-ignore: IfNegated
            report($exception); // @pest-mutate-ignore: RemoveFunctionCall
        }
    }

    /**
     * @throws ApiKeyRejection
     */
    private function enforceRateLimit(ApiKeyRecord $record, KeyContext $context): void
    {
        $decision = $this->authorizer->rateLimit($record, $context);

        if ($decision === null) {
            $limit = $record->rateLimitPerMinute() ?? $this->defaultRateLimitPerMinute;
            // Design: 0 disables the per-key brake (config default_rate_limit_per_minute).
            if ($limit <= 0) {
                return;
            }

            $decision = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id(),
                maxAttempts: $limit,
                decaySeconds: 60,
            );
        }

        if ($this->attemptLimiter->tooManyAttempts($decision->bucketKey, $decision->maxAttempts)) {
            throw ApiKeyRejection::rateLimited(
                $this->attemptLimiter->availableIn($decision->bucketKey),
                $decision->maxAttempts,
                remaining: 0,
            );
        }

        $this->attemptLimiter->hit($decision->bucketKey, $decision->decaySeconds);
    }
}
