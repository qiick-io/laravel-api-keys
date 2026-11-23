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
 * refuse oauth_grant → revoked/expired → unknown version/algorithm → actor → IP →
 * request restrictions → scopes + authorizer ceiling → resource restrictions →
 * rate limits (minute/day/month) → usage.
 *
 * Never puts `$presentedToken` in exception messages.
 */
final class ApiKeyAuthenticator
{
    private const array KNOWN_TOKEN_VERSIONS = [0, 1, 2]; // @pest-mutate-ignore: IncrementInteger,DecrementInteger,RemoveArrayItem

    private RequestRestrictionsEvaluator $requestRestrictionsEvaluator;

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
        ?RequestRestrictionsEvaluator $requestRestrictionsEvaluator = null,
    ) {
        $this->requestRestrictionsEvaluator = $requestRestrictionsEvaluator ?? new RequestRestrictionsEvaluator; // @pest-mutate-ignore: CoalesceRemoveLeft
    }

    /**
     * The failed-attempt brake takes its slot before the token is evaluated
     * (see {@see FailedAttemptLimiter::reserve()}). Only an `invalid_token`
     * refusal is a failed guess and keeps the slot; every other outcome,
     * success included, hands it back.
     *
     * @throws ApiKeyRejection
     */
    public function authenticate(
        #[\SensitiveParameter] string $presentedToken,
        KeyContext $context,
        ?Scope $requiredScope = null,
    ): AuthenticationResult {
        $clientIp = $context->ip;

        if ($this->failedAttemptLimiter !== null && ! $this->failedAttemptLimiter->reserve($clientIp)) {
            throw ApiKeyRejection::rateLimited(
                $this->failedAttemptLimiter->availableIn($clientIp),
                $this->failedAttemptLimiter->maxPerMinute(),
                remaining: 0,
            );
        }

        $isFailedGuess = false;

        try {
            return $this->verify($presentedToken, $context, $requiredScope);
        } catch (ApiKeyRejection $rejection) {
            $isFailedGuess = $rejection->errorCode() === KeyRejectionCode::InvalidToken->value;

            throw $rejection;
        } finally {
            if (! $isFailedGuess) {
                $this->failedAttemptLimiter?->release($clientIp);
            }
        }
    }

    /**
     * The evaluation order itself. Every credential failure is the same
     * `invalid_token` refusal (A2b), which is what the brake counts.
     *
     * @throws ApiKeyRejection
     */
    private function verify(
        #[\SensitiveParameter] string $presentedToken,
        KeyContext $context,
        ?Scope $requiredScope,
    ): AuthenticationResult {
        $clientIp = $context->ip;

        $now = $this->clock->now();
        // Pass $now so legacy matchers respect accept_until (A13).
        $keyPrefix = $this->codec->prefixOf($presentedToken, $now);
        if ($keyPrefix === null) {
            throw ApiKeyRejection::invalidToken();
        }

        // Repository failures are infrastructure errors, not failed guesses: authenticate() releases the brake slot.
        $candidates = [];
        foreach ($this->repository->findCandidatesByPrefix($keyPrefix) as $candidate) {
            $candidates[] = $candidate;
        }

        if ($candidates === []) {
            $this->codec->performDummyMatch($presentedToken);
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
                $candidate->hashAlgorithm(),
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

        // O2: oauth_grant rows have no usable bearer secret.
        if ($matched->credentialKind() === CredentialKind::OauthGrant) {
            throw ApiKeyRejection::invalidToken();
        }

        if ($matched->revokedAt() !== null) {
            throw ApiKeyRejection::invalidToken('The API key has been revoked.');
        }

        if ($matched->expiresAt() !== null && $now >= $matched->expiresAt()) {
            throw ApiKeyRejection::invalidToken('The API key has expired.');
        }

        if (! in_array($matched->tokenVersion(), self::KNOWN_TOKEN_VERSIONS, true)) {
            throw ApiKeyRejection::invalidToken();
        }

        // Unknown hash_algorithm is refused inside TokenCodec::match (single place).

        $actor = $this->authorizer->authorizeActor($matched, $context);
        if (! $actor->allowed) {
            throw ApiKeyRejection::invalidToken(
                $actor->denialMessage ?? 'The API key is not valid.',
            );
        }

        // Cast keeps a strict string for IpAllowlist; empty fallback is for null IP only.
        if (! $this->ipAllowlist->allows((string) ($clientIp ?? ''), $matched->rawIpAllowlist())) { // @pest-mutate-ignore: RemoveStringCast,EmptyStringToNotEmpty
            throw ApiKeyRejection::ipNotAllowed();
        }

        $restrictions = KeyRestrictions::parse($matched->rawRestrictions());
        if ($restrictions->isDenied) {
            throw ApiKeyRejection::requestNotAllowed();
        }

        if (! $this->requestRestrictionsEvaluator->allows($restrictions->request, $context)) {
            throw ApiKeyRejection::requestNotAllowed();
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

        if (! $restrictions->resources->isEmpty()) {
            $resourceDecision = $this->authorizer->authorizeResources(
                $matched,
                $restrictions->resources,
                $context,
            );
            if (! $resourceDecision->allowed) {
                throw ApiKeyRejection::requestNotAllowed();
            }
        }

        $this->enforceRateLimits($matched, $context);

        $wasFirstUse = $matched->lastUsedAt() === null;
        if ($this->usageRecorder->shouldRecord(
            $now,
            $matched->lastUsedAt(),
            $matched->lastUsedIp(),
            $context->ip,
            $this->usageThrottleSeconds,
            $this->bypassThrottleOnIpChange,
        )) {
            $this->recordUsageQuietly($matched, $context->ip, $context->userAgent, $now, $wasFirstUse);
        }

        $legacyMatcher = $this->codec->legacyMatcherFor($presentedToken, $now);

        return new AuthenticationResult(
            $matched,
            $granted,
            $matchKind === TokenMatch::Previous,
            $legacyMatcher === null ? null : $legacyMatcher::class,
        );
    }

    /**
     * C1: the product decides the ceiling for ownerless / creator-less keys.
     * Narrow against the expanded offer (writes imply reads) before collapsing.
     */
    private function narrowToOwnerCeiling(
        ApiKeyRecord $record,
        ScopeSet $expanded,
        KeyContext $context,
    ): ScopeSet {
        $allowedValues = $this->authorizer->scopesCreatorMayGrant(
            $record,
            $expanded->valuesOfferedToAuthorizer(),
            $context,
        );

        return $expanded->narrowedTo($allowedValues)->collapsed();
    }

    private function recordUsageQuietly(
        ApiKeyRecord $record,
        ?string $ip,
        ?string $userAgent,
        \DateTimeImmutable $usedAt,
        bool $wasFirstUse,
    ): void {
        try {
            $this->repository->recordUsage($record, $ip, $userAgent, $usedAt);
            $this->usageSideEffect?->afterRecorded($record, $ip, $userAgent, $wasFirstUse);
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
    private function enforceRateLimits(ApiKeyRecord $record, KeyContext $context): void
    {
        $decisions = $this->authorizer->rateLimit($record, $context);

        if ($decisions === []) {
            $decisions = $this->defaultRateLimits($record);
        }

        foreach ($decisions as $decision) {
            if ($decision->maxAttempts <= 0) { // @pest-mutate-ignore: SmallerOrEqualToSmaller,DecrementInteger
                continue;
            }

            // Count first, then compare: one atomic step, so concurrent requests cannot all see room.
            $hits = $this->attemptLimiter->hit($decision->bucketKey, $decision->decaySeconds);

            if ($hits > $decision->maxAttempts) {
                // A refused request does not count against the limit.
                $this->attemptLimiter->decrement($decision->bucketKey, $decision->decaySeconds);
                $retryAfter = $this->attemptLimiter->availableIn($decision->bucketKey);

                throw ApiKeyRejection::rateLimited(
                    $retryAfter,
                    $decision->maxAttempts,
                    remaining: 0,
                    resetAfterSeconds: $retryAfter,
                );
            }
        }
    }

    /**
     * @return list<RateLimitDecision>
     */
    private function defaultRateLimits(ApiKeyRecord $record): array
    {
        $decisions = [];
        $minute = $record->rateLimitPerMinute() ?? $this->defaultRateLimitPerMinute;

        // Decrement of the 0 literal is equivalent: maxAttempts<=0 still skips the bucket.
        if ($minute > 0) { // @pest-mutate-ignore: GreaterToGreaterOrEqual,DecrementInteger
            $decisions[] = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id(),
                maxAttempts: $minute,
                decaySeconds: 60, // @pest-mutate-ignore: IncrementInteger,DecrementInteger
            );
        }

        $day = $record->rateLimitPerDay();
        if ($day !== null && $day > 0) { // @pest-mutate-ignore: GreaterToGreaterOrEqual,DecrementInteger,BooleanAndToBooleanOr
            $decisions[] = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id().':day',
                maxAttempts: $day,
                decaySeconds: 86_400, // @pest-mutate-ignore: IncrementInteger,DecrementInteger
            );
        }

        $month = $record->rateLimitPerMonth();
        if ($month !== null && $month > 0) { // @pest-mutate-ignore: GreaterToGreaterOrEqual,DecrementInteger,BooleanAndToBooleanOr
            $decisions[] = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id().':month',
                maxAttempts: $month,
                decaySeconds: 2_592_000, // @pest-mutate-ignore: IncrementInteger,DecrementInteger
            );
        }

        return $decisions;
    }
}
