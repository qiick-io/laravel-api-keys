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
     * The failed-attempt brake counts only failed guesses, after they fail, so
     * valid requests in flight never take a slot. Once a client's bucket is
     * full, every outcome that would tell a guess apart is answered
     * `rate_limited` instead: a guess over the limit, and a correct key (see
     * {@see verify()}). Racing guesses therefore reveal at most
     * `maxPerMinute` outcomes per window.
     *
     * @throws ApiKeyRejection
     */
    public function authenticate(
        #[\SensitiveParameter] string $presentedToken,
        KeyContext $context,
        ?Scope $requiredScope = null,
    ): AuthenticationResult {
        $clientIp = $context->ip;

        $brake = $this->failedAttemptLimiter;

        if ($brake !== null && $this->onAttemptStore(fn (): bool => $brake->isBlocked($clientIp))) {
            throw $this->failedAttemptsExceeded($brake, $clientIp);
        }

        try {
            return $this->verify($presentedToken, $context, $requiredScope);
        } catch (ApiKeyRejection $rejection) {
            $isFailedGuess = $rejection->errorCode() === KeyRejectionCode::InvalidToken->value;

            if ($isFailedGuess && $brake !== null && ! $this->onAttemptStore(fn (): bool => $brake->countFailure($clientIp))) {
                throw $this->failedAttemptsExceeded($brake, $clientIp);
            }

            throw $rejection;
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

        // Token versions this package can verify: 0 legacy, 1 canonical, 2 canonical with checksum.
        if (! in_array($matched->tokenVersion(), [0, 1, 2], true)) {
            throw ApiKeyRejection::invalidToken();
        }

        // Unknown hash_algorithm is refused inside TokenCodec::match (single place).

        $actor = $this->authorizer->authorizeActor($matched, $context);
        if (! $actor->allowed) {
            throw ApiKeyRejection::invalidToken(
                $actor->denialMessage ?? 'The API key is not valid.',
            );
        }

        // The credential is valid. If racing guesses filled the bucket meanwhile, do not reveal it.
        $brake = $this->failedAttemptLimiter;

        if ($brake !== null && $this->onAttemptStore(fn (): bool => $brake->isBlocked($clientIp))) {
            throw $this->failedAttemptsExceeded($brake, $clientIp);
        }

        $ipAllowlist = $this->decodedStoredJson($matched, 'ip_allowlist', $matched->rawIpAllowlist(), ApiKeyRejection::ipNotAllowed(...));

        if (! $this->ipAllowlist->allows($clientIp, $ipAllowlist)) {
            throw ApiKeyRejection::ipNotAllowed();
        }

        $restrictions = KeyRestrictions::parse(
            $this->decodedStoredJson($matched, 'restrictions', $matched->rawRestrictions(), ApiKeyRejection::requestNotAllowed(...)),
        );
        if ($restrictions->isDenied) {
            throw ApiKeyRejection::requestNotAllowed();
        }

        if (! (new RequestRestrictionsEvaluator)->allows($restrictions->request, $context)) {
            throw ApiKeyRejection::requestNotAllowed();
        }

        $expanded = ScopeSet::parseStoredExpanded(
            $this->decodedStoredJson($matched, 'scopes', $matched->rawScopes(), ApiKeyRejection::noUsableScopes(...)),
            $this->vocabulary,
        );
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
     * Runs a call on the attempt store (Redis, Memcached). A store that is down
     * fails closed as a typed 503, never a bare 500: the cause is reported, the
     * client gets a stable `service_unavailable` it can retry.
     *
     * @template TResult
     *
     * @param  callable(): TResult  $call
     * @return TResult
     *
     * @throws ApiKeyRejection
     */
    private function onAttemptStore(callable $call): mixed
    {
        try {
            return $call();
        } catch (\Throwable $exception) {
            $this->reportException($exception);

            throw ApiKeyRejection::serviceUnavailable();
        }
    }

    private function failedAttemptsExceeded(FailedAttemptLimiter $failedAttemptLimiter, ?string $clientIp): ApiKeyRejection
    {
        return ApiKeyRejection::rateLimited(
            $this->onAttemptStore(fn (): int => $failedAttemptLimiter->availableIn($clientIp)),
            $failedAttemptLimiter->maxPerMinute(),
            remaining: 0,
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

    /**
     * Products pass the JSON columns as stored ({@see ApiKeyRecord::rawIpAllowlist()}
     * and its siblings). Laravel's `array` cast would read JSON that does not
     * decode as null, which means "no restriction" for the allowlist and the
     * restrictions. A string is decoded here instead; one that does not decode
     * (an empty string included) denies the key and is reported, so a corrupted
     * row never authenticates without its limits.
     *
     * @param  callable(): ApiKeyRejection  $denial
     *
     * @throws ApiKeyRejection when the stored string is not valid JSON
     */
    private function decodedStoredJson(ApiKeyRecord $record, string $column, mixed $stored, callable $denial): mixed
    {
        if (! is_string($stored)) {
            return $stored;
        }

        try {
            return json_decode($stored, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            $this->reportException(new \UnexpectedValueException(
                "The stored {$column} of API key {$record->publicId()} is not valid JSON: the key is denied.",
                previous: $exception,
            ));

            throw $denial();
        }
    }

    private function reportException(\Throwable $exception): void
    {
        if (is_callable($this->exceptionReporter)) {
            ($this->exceptionReporter)($exception);

            return;
        }

        // Laravel helper when present; host apps without it still authenticate.
        if (\function_exists('report')) {
            report($exception);
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

        $countedBucketKeys = [];

        foreach ($decisions as $decision) {
            if ($decision->maxAttempts <= 0) {
                continue;
            }

            // Count first, then compare: one atomic step, so concurrent requests cannot all see room.
            $hits = $this->onAttemptStore(fn (): int => $this->attemptLimiter->hit($decision->bucketKey, $decision->decaySeconds));
            $countedBucketKeys[] = $decision->bucketKey;

            if ($hits > $decision->maxAttempts) {
                // A refused request counts against no window, the earlier ones included.
                foreach ($countedBucketKeys as $countedBucketKey) {
                    $this->onAttemptStore(fn () => $this->attemptLimiter->decrement($countedBucketKey));
                }

                $retryAfter = $this->onAttemptStore(fn (): int => $this->attemptLimiter->availableIn($decision->bucketKey));

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
     * The row's windows; a limit of 0 or below is skipped by {@see enforceRateLimits()}.
     *
     * @return list<RateLimitDecision>
     */
    private function defaultRateLimits(ApiKeyRecord $record): array
    {
        $decisions = [new RateLimitDecision(
            bucketKey: 'api-key:'.$record->id(),
            maxAttempts: $record->rateLimitPerMinute() ?? $this->defaultRateLimitPerMinute,
            decaySeconds: 60,
        )];

        $day = $record->rateLimitPerDay();
        if ($day !== null) {
            $decisions[] = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id().':day',
                maxAttempts: $day,
                decaySeconds: 86_400,
            );
        }

        $month = $record->rateLimitPerMonth();
        if ($month !== null) {
            $decisions[] = new RateLimitDecision(
                bucketKey: 'api-key:'.$record->id().':month',
                maxAttempts: $month,
                decaySeconds: 2_592_000,
            );
        }

        return $decisions;
    }
}
