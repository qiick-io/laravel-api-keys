<?php

declare(strict_types=1);

use Qiick\ApiKeys\ApiKeyAuthenticator;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\IpAllowlist;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\Testing\ArrayScopeVocabulary;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeKeyAuthorizer;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\InterleavingAttemptLimiter;
use Qiick\ApiKeys\Tests\Support\ReentrantApiKeyRepository;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;
use Qiick\ApiKeys\UsageRecorder;

mutates(ApiKeyAuthenticator::class);
mutates(FailedAttemptLimiter::class);

/**
 * Runs `$authenticate` and reports its outcome as a short label, so two
 * interleaved requests can be compared without nested try/catch blocks.
 */
function concurrentOutcome(Closure $authenticate): string
{
    try {
        $authenticate();

        return 'authenticated';
    } catch (ApiKeyRejection $rejection) {
        return $rejection->errorCode();
    }
}

function concurrentCodec(): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('concurrency-seed-for-deterministic-tests!'),
    );
}

it('admits only maxAttempts requests when two requests race on one key bucket', function (): void {
    $codec = concurrentCodec();
    $issued = $codec->issue();
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
        rateLimitPerMinute: 1,
    );
    $limiter = new InterleavingAttemptLimiter;
    $authenticator = new ApiKeyAuthenticator(
        codec: $codec,
        repository: new FakeApiKeyRepository([$record]),
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: $limiter,
    );
    $authenticate = fn () => $authenticator->authenticate($issued->plainText, new KeyContext('203.0.113.10'));

    $secondOutcome = null;
    $limiter->interleave(function () use (&$secondOutcome, $authenticate): void {
        $secondOutcome = concurrentOutcome($authenticate);
    });
    $firstOutcome = concurrentOutcome($authenticate);

    expect([$firstOutcome, $secondOutcome])->toEqualCanonicalizing(['authenticated', 'too_many_requests'])
        ->and($limiter->inner->hitsFor('api-key:42'))->toBe(1);
});

it('evaluates only maxPerMinute guesses when two invalid guesses race from one IP', function (): void {
    $codec = concurrentCodec();
    $issued = $codec->issue();
    $record = new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: hash('sha256', 'a different secret'),
        scopes: ['items:read'],
    );
    $failureLimiter = new InterleavingAttemptLimiter;
    $authenticator = new ApiKeyAuthenticator(
        codec: $codec,
        repository: new FakeApiKeyRepository([$record]),
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: new FakeAttemptLimiter,
        failedAttemptLimiter: new FailedAttemptLimiter($failureLimiter, maxPerMinute: 1),
    );
    $authenticate = fn () => $authenticator->authenticate($issued->plainText, new KeyContext('203.0.113.10'));

    $secondOutcome = null;
    $failureLimiter->interleave(function () use (&$secondOutcome, $authenticate): void {
        $secondOutcome = concurrentOutcome($authenticate);
    });
    $firstOutcome = concurrentOutcome($authenticate);

    expect([$firstOutcome, $secondOutcome])->toEqualCanonicalizing(['invalid_token', 'too_many_requests'])
        ->and($failureLimiter->inner->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(1);
});

it('never refuses a valid key because other valid requests from its IP are still being verified', function (): void {
    $codec = concurrentCodec();
    $issued = $codec->issue();
    $record = new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    );
    $repository = new ReentrantApiKeyRepository(new FakeApiKeyRepository([$record]));
    $failures = new FakeAttemptLimiter;
    $authenticator = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $repository,
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: new FakeAttemptLimiter,
        failedAttemptLimiter: new FailedAttemptLimiter($failures, maxPerMinute: 1),
        defaultRateLimitPerMinute: 0,
    );
    $authenticate = fn () => $authenticator->authenticate($issued->plainText, new KeyContext('203.0.113.10'));

    $secondOutcome = null;
    $repository->interleave(function () use (&$secondOutcome, $authenticate): void {
        $secondOutcome = concurrentOutcome($authenticate);
    });
    $firstOutcome = concurrentOutcome($authenticate);

    expect([$firstOutcome, $secondOutcome])->toBe(['authenticated', 'authenticated'])
        ->and($failures->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);
});
