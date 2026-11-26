<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Schema;
use Qiick\ApiKeys\ApiKeyAuthenticator;
use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\UsageSideEffect;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\IpAllowlist;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\Testing\ArrayScopeVocabulary;
use Qiick\ApiKeys\Testing\DummyMatchProbe;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeKeyAuthorizer;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\Tests\Support\UnavailableAttemptLimiter;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;
use Qiick\ApiKeys\UsageRecorder;

mutates(ApiKeyAuthenticator::class);
mutates(AuthorizationDecision::class);

function makeCodec(?DummyMatchProbe $probe = null): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-api-key-tests!!'),
        onDummyMatch: $probe !== null ? $probe->record(...) : null,
    );
}

/**
 * @param  array{
 *     repository?: FakeApiKeyRepository,
 *     authorizer?: FakeKeyAuthorizer,
 *     limiter?: AttemptLimiter,
 *     failedLimiter?: FailedAttemptLimiter|null,
 *     clock?: FixedClock,
 *     throttle?: int,
 *     bypassIp?: bool,
 *     defaultRate?: int,
 *     record?: InMemoryApiKeyRecord,
 *     token?: string,
 *     exceptionReporter?: callable(Throwable): void,
 *     probe?: DummyMatchProbe,
 * }  $overrides
 * @return array{
 *     auth: ApiKeyAuthenticator,
 *     codec: TokenCodec,
 *     token: string,
 *     prefix: string,
 *     hash: string,
 *     record: InMemoryApiKeyRecord,
 *     repository: FakeApiKeyRepository,
 *     authorizer: FakeKeyAuthorizer,
 *     limiter: FakeAttemptLimiter,
 *     clock: FixedClock,
 *     now: DateTimeImmutable,
 *     probe: DummyMatchProbe|null,
 * }
 */
function authenticator(array $overrides = []): array
{
    $probe = $overrides['probe'] ?? null;
    $codec = makeCodec($probe);
    $issued = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $record = $overrides['record'] ?? new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read', 'items:write'],
    );

    $repository = $overrides['repository'] ?? new FakeApiKeyRepository([$record]);
    $authorizer = $overrides['authorizer'] ?? new FakeKeyAuthorizer;
    $limiter = $overrides['limiter'] ?? new FakeAttemptLimiter;
    $clock = $overrides['clock'] ?? new FixedClock($now);

    // Omit throttle / bypass / defaultRate unless overridden so constructor
    // defaults stay load-bearing for mutation coverage.
    $params = [
        'codec' => $codec,
        'repository' => $repository,
        'authorizer' => $authorizer,
        'vocabulary' => new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        'ipAllowlist' => new IpAllowlist,
        'usageRecorder' => new UsageRecorder,
        'clock' => $clock,
        'attemptLimiter' => $limiter,
        'failedAttemptLimiter' => $overrides['failedLimiter'] ?? null,
        'exceptionReporter' => $overrides['exceptionReporter'] ?? null,
    ];
    if (array_key_exists('throttle', $overrides)) {
        $params['usageThrottleSeconds'] = $overrides['throttle'];
    }
    if (array_key_exists('bypassIp', $overrides)) {
        $params['bypassThrottleOnIpChange'] = $overrides['bypassIp'];
    }
    if (array_key_exists('defaultRate', $overrides)) {
        $params['defaultRateLimitPerMinute'] = $overrides['defaultRate'];
    }

    $auth = new ApiKeyAuthenticator(...$params);

    return [
        'auth' => $auth,
        'codec' => $codec,
        'token' => $overrides['token'] ?? $issued->plainText,
        'prefix' => $issued->keyPrefix,
        'hash' => $issued->keyHash,
        'record' => $record,
        'repository' => $repository,
        'authorizer' => $authorizer,
        'limiter' => $limiter,
        'clock' => $clock,
        'now' => $now,
        'probe' => $probe,
    ];
}

function keyContext(?string $ip = '203.0.113.10'): KeyContext
{
    return new KeyContext(ip: $ip);
}

it('authenticates a valid current secret and records usage', function (): void {
    $sideEffect = new class implements UsageSideEffect
    {
        public ?bool $wasFirstUse = null;

        public function afterRecorded(
            ApiKeyRecord $record,
            ?string $ip,
            ?string $userAgent,
            bool $wasFirstUse,
        ): void {
            $this->wasFirstUse = $wasFirstUse;
        }
    };

    $codec = makeCodec();
    $issued = $codec->issue();
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read', 'items:write'],
    );
    $repository = new FakeApiKeyRepository([$record]);
    $limiter = new FakeAttemptLimiter;
    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $repository,
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: $limiter,
        usageSideEffect: $sideEffect,
    );

    $result = $auth->authenticate($issued->plainText, keyContext());

    expect($result->record->id())->toBe('42')
        ->and($result->usedPreviousSecret)->toBeFalse()
        ->and($result->legacyMatcherClass)->toBeNull()
        ->and($result->grantedScopes->allows(Scope::tryFromString('items:read')))->toBeTrue()
        ->and($repository->recordedUsages)->toHaveCount(1)
        ->and($limiter->hitsFor('api-key:42'))->toBe(1)
        ->and($sideEffect->wasFirstUse)->toBeTrue();
});

it('authenticates a real Externa ek_+9+31 legacy token', function (): void {
    $matcher = RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2099-01-01T00:00:00+00:00'));
    $codec = new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-api-key-tests!!'),
        legacyMatchers: [$matcher],
    );
    $legacyPlain = 'ek_ABCDEFGHI'.str_repeat('y', 31);
    $record = new InMemoryApiKeyRecord(
        id: 'ek-1',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: hash('sha256', $legacyPlain),
        scopes: ['items:read'],
    );
    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: new FakeApiKeyRepository([$record]),
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15T12:00:00+00:00')),
        attemptLimiter: new FakeAttemptLimiter,
        defaultRateLimitPerMinute: 0,
    );

    $result = $auth->authenticate($legacyPlain, keyContext());

    expect($result->record->id())->toBe('ek-1')
        ->and($result->legacyMatcherClass)->toBe(RegexLegacyTokenMatcher::class)
        ->and($result->usedPreviousSecret)->toBeFalse();

    expect(fn () => $auth->authenticate('ek_ABCDEFGHI', keyContext()))
        ->toThrow(ApiKeyRejection::class);
});

it('accepts the previous secret inside the grace window (A3)', function (): void {
    $codec = makeCodec();
    $first = $codec->issue();
    $second = $codec->reissueForPrefix($first->keyPrefix);
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $record = (new InMemoryApiKeyRecord(
        id: '7',
        keyPrefix: $first->keyPrefix,
        keyHash: $second->keyHash,
        scopes: ['items:read'],
    ))->withPrevious($first->keyHash, $now->modify('+1 hour'));

    $fixture = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'record' => $record,
        'token' => $first->plainText,
        'clock' => new FixedClock($now),
        'defaultRate' => 0,
    ]);

    $result = $fixture['auth']->authenticate($first->plainText, keyContext());

    expect($result->usedPreviousSecret)->toBeTrue()
        ->and($result->record->id())->toBe('7');
});

it('returns identical invalid_token for format-miss and hash-miss (A2b)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    try {
        $fixture['auth']->authenticate('not-a-token', keyContext());
        $this->fail('expected format miss');
    } catch (ApiKeyRejection $formatMiss) {
        try {
            $fixture['auth']->authenticate($fixture['prefix'].str_repeat('x', 32), keyContext());
            $this->fail('expected hash miss');
        } catch (ApiKeyRejection $hashMiss) {
            expect($formatMiss->render()->getData(true))->toBe($hashMiss->render()->getData(true))
                ->and($formatMiss->render()->headers->get('WWW-Authenticate'))
                ->toBe($hashMiss->render()->headers->get('WWW-Authenticate'))
                ->and($formatMiss->errorCode())->toBe('invalid_token')
                ->and($hashMiss->errorCode())->toBe('invalid_token');
        }
    }
});

it('rejects with invalid_token and a dummy compare when the prefix has no candidates (A2)', function (): void {
    $fixture = authenticator([
        'repository' => new FakeApiKeyRepository([]),
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('invalid_token')
            ->and($rejection->getMessage())->toBe('The API key is not valid.');
    }
});

it('denies revoked and expired keys after a successful match (A3b)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $now = $fixture['now'];

    $revokedOnly = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '42',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: ['items:read'],
            ))->withRevokedAt($now->modify('-1 hour')),
        ]),
        'token' => $fixture['token'],
        'clock' => $fixture['clock'],
        'defaultRate' => 0,
    ]);

    try {
        $revokedOnly['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected revoked rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('invalid_token')
            ->and($rejection->getMessage())->toBe('The API key has been revoked.');
    }

    $expiredOnly = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '42',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: ['items:read'],
            ))->withExpiresAt($now->modify('-1 second')),
        ]),
        'token' => $fixture['token'],
        'clock' => $fixture['clock'],
        'defaultRate' => 0,
    ]);

    try {
        $expiredOnly['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected expired rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getMessage())->toBe('The API key has expired.');
    }

    $codec = makeCodec();
    $old = $codec->issue();
    $new = $codec->reissueForPrefix($old->keyPrefix);

    $revokedPrevious = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '9',
                keyPrefix: $old->keyPrefix,
                keyHash: $new->keyHash,
                scopes: ['items:read'],
            ))->withPrevious($old->keyHash, $now->modify('+2 hours'))
                ->withRevokedAt($now->modify('-1 minute')),
        ]),
        'token' => $old->plainText,
        'clock' => new FixedClock($now),
        'defaultRate' => 0,
    ]);

    expect(fn () => $revokedPrevious['auth']->authenticate($old->plainText, keyContext()))
        ->toThrow(ApiKeyRejection::class);
});

it('denies when the actor authorizer refuses (401 invalid_token)', function (): void {
    $fixture = authenticator([
        'authorizer' => (new FakeKeyAuthorizer)->denyActor('owner inactive'),
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('invalid_token')
            ->and($rejection->getMessage())->toBe('owner inactive');
    }
});

it('checks IP before scopes when both would fail (A7)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: [],
    ))->withIpAllowlist(['198.51.100.1']);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('ip_not_allowed');
    }
});

it('returns 403 insufficient_scope for empty scopes, never 401 (A8)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([
            new InMemoryApiKeyRecord(
                id: '42',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: [],
            ),
        ]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getStatusCode())->toBe(403)
            ->and($rejection->errorCode())->toBe('insufficient_scope');
    }
});

it('enforces required scope and authorizer ceiling (A6)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $required = Scope::tryFromString('items:write');

    $ok = $fixture['auth']->authenticate($fixture['token'], keyContext(), $required);
    expect($ok->grantedScopes->allows($required))->toBeTrue();

    try {
        $fixture['auth']->authenticate(
            $fixture['token'],
            keyContext(),
            Scope::tryFromString('files:read'),
        );
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('insufficient_scope')
            ->and($rejection->render()->getData(true)['scope'])->toBe('files:read');
    }

    $ceiling = authenticator([
        'authorizer' => (new FakeKeyAuthorizer)->denyScopes(),
        'defaultRate' => 0,
    ]);

    try {
        $ceiling['auth']->authenticate($ceiling['token'], keyContext(), Scope::tryFromString('items:read'));
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('insufficient_scope');
    }
});

it('rate-limits with default api-key:{id} bucket and rejects over limit (A17)', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'limiter' => $limiter,
        'defaultRate' => 2,
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());
    $fixture['auth']->authenticate($fixture['token'], keyContext());

    expect($limiter->hitsFor('api-key:42'))->toBe(2);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rate limit');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getStatusCode())->toBe(429)
            ->and($rejection->errorCode())->toBe('rate_limit_exceeded')
            ->and($rejection->render()->headers->get('Retry-After'))->not->toBeNull();
    }
});

it('uses the authorizer rate-limit decision when provided', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'limiter' => $limiter,
        'authorizer' => (new FakeKeyAuthorizer)->withRateLimit(
            new RateLimitDecision('custom-bucket', 1, 30),
        ),
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());

    expect($limiter->hitsFor('custom-bucket'))->toBe(1)
        ->and($limiter->hitsFor('api-key:42'))->toBe(0);
});

it('skips rate limiting when default is 0 and authorizer returns null', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'limiter' => $limiter,
        'defaultRate' => 0,
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());

    expect($limiter->hitsFor('api-key:42'))->toBe(0);
});

it('throttles usage writes and bypasses on IP change (A12)', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $codec = makeCodec();
    $issued = $codec->issue();

    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withLastUsed($now->modify('-10 seconds'), '203.0.113.10');

    $repository = new FakeApiKeyRepository([$record]);
    $auth = authenticator([
        'repository' => $repository,
        'record' => $record,
        'token' => $issued->plainText,
        'clock' => new FixedClock($now),
        'throttle' => 60,
        'bypassIp' => true,
        'defaultRate' => 0,
    ]);

    $auth['auth']->authenticate($issued->plainText, keyContext('203.0.113.10'));
    expect($repository->recordedUsages)->toHaveCount(0);

    $auth['auth']->authenticate($issued->plainText, keyContext('198.51.100.1'));
    expect($repository->recordedUsages)->toHaveCount(1);
});

it('never puts the presented token into rejection output (A14)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $token = $fixture['token'];

    foreach (['bad-token', $fixture['prefix'].str_repeat('0', 32)] as $presented) {
        try {
            $fixture['auth']->authenticate($presented, keyContext());
            $this->fail('expected rejection');
        } catch (ApiKeyRejection $rejection) {
            $json = json_encode($rejection->render()->getData(true), JSON_THROW_ON_ERROR);
            expect($rejection->getMessage())->not->toContain($token)
                ->and($json)->not->toContain($token)
                ->and(json_encode($rejection->__debugInfo()))->not->toContain($token);
        }
    }
});

it('builds AuthorizationDecision allow and deny helpers', function (): void {
    expect(AuthorizationDecision::allow()->allowed)->toBeTrue()
        ->and(AuthorizationDecision::allow()->denialMessage)->toBeNull()
        ->and(AuthorizationDecision::deny('nope')->allowed)->toBeFalse()
        ->and(AuthorizationDecision::deny('nope')->denialMessage)->toBe('nope');
});

it('keeps the first matching candidate when several share a prefix', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    $valid = new InMemoryApiKeyRecord(
        id: 'first',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:read'],
    );
    $revokedDuplicate = (new InMemoryApiKeyRecord(
        id: 'second',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:read'],
    ))->withRevokedAt($fixture['now']->modify('-1 minute'));

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$valid, $revokedDuplicate]),
        'token' => $fixture['token'],
        'clock' => $fixture['clock'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext());
    expect($result->record->id())->toBe('first');
});

it('treats expiresAt equal to now as expired', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '42',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: ['items:read'],
            ))->withExpiresAt($fixture['now']),
        ]),
        'token' => $fixture['token'],
        'clock' => $fixture['clock'],
        'defaultRate' => 0,
    ]);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected expired');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getMessage())->toBe('The API key has expired.');
    }
});

it('denies a null client IP against a non-empty allowlist', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '42',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: ['items:read'],
            ))->withIpAllowlist(['203.0.113.10']),
        ]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext(null));
        $this->fail('expected ip denial');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('ip_not_allowed');
    }
});

it('maps authorizer scope denial without a required scope to noUsableScopes', function (): void {
    $fixture = authenticator([
        'authorizer' => (new FakeKeyAuthorizer)->denyScopes(),
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('insufficient_scope')
            ->and($rejection->getMessage())->toBe('The API key holds no scopes.');
    }
});

it('prefers the record rate_limit_per_minute over the package default', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator(['defaultRate' => 0]);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '99',
                keyPrefix: $fixture['prefix'],
                keyHash: $fixture['hash'],
                scopes: ['items:read'],
            ))->withRateLimitPerMinute(1),
        ]),
        'token' => $fixture['token'],
        'limiter' => $limiter,
        'defaultRate' => 0,
    ]);

    $auth['auth']->authenticate($fixture['token'], keyContext());
    expect($limiter->hitsFor('api-key:99'))->toBe(1);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rate limit');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('rate_limit_exceeded');
    }
});

it('flags usedPreviousSecret only for previous-hash matches', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $current = $fixture['auth']->authenticate($fixture['token'], keyContext());
    expect($current->usedPreviousSecret)->toBeFalse();

    $codec = makeCodec();
    $first = $codec->issue();
    $second = $codec->reissueForPrefix($first->keyPrefix);
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([
            (new InMemoryApiKeyRecord(
                id: '7',
                keyPrefix: $first->keyPrefix,
                keyHash: $second->keyHash,
                scopes: ['items:read'],
            ))->withPrevious($first->keyHash, $now->modify('+1 hour')),
        ]),
        'token' => $first->plainText,
        'clock' => new FixedClock($now),
        'defaultRate' => 0,
    ]);

    expect($auth['auth']->authenticate($first->plainText, keyContext())->usedPreviousSecret)->toBeTrue();
});

it('records usage after the throttle window elapses', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $codec = makeCodec();
    $issued = $codec->issue();

    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withLastUsed($now->modify('-61 seconds'), '203.0.113.10');

    $repository = new FakeApiKeyRepository([$record]);
    $auth = authenticator([
        'repository' => $repository,
        'token' => $issued->plainText,
        'clock' => new FixedClock($now),
        'throttle' => 60,
        'bypassIp' => false,
        'defaultRate' => 0,
    ]);

    $auth['auth']->authenticate($issued->plainText, keyContext('203.0.113.10'));
    expect($repository->recordedUsages)->toHaveCount(1);
});

it('runs performDummyMatch when no candidates match the prefix', function (): void {
    $probe = new DummyMatchProbe;
    $fixture = authenticator([
        'repository' => new FakeApiKeyRepository([]),
        'defaultRate' => 0,
        'probe' => $probe,
    ]);

    expect($probe->calls)->toBe(0);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection) {
        expect($probe->calls)->toBe(1);
    }
});

it('narrows grantedScopes to the owner ceiling before highest-per-resource (A6)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);

    // Key stores only write; owner demoted to read — must keep items:read, not 403.
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:write'],
    );

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'authorizer' => (new FakeKeyAuthorizer)->withCreatorMayGrant(['items:read']),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext());

    expect($result->grantedScopes->values())->toBe(['items:read'])
        ->and($result->grantedScopes->allows(Scope::tryFromString('items:read')))->toBeTrue()
        ->and($result->grantedScopes->allows(Scope::tryFromString('items:write')))->toBeFalse();
});

it('dedupes grantedScopes when stored read+write both demote to read', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:read', 'items:write'],
    );

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'authorizer' => (new FakeKeyAuthorizer)->withCreatorMayGrant(['items:read']),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext());

    expect($result->grantedScopes->values())->toBe(['items:read']);
});

it('fail-closes when the key has no owner and no creator', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:read'],
    ))->withOwnerIdentifier(null)->withCreatedByIdentifier(null);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('insufficient_scope');
    }
});

it('keeps authentication when recordUsage throws (audit stamp must not 500)', function (): void {
    $reported = [];
    $fixture = authenticator(['defaultRate' => 0]);

    $matching = authenticator([
        'repository' => new class($fixture['hash'], $fixture['prefix']) implements ApiKeyRepository
        {
            public function __construct(private string $hash, private string $prefix) {}

            public function findCandidatesByPrefix(string $keyPrefix): iterable
            {
                return [new InMemoryApiKeyRecord(
                    id: '42',
                    keyPrefix: $this->prefix,
                    keyHash: $this->hash,
                    scopes: ['items:read'],
                )];
            }

            public function findByPublicId(string $publicId): ?ApiKeyRecord
            {
                return null;
            }

            public function expiringUnnotified(DateTimeImmutable $until): iterable
            {
                return [];
            }

            public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt, string $claimToken): bool
            {
                return false;
            }

            public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds, string $claimToken): bool
            {
                return true;
            }

            public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void {}

            public function findActiveLegacy(): iterable
            {
                return [];
            }

            public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void
            {
                throw new RuntimeException('usage write failed');
            }
        },
        'token' => $fixture['token'],
        'defaultRate' => 0,
        'exceptionReporter' => function (Throwable $exception) use (&$reported): void {
            $reported[] = $exception;
        },
    ]);

    $result = $matching['auth']->authenticate($fixture['token'], keyContext());

    expect($result->record->id())->toBe('42')
        ->and($reported)->toHaveCount(1)
        ->and($reported[0])->toBeInstanceOf(RuntimeException::class);
});

it('never leaks the presented token via SensitiveParameter in traces (A14)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $token = $fixture['token'];

    $assertClean = function (Throwable $exception) use ($token): void {
        expect($exception->getMessage())->not->toContain($token)
            ->and($exception->getTraceAsString())->not->toContain($token);

        try {
            expect(serialize($exception))->not->toContain($token);
        } catch (Exception $serializationFailure) {
            // Trace frames hold SensitiveParameterValue, which PHP refuses to serialize.
            expect($serializationFailure->getMessage())->toContain('SensitiveParameterValue');
        }

        foreach ($exception->getTrace() as $frame) {
            foreach ($frame['args'] ?? [] as $argument) {
                if ($argument instanceof SensitiveParameterValue) {
                    continue;
                }

                if (is_string($argument)) {
                    expect($argument)->not->toBe($token);
                }
            }
        }
    };

    try {
        $fixture['auth']->authenticate($token.'-bad', keyContext());
        $this->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        $assertClean($rejection);
    }

    $exploding = authenticator([
        'repository' => new class implements ApiKeyRepository
        {
            public function findCandidatesByPrefix(string $keyPrefix): iterable
            {
                throw new RuntimeException('repository boom');
            }

            public function findByPublicId(string $publicId): ?ApiKeyRecord
            {
                return null;
            }

            public function expiringUnnotified(DateTimeImmutable $until): iterable
            {
                return [];
            }

            public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt, string $claimToken): bool
            {
                return false;
            }

            public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds, string $claimToken): bool
            {
                return true;
            }

            public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void {}

            public function findActiveLegacy(): iterable
            {
                return [];
            }

            public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void {}
        },
        'token' => $token,
        'defaultRate' => 0,
    ]);

    try {
        $exploding['auth']->authenticate($token, keyContext());
        $this->fail('expected repository boom');
    } catch (RuntimeException $exception) {
        $assertClean($exception);
    }
});

it('applies the pre-auth failed-attempt limiter on 401 paths (A15)', function (): void {
    $limiter = new FakeAttemptLimiter;
    $failed = new FailedAttemptLimiter($limiter, maxPerMinute: 2);
    $fixture = authenticator([
        'failedLimiter' => $failed,
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate('bad-1', keyContext('203.0.113.10'));
    } catch (ApiKeyRejection) {
    }
    try {
        $fixture['auth']->authenticate('bad-2', keyContext('203.0.113.10'));
    } catch (ApiKeyRejection) {
    }

    expect($limiter->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(2);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));
        $this->fail('expected rate limit');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('rate_limit_exceeded')
            ->and($rejection->getStatusCode())->toBe(429);
    }
});

it('hits the failed-attempt brake on every 401 path', function (): void {
    $bucket = 'api-key-failures:v4:203.0.113.10';
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $assertHit = function (callable $build) use ($bucket): void {
        $limiter = new FakeAttemptLimiter;
        $build($limiter);
        expect($limiter->hitsFor($bucket))->toBe(1);
    };

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $auth = authenticator([
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate('not-a-token', keyContext());
        } catch (ApiKeyRejection) {
        }
    });

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $auth = authenticator([
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate($auth['prefix'].str_repeat('x', 32), keyContext());
        } catch (ApiKeyRejection) {
        }
    });

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $base = authenticator(['defaultRate' => 0, 'clock' => new FixedClock($now)]);
        $auth = authenticator([
            'repository' => new FakeApiKeyRepository([
                (new InMemoryApiKeyRecord(
                    id: '42',
                    keyPrefix: $base['prefix'],
                    keyHash: $base['hash'],
                    scopes: ['items:read'],
                ))->withRevokedAt($now->modify('-1 minute')),
            ]),
            'token' => $base['token'],
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate($base['token'], keyContext());
        } catch (ApiKeyRejection) {
        }
    });

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $base = authenticator(['defaultRate' => 0, 'clock' => new FixedClock($now)]);
        $auth = authenticator([
            'repository' => new FakeApiKeyRepository([
                (new InMemoryApiKeyRecord(
                    id: '42',
                    keyPrefix: $base['prefix'],
                    keyHash: $base['hash'],
                    scopes: ['items:read'],
                ))->withExpiresAt($now->modify('-1 second')),
            ]),
            'token' => $base['token'],
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate($base['token'], keyContext());
        } catch (ApiKeyRejection) {
        }
    });

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $auth = authenticator([
            'authorizer' => (new FakeKeyAuthorizer)->denyActor('gone'),
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate($auth['token'], keyContext());
        } catch (ApiKeyRejection) {
        }
    });

    $assertHit(function (FakeAttemptLimiter $limiter) use ($now): void {
        $auth = authenticator([
            'repository' => new FakeApiKeyRepository([]),
            'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
            'defaultRate' => 0,
            'clock' => new FixedClock($now),
        ]);
        try {
            $auth['auth']->authenticate($auth['token'], keyContext());
        } catch (ApiKeyRejection) {
        }
    });
});

it('pins constructor defaults for throttle, IP bypass, and rate limit', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $codec = makeCodec();
    $issued = $codec->issue();
    $limiter = new FakeAttemptLimiter;

    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withLastUsed($now->modify('-59 seconds'), '203.0.113.10');

    $repository = new FakeApiKeyRepository([$record]);
    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $repository,
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock($now),
        attemptLimiter: $limiter,
    );

    // Default throttle 60: 59s elapsed, same IP → no usage write (kills Decrement 60→59).
    $auth->authenticate($issued->plainText, keyContext('203.0.113.10'));
    expect($repository->recordedUsages)->toHaveCount(0)
        ->and($limiter->lastDecaySeconds['api-key:42'])->toBe(60);

    // Exactly 60s elapsed must record under default 60 (kills Increment 60→61).
    $boundaryRecord = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withLastUsed($now->modify('-60 seconds'), '203.0.113.10');
    $boundaryRepo = new FakeApiKeyRepository([$boundaryRecord]);
    $atBoundary = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $boundaryRepo,
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock($now),
        attemptLimiter: new FakeAttemptLimiter,
    );
    $atBoundary->authenticate($issued->plainText, keyContext('203.0.113.10'));
    expect($boundaryRepo->recordedUsages)->toHaveCount(1);

    // Default bypassThrottleOnIpChange true: IP change records inside the window.
    $auth->authenticate($issued->plainText, keyContext('198.51.100.1'));
    expect($repository->recordedUsages)->toHaveCount(1);

    // Fresh limiter for the default rate=60 ceiling (tooMany when hits >= 60).
    $rateLimiter = new FakeAttemptLimiter;
    $rateAuth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $repository,
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock($now),
        attemptLimiter: $rateLimiter,
    );

    for ($i = 0; $i < 60; $i++) {
        $rateAuth->authenticate($issued->plainText, keyContext('198.51.100.1'));
    }
    expect($rateLimiter->hitsFor('api-key:42'))->toBe(60);

    try {
        $rateAuth->authenticate($issued->plainText, keyContext('198.51.100.1'));
        $this->fail('expected rate limit');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getStatusCode())->toBe(429)
            ->and($rejection->render()->headers->get('X-RateLimit-Remaining'))->toBe('0');
    }
});

it('falls back to createdBy when owner is null for the ceiling', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:write', 'files:read'],
    ))->withOwnerIdentifier(null)->withCreatedByIdentifier(99);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'authorizer' => (new FakeKeyAuthorizer)->withCreatorMayGrant(['items:read']),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext());

    expect($result->grantedScopes->values())->toBe(['items:read']);
});

it('prefers owner over createdBy when both are set (coalesce left is load-bearing)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $record = (new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:write', 'files:read'],
    ))->withOwnerIdentifier(1)->withCreatedByIdentifier(99);

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'authorizer' => (new FakeKeyAuthorizer)->withCreatorMayGrantById([
            1 => ['items:read'],
            99 => ['items:write', 'items:read', 'files:read'],
        ]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext());

    // Owner ceiling wins → demote to items:read; createdBy alone would keep write+files.
    expect($result->grantedScopes->values())->toBe(['items:read']);
});

it('passes the real client IP into the allowlist (null coalesce is load-bearing)', function (): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $fixture['prefix'],
        keyHash: $fixture['hash'],
        scopes: ['items:read'],
        ipAllowlist: ['203.0.113.10'],
    );

    $auth = authenticator([
        'repository' => new FakeApiKeyRepository([$record]),
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    $result = $auth['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));
    expect($result->record->id())->toBe('42');

    try {
        $auth['auth']->authenticate($fixture['token'], keyContext('198.51.100.1'));
        $this->fail('expected IP denial');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('ip_not_allowed');
    }
});

it('does not invoke the exception reporter when usageSideEffect is null', function (): void {
    $reported = [];
    $fixture = authenticator([
        'defaultRate' => 0,
        'exceptionReporter' => function (Throwable $exception) use (&$reported): void {
            $reported[] = $exception;
        },
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());

    expect($reported)->toBe([]);
});

it('reports usage failures via the Laravel report() helper when no reporter is wired', function (): void {
    Exceptions::fake();
    $fixture = authenticator(['defaultRate' => 0]);

    $matching = authenticator([
        'repository' => new class($fixture['hash'], $fixture['prefix']) implements ApiKeyRepository
        {
            public function __construct(private string $hash, private string $prefix) {}

            public function findCandidatesByPrefix(string $keyPrefix): iterable
            {
                return [new InMemoryApiKeyRecord(
                    id: '42',
                    keyPrefix: $this->prefix,
                    keyHash: $this->hash,
                    scopes: ['items:read'],
                )];
            }

            public function findByPublicId(string $publicId): ?ApiKeyRecord
            {
                return null;
            }

            public function expiringUnnotified(DateTimeImmutable $until): iterable
            {
                return [];
            }

            public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt, string $claimToken): bool
            {
                return false;
            }

            public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds, string $claimToken): bool
            {
                return true;
            }

            public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void {}

            public function findActiveLegacy(): iterable
            {
                return [];
            }

            public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void
            {
                throw new RuntimeException('usage write failed');
            }
        },
        'token' => $fixture['token'],
        'defaultRate' => 0,
    ]);

    // No exceptionReporter — exercise the function_exists('report') fallback.
    $result = $matching['auth']->authenticate($fixture['token'], keyContext());
    expect($result->record->id())->toBe('42');
    Exceptions::assertReported(fn (RuntimeException $exception): bool => $exception->getMessage() === 'usage write failed');
});

it('asserts remaining=0 on the pre-auth failed-attempt 429', function (): void {
    $limiter = new FakeAttemptLimiter;
    $failed = new FailedAttemptLimiter($limiter, maxPerMinute: 1);
    $fixture = authenticator([
        'failedLimiter' => $failed,
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate('bad', keyContext('203.0.113.10'));
    } catch (ApiKeyRejection) {
    }

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));
        $this->fail('expected rate limit');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->render()->headers->get('X-RateLimit-Remaining'))->toBe('0');
    }
});

it('does not count repository exceptions as failed attempts', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'repository' => new class implements ApiKeyRepository
        {
            public function findCandidatesByPrefix(string $keyPrefix): iterable
            {
                throw new RuntimeException('db down');
            }

            public function findByPublicId(string $publicId): ?ApiKeyRecord
            {
                return null;
            }

            public function expiringUnnotified(DateTimeImmutable $until): iterable
            {
                return [];
            }

            public function markExpiryNotified(ApiKeyRecord $record, DateTimeImmutable $notifiedAt, string $claimToken): bool
            {
                return false;
            }

            public function claimExpiryNotice(ApiKeyRecord $record, DateTimeImmutable $now, int $leaseSeconds, string $claimToken): bool
            {
                return true;
            }

            public function releaseExpiryNotice(ApiKeyRecord $record, string $claimToken): void {}

            public function findActiveLegacy(): iterable
            {
                return [];
            }

            public function recordUsage(ApiKeyRecord $record, ?string $ip, ?string $userAgent, DateTimeImmutable $usedAt): void {}
        },
        'failedLimiter' => new FailedAttemptLimiter($limiter, 20),
        'defaultRate' => 0,
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected repository boom');
    } catch (RuntimeException) {
        expect($limiter->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(0);
    }
});

it('hands the brake slot back when the key authenticates or is refused for a non-credential reason', function (): void {
    $bucket = 'api-key-failures:v4:203.0.113.10';
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'failedLimiter' => new FailedAttemptLimiter($limiter, maxPerMinute: 1),
        'defaultRate' => 0,
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));
    $fixture['auth']->authenticate($fixture['token'], keyContext('203.0.113.10'));

    expect($limiter->hitsFor($bucket))->toBe(0);

    $allowlisted = authenticator([
        'record' => $fixture['record']->withIpAllowlist(['198.51.100.0/24']),
        'failedLimiter' => new FailedAttemptLimiter($limiter, maxPerMinute: 1),
        'defaultRate' => 0,
    ]);

    try {
        $allowlisted['auth']->authenticate($allowlisted['token'], keyContext('203.0.113.10'));
        $this->fail('expected ip_not_allowed');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('ip_not_allowed')
            ->and($limiter->hitsFor($bucket))->toBe(0);
    }
});

it('does not count a request refused by the per-key limit against that limit', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator(['limiter' => $limiter, 'defaultRate' => 1]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());

    foreach (range(1, 3) as $refusedAttempt) {
        expect(fn () => $fixture['auth']->authenticate($fixture['token'], keyContext()))
            ->toThrow(ApiKeyRejection::class);
    }

    expect($limiter->hitsFor('api-key:42'))->toBe(1);
});

it('accepts exactly the token versions it can verify', function (int $tokenVersion, bool $isAccepted): void {
    $fixture = authenticator(['defaultRate' => 0]);
    $versioned = authenticator([
        'record' => $fixture['record']->withTokenVersion($tokenVersion),
        'defaultRate' => 0,
    ]);

    $outcome = fn () => $versioned['auth']->authenticate($versioned['token'], keyContext());

    if ($isAccepted) {
        expect($outcome()->record->tokenVersion())->toBe($tokenVersion);

        return;
    }

    expect($outcome)->toThrow(ApiKeyRejection::class, 'The API key is not valid.');
})->with([
    'legacy 0' => [0, true],
    'canonical 1' => [1, true],
    'checksummed 2' => [2, true],
    'unknown 3' => [3, false],
    'negative' => [-1, false],
]);

it('skips row windows that are unset or not positive', function (?int $perDay, ?int $perMonth): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator(['limiter' => $limiter, 'defaultRate' => 0]);
    $windowed = authenticator([
        'limiter' => $limiter,
        'defaultRate' => 0,
        'record' => $fixture['record']->withRateLimitPerDay($perDay)->withRateLimitPerMonth($perMonth),
    ]);

    $windowed['auth']->authenticate($windowed['token'], keyContext());

    expect($limiter->lastDecaySeconds)->toBe([]);
})->with([
    'unset' => [null, null],
    'zero' => [0, 0],
    'negative' => [-1, -1],
]);

it('gives back the hits it took on earlier windows when a later window refuses', function (): void {
    $limiter = new FakeAttemptLimiter;
    $fixture = authenticator([
        'limiter' => $limiter,
        'authorizer' => (new FakeKeyAuthorizer)->withRateLimits([
            new RateLimitDecision('minute-bucket', 5, 60),
            new RateLimitDecision('day-bucket', 1, 86_400),
        ]),
    ]);

    $fixture['auth']->authenticate($fixture['token'], keyContext());

    expect(fn () => $fixture['auth']->authenticate($fixture['token'], keyContext()))
        ->toThrow(ApiKeyRejection::class);

    expect($limiter->hitsFor('minute-bucket'))->toBe(1)
        ->and($limiter->hitsFor('day-bucket'))->toBe(1);
});

it('answers rate_limited, never the real outcome, once the failed-attempt bucket is full', function (): void {
    $failures = new FakeAttemptLimiter;
    $fixture = authenticator([
        'failedLimiter' => new FailedAttemptLimiter($failures, maxPerMinute: 2),
        'defaultRate' => 0,
    ]);
    $outcome = function (string $token) use ($fixture): string {
        try {
            $fixture['auth']->authenticate($token, keyContext('203.0.113.10'));

            return 'authenticated';
        } catch (ApiKeyRejection $rejection) {
            return $rejection->errorCode();
        }
    };

    expect($outcome($fixture['token']))->toBe('authenticated')
        ->and($outcome('bad-1'))->toBe('invalid_token')
        ->and($outcome('bad-2'))->toBe('invalid_token')
        ->and($outcome('bad-3'))->toBe('rate_limit_exceeded')
        // A correct key is not revealed while the bucket is full.
        ->and($outcome($fixture['token']))->toBe('rate_limit_exceeded')
        ->and($failures->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe(2);
});

it('refuses a rate-limit window shorter than one second', function (int $decaySeconds): void {
    expect(fn () => new RateLimitDecision('bucket', 10, $decaySeconds))
        ->toThrow(InvalidArgumentException::class, 'decaySeconds');
})->with([0, -5]);

it('answers a typed 503 when the attempt store is down, and reports the cause', function (string $whichLimiter): void {
    $reported = [];
    $down = new UnavailableAttemptLimiter;
    $fixture = authenticator([
        'limiter' => $whichLimiter === 'per-key limits' ? $down : new FakeAttemptLimiter,
        'failedLimiter' => $whichLimiter === 'failed-attempt brake' ? new FailedAttemptLimiter($down) : null,
        'exceptionReporter' => function (Throwable $exception) use (&$reported): void {
            $reported[] = $exception->getMessage();
        },
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext());
        $this->fail('expected service_unavailable');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->getStatusCode())->toBe(503)
            ->and($rejection->errorCode())->toBe('service_unavailable')
            ->and($rejection->render()->getData(true))->toBe([
                'message' => 'API key verification is temporarily unavailable.',
                'error' => 'service_unavailable',
            ])
            ->and($reported)->toBe(['attempt store down']);
    }
})->with(['failed-attempt brake', 'per-key limits']);

it('names the required scope when the key holds no usable scopes', function (): void {
    $seed = authenticator();
    $fixture = authenticator([
        'defaultRate' => 0,
        'record' => new InMemoryApiKeyRecord(id: '42', keyPrefix: $seed['prefix'], keyHash: $seed['hash'], scopes: ['unknown:scope']),
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext(), Scope::tryFromString('items:read'));
        $this->fail('expected insufficient_scope');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->render()->headers->get('WWW-Authenticate'))->toBe('Bearer error="insufficient_scope", scope="items:read"')
            ->and($rejection->render()->getData(true)['scope'])->toBe('items:read');
    }
});

/**
 * Laravel's `array` cast reads JSON that does not decode as null, and a null
 * allowlist or null restrictions mean "no restriction". Products therefore pass
 * the columns as stored and the authenticator decodes them, failing closed.
 *
 * @return array{0: string, 1: list<string>}
 */
function authenticateWithStoredColumn(string $column, mixed $stored, string $ip = '203.0.113.10'): array
{
    $reported = [];
    $seed = authenticator();
    $record = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $seed['prefix'],
        keyHash: $seed['hash'],
        scopes: $column === 'scopes' ? $stored : '["items:read"]',
        ipAllowlist: $column === 'ip_allowlist' ? $stored : null,
        restrictions: $column === 'restrictions' ? $stored : null,
    );
    $fixture = authenticator([
        'record' => $record,
        'defaultRate' => 0,
        'exceptionReporter' => function (Throwable $exception) use (&$reported): void {
            $reported[] = $exception::class.': '.$exception->getMessage();
        },
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext($ip));

        return ['authenticated', $reported];
    } catch (ApiKeyRejection $rejection) {
        return [$rejection->errorCode(), $reported];
    }
}

it('denies and reports a stored JSON column that does not decode', function (string $column, string $errorCode): void {
    [$outcome, $reported] = authenticateWithStoredColumn($column, '{"broken');

    expect($outcome)->toBe($errorCode)
        ->and($reported)->toBe([
            "UnexpectedValueException: The stored {$column} of API key 00000000-0000-7000-8000-000000000001 is not valid JSON: the key is denied.",
        ]);
})->with([
    'ip allowlist' => ['ip_allowlist', 'ip_not_allowed'],
    'restrictions' => ['restrictions', 'request_not_allowed'],
    'scopes' => ['scopes', 'insufficient_scope'],
]);

it('treats an empty stored string as JSON that does not decode', function (string $column): void {
    [$outcome, $reported] = authenticateWithStoredColumn($column, '');

    expect($outcome)->not->toBe('authenticated')
        ->and($reported)->toHaveCount(1);
})->with(['ip_allowlist', 'restrictions', 'scopes']);

it('decodes stored JSON columns and applies them', function (): void {
    expect(authenticateWithStoredColumn('ip_allowlist', '["203.0.113.10"]'))->toBe(['authenticated', []])
        ->and(authenticateWithStoredColumn('ip_allowlist', '["203.0.113.10"]', '198.51.100.1'))->toBe(['ip_not_allowed', []])
        ->and(authenticateWithStoredColumn('restrictions', '{"v":1,"request":{"methods":["POST"]}}'))->toBe(['request_not_allowed', []])
        ->and(authenticateWithStoredColumn('scopes', '["items:read"]'))->toBe(['authenticated', []]);
});

it('reads only a SQL NULL as no restriction, and decoded arrays as before', function (): void {
    expect(authenticateWithStoredColumn('ip_allowlist', null))->toBe(['authenticated', []])
        ->and(authenticateWithStoredColumn('restrictions', null))->toBe(['authenticated', []])
        ->and(authenticateWithStoredColumn('ip_allowlist', ['198.51.100.1']))->toBe(['ip_not_allowed', []]);
});

it('denies and reports a stored JSON null, which is not SQL NULL', function (string $column, string $errorCode): void {
    [$outcome, $reported] = authenticateWithStoredColumn($column, 'null');

    expect($outcome)->toBe($errorCode)
        ->and($reported)->toBe([
            "UnexpectedValueException: The stored {$column} of API key 00000000-0000-7000-8000-000000000001 is JSON null; only SQL NULL means no restriction: the key is denied.",
        ]);
})->with([
    'ip allowlist' => ['ip_allowlist', 'ip_not_allowed'],
    'restrictions' => ['restrictions', 'request_not_allowed'],
    'scopes' => ['scopes', 'insufficient_scope'],
]);

it('denies a corrupted JSON column read from an Eloquent model as the contract asks, which its array cast would hide', function (): void {
    Schema::create('api_keys', function (Blueprint $table): void {
        $table->id();
        $table->json('scopes');
        $table->json('ip_allowlist')->nullable();
        $table->json('restrictions')->nullable();
    });
    // SQLite stores the text as is; MySQL and PostgreSQL reject it, but a corrupted row can come from elsewhere.
    DB::table('api_keys')->insert([
        'scopes' => '["items:read"]',
        'ip_allowlist' => '["203.0.113.10"',
        'restrictions' => null,
    ]);
    $model = new class extends Model
    {
        protected $table = 'api_keys';

        protected function casts(): array
        {
            return ['scopes' => 'array', 'ip_allowlist' => 'array', 'restrictions' => 'array'];
        }
    };
    $stored = $model->newQuery()->firstOrFail();

    // The cast the product keeps for its own code reads the corrupted allowlist as "allow every IP".
    expect($stored->ip_allowlist)->toBeNull();

    // ApiKeyRecord::rawIpAllowlist() as documented: the column as stored.
    [$outcome, $reported] = authenticateWithStoredColumn('ip_allowlist', $stored->getRawOriginal('ip_allowlist'));

    expect($outcome)->toBe('ip_not_allowed')
        ->and($reported)->toHaveCount(1);
});

it('names the required scope when the stored scopes do not decode', function (): void {
    $seed = authenticator();
    $fixture = authenticator([
        'defaultRate' => 0,
        'record' => new InMemoryApiKeyRecord(id: '42', keyPrefix: $seed['prefix'], keyHash: $seed['hash'], scopes: '{"broken'),
        'exceptionReporter' => function (Throwable $exception): void {},
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext(), Scope::tryFromString('items:read'));
        $this->fail('expected insufficient_scope');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->render()->headers->get('WWW-Authenticate'))->toBe('Bearer error="insufficient_scope", scope="items:read"')
            ->and($rejection->render()->getData(true)['scope'])->toBe('items:read');
    }
});

it('denies and reports a stored JSON object where a list is expected', function (string $column, string $stored, string $errorCode): void {
    [$outcome, $reported] = authenticateWithStoredColumn($column, $stored);

    expect($outcome)->toBe($errorCode)
        ->and($reported)->toBe([
            "UnexpectedValueException: The stored {$column} of API key 00000000-0000-7000-8000-000000000001 is not a JSON list: the key is denied.",
        ]);
})->with([
    'empty object as ip allowlist' => ['ip_allowlist', '{}', 'ip_not_allowed'],
    'numbered object as ip allowlist' => ['ip_allowlist', '{"0":"203.0.113.10"}', 'ip_not_allowed'],
    'empty object as scopes' => ['scopes', '{}', 'insufficient_scope'],
    'numbered object as scopes' => ['scopes', '{"0":"items:read"}', 'insufficient_scope'],
    'string as ip allowlist' => ['ip_allowlist', '"203.0.113.10"', 'ip_not_allowed'],
]);

it('denies stored restrictions without version 1', function (string $stored): void {
    expect(authenticateWithStoredColumn('restrictions', $stored)[0])->toBe('request_not_allowed');
})->with(['{}', '[]', '{"request":{}}']);

it('still reads an empty JSON list as an open allowlist, and a version-1 object as restrictions', function (): void {
    expect(authenticateWithStoredColumn('ip_allowlist', '[]'))->toBe(['authenticated', []])
        ->and(authenticateWithStoredColumn('restrictions', '{"v":1}'))->toBe(['authenticated', []]);
});

it('denies stored restrictions whose nested shape is not recognised, and accepts an empty request object', function (): void {
    expect(authenticateWithStoredColumn('restrictions', '{"v":1,"request":[]}')[0])->toBe('request_not_allowed')
        ->and(authenticateWithStoredColumn('restrictions', '{"v":1,"request":{"methods":{}}}')[0])->toBe('request_not_allowed')
        ->and(authenticateWithStoredColumn('restrictions', '{"v":1,"resources":{}}')[0])->toBe('request_not_allowed')
        ->and(authenticateWithStoredColumn('restrictions', '{"v":1,"request":{}}'))->toBe(['authenticated', []]);
});

it('tells SQL NULL from a JSON null literal through an Eloquent model read as the contract asks', function (): void {
    Schema::create('api_keys', function (Blueprint $table): void {
        $table->id();
        $table->json('ip_allowlist')->nullable();
    });
    DB::table('api_keys')->insert([['ip_allowlist' => null], ['ip_allowlist' => 'null']]);
    $model = new class extends Model
    {
        protected $table = 'api_keys';

        protected function casts(): array
        {
            return ['ip_allowlist' => 'array'];
        }
    };
    [$sqlNull, $jsonNull] = $model->newQuery()->orderBy('id')->get()->all();

    // The cast reads both as PHP null; only the raw value tells them apart.
    expect($sqlNull->ip_allowlist)->toBeNull()
        ->and($jsonNull->ip_allowlist)->toBeNull()
        ->and(authenticateWithStoredColumn('ip_allowlist', $sqlNull->getRawOriginal('ip_allowlist')))->toBe(['authenticated', []]);

    [$outcome, $reported] = authenticateWithStoredColumn('ip_allowlist', $jsonNull->getRawOriginal('ip_allowlist'));

    expect($outcome)->toBe('ip_not_allowed')
        ->and($reported)->toHaveCount(1);
});

it('denies stored request list fields holding JSON null', function (string $field): void {
    expect(authenticateWithStoredColumn('restrictions', '{"v":1,"request":{"'.$field.'":null}}')[0])->toBe('request_not_allowed');
})->with(['methods', 'route_names', 'origins', 'referrers']);

it('names the required scope when the stored scopes are a JSON null literal', function (): void {
    $seed = authenticator();
    $fixture = authenticator([
        'defaultRate' => 0,
        'record' => new InMemoryApiKeyRecord(id: '42', keyPrefix: $seed['prefix'], keyHash: $seed['hash'], scopes: 'null'),
        'exceptionReporter' => function (Throwable $exception): void {},
    ]);

    try {
        $fixture['auth']->authenticate($fixture['token'], keyContext(), Scope::tryFromString('items:read'));
        $this->fail('expected insufficient_scope');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->render()->headers->get('WWW-Authenticate'))->toBe('Bearer error="insufficient_scope", scope="items:read"');
    }
});
