<?php

declare(strict_types=1);

use Qiick\ApiKeys\ApiKeyAuthenticator;
use Qiick\ApiKeys\AuthorizationDecision;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\UsageSideEffect;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\IpAllowlist;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\Testing\ArrayScopeVocabulary;
use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;
use Qiick\ApiKeys\Testing\FakeKeyAuthorizer;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;
use Qiick\ApiKeys\UsageRecorder;

mutates(ApiKeyAuthenticator::class);
mutates(AuthorizationDecision::class);

function makeCodec(): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-api-key-tests!!'),
    );
}

/**
 * @param  array{
 *     repository?: FakeApiKeyRepository,
 *     authorizer?: FakeKeyAuthorizer,
 *     limiter?: FakeAttemptLimiter,
 *     clock?: FixedClock,
 *     throttle?: int,
 *     bypassIp?: bool,
 *     defaultRate?: int,
 *     record?: InMemoryApiKeyRecord,
 *     token?: string,
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
 * }
 */
function authenticator(array $overrides = []): array
{
    $codec = makeCodec();
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

    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: $repository,
        authorizer: $authorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write', 'files:read']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: $clock,
        attemptLimiter: $limiter,
        usageThrottleSeconds: $overrides['throttle'] ?? 60,
        bypassThrottleOnIpChange: $overrides['bypassIp'] ?? true,
        defaultRateLimitPerMinute: $overrides['defaultRate'] ?? 60,
    );

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
        ->and($result->grantedScopes->allows(Scope::tryFromString('items:read')))->toBeTrue()
        ->and($repository->recordedUsages)->toHaveCount(1)
        ->and($limiter->hitsFor('api-key:42'))->toBe(1)
        ->and($sideEffect->wasFirstUse)->toBeTrue();
});

it('accepts the previous secret inside the grace window', function (): void {
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

it('rejects with invalid_token when the prefix has no candidates', function (): void {
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
