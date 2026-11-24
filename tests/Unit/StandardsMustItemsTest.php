<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\ApiKeys\ApiKeyAuthenticator;
use Qiick\ApiKeys\CredentialKind;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\FailedAttemptLimiter;
use Qiick\ApiKeys\Http\KeyContextFactory;
use Qiick\ApiKeys\IpAllowlist;
use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\KeyRestrictions;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\RequestRestrictionsEvaluator;
use Qiick\ApiKeys\RevocationReason;
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
use Qiick\ApiKeys\TokenMatch;
use Qiick\ApiKeys\UsageRecorder;

mutates(KeyRestrictions::class);
mutates(RequestRestrictionsEvaluator::class);

function mustCodec(?int $tokenVersion = null): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('must-item-seed-for-deterministic-tests!!!'),
        defaultTokenVersion: $tokenVersion ?? TokenCodec::DEFAULT_TOKEN_VERSION,
    );
}

function mustAuth(InMemoryApiKeyRecord $record, string $token, ?FakeKeyAuthorizer $authorizer = null): ApiKeyAuthenticator
{
    return new ApiKeyAuthenticator(
        codec: mustCodec(),
        repository: new FakeApiKeyRepository([$record], new DateTimeImmutable('2026-01-15 12:00:00')),
        authorizer: $authorizer ?? new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: new FakeAttemptLimiter,
        defaultRateLimitPerMinute: 0,
    );
}

it('T3: issues token_version 2 with checksum by default and still accepts v1', function (): void {
    $codec = mustCodec();
    $v2 = $codec->issue();
    $v1 = $codec->issue(tokenVersion: 1);

    expect($v2->tokenVersion)->toBe(2)
        ->and(strlen($v2->plainText) - strlen($v2->keyPrefix))->toBe(38)
        ->and($codec->prefixOf($v2->plainText, new DateTimeImmutable('now')))->toBe($v2->keyPrefix)
        ->and($v1->tokenVersion)->toBe(1)
        ->and(strlen($v1->plainText) - strlen($v1->keyPrefix))->toBe(32)
        ->and($codec->prefixOf($v1->plainText, new DateTimeImmutable('now')))->toBe($v1->keyPrefix);

    $tampered = substr($v2->plainText, 0, -1).(substr($v2->plainText, -1) === 'A' ? 'B' : 'A');
    expect($codec->prefixOf($tampered, new DateTimeImmutable('now')))->toBeNull();
});

it('T1/T2: unknown token_version or hash_algorithm fail closed as invalid_token', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $badVersion = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withTokenVersion(99);
    $badAlgo = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withHashAlgorithm('md5');

    expect(fn () => mustAuth($badVersion, $issued->plainText)->authenticate($issued->plainText, new KeyContext('203.0.113.10')))
        ->toThrow(ApiKeyRejection::class)
        ->and(fn () => mustAuth($badAlgo, $issued->plainText)->authenticate($issued->plainText, new KeyContext('203.0.113.10')))
        ->toThrow(ApiKeyRejection::class);

    expect($codec->match(
        $issued->plainText,
        $issued->keyHash,
        null,
        null,
        new DateTimeImmutable('now'),
        'md5',
    ))->toBe(TokenMatch::None);
});

it('T5: ApiKeyRecord::publicId returns the UUID string', function (): void {
    $record = new InMemoryApiKeyRecord(publicId: '018f0000-0000-7000-8000-000000000099');

    expect($record->publicId())->toBe('018f0000-0000-7000-8000-000000000099');
});

it('F10: findCandidatesByPrefix matches previous_key_prefix inside the grace window', function (): void {
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $record = (new InMemoryApiKeyRecord(
        keyPrefix: 'tst_test_newprefix',
        keyHash: 'current',
    ))->withPrevious('oldhash', $now->modify('+1 hour'), 'tst_test_oldprefix');
    $repository = new FakeApiKeyRepository([$record], $now);

    expect($repository->findCandidatesByPrefix('tst_test_oldprefix'))->toHaveCount(1)
        ->and($repository->findCandidatesByPrefix('tst_test_missing'))->toHaveCount(0);

    $expired = (new InMemoryApiKeyRecord(
        keyPrefix: 'tst_test_newprefix2',
        keyHash: 'current',
    ))->withPrevious('oldhash', $now->modify('-1 hour'), 'tst_test_expired');
    $expiredRepo = new FakeApiKeyRepository([$expired], $now);

    expect($expiredRepo->findCandidatesByPrefix('tst_test_expired'))->toHaveCount(0);
});

it('O2: refuses oauth_grant rows as invalid_token even when the hash matches', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $grant = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withCredentialKind(CredentialKind::OauthGrant);

    try {
        mustAuth($grant, $issued->plainText)->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
        test()->fail('expected rejection');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('invalid_token')
            ->and($rejection->getStatusCode())->toBe(401);
    }
});

it('C1: package no longer empties scopes for ownerless keys; FakeKeyAuthorizer stays fail-closed', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $ownerless = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withOwnerIdentifier(null)->withCreatedByIdentifier(null);

    try {
        mustAuth($ownerless, $issued->plainText)->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
        test()->fail('expected insufficient_scope from fail-closed fake');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('insufficient_scope');
    }

    $allowed = mustAuth(
        $ownerless,
        $issued->plainText,
        (new FakeKeyAuthorizer)->allowingOwnerlessCeiling(),
    )->authenticate($issued->plainText, new KeyContext('203.0.113.10'));

    expect($allowed->record->publicId())->not->toBe('');
});

it('L5/L6: malformed restrictions and request denials yield 403 request_not_allowed', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $malformed = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withRestrictions(['v' => 99]);

    try {
        mustAuth($malformed, $issued->plainText)->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
        test()->fail('expected request_not_allowed');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('request_not_allowed')
            ->and($rejection->getStatusCode())->toBe(403)
            ->and($rejection->render()->headers->get('WWW-Authenticate'))->toBeNull();
    }

    $restricted = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withRestrictions([
        'v' => 1,
        'request' => ['methods' => ['POST']],
    ]);

    try {
        mustAuth($restricted, $issued->plainText)->authenticate(
            $issued->plainText,
            new KeyContext(ip: '203.0.113.10', method: 'GET'),
        );
        test()->fail('expected method denial');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('request_not_allowed');
    }
});

it('L1/L2: day and month buckets are enforced and rateLimit returns a list', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $record = (new InMemoryApiKeyRecord(
        id: 'quota-1',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withRateLimitPerDay(1)->withRateLimitPerMonth(1);
    $limiter = new FakeAttemptLimiter;
    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: new FakeApiKeyRepository([$record]),
        authorizer: new FakeKeyAuthorizer,
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: $limiter,
        defaultRateLimitPerMinute: 0,
    );

    $auth->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
    expect($limiter->hitsFor('api-key:quota-1:day'))->toBe(1)
        ->and($limiter->hitsFor('api-key:quota-1:month'))->toBe(1)
        ->and($limiter->lastDecaySeconds)->toBe([
            'api-key:quota-1:day' => 86_400,
            'api-key:quota-1:month' => 2_592_000,
        ]);

    $authorizer = (new FakeKeyAuthorizer)->withRateLimits([
        new RateLimitDecision('custom:bucket', 1, 60),
    ]);
    expect($authorizer->rateLimit($record, new KeyContext('203.0.113.10')))->toHaveCount(1);
});

it('F3/F4: revocation attribution and last_used_user_agent are on the record contract', function (): void {
    $record = (new InMemoryApiKeyRecord)
        ->withRevocation(
            new DateTimeImmutable('2026-01-01'),
            7,
            RevocationReason::Exposure,
            'scanner hit',
        )
        ->withLastUsed(new DateTimeImmutable('2026-01-02'), '203.0.113.10', 'PestAgent/1.0')
        ->withMetadata(['labels' => ['env' => 'test']]);

    expect($record->revokedByIdentifier())->toBe(7)
        ->and($record->revokedReason())->toBe(RevocationReason::Exposure)
        ->and($record->revocationNote())->toBe('scanner hit')
        ->and($record->lastUsedUserAgent())->toBe('PestAgent/1.0')
        ->and($record->metadata()['labels']['env'])->toBe('test');

    $repository = new FakeApiKeyRepository;
    $repository->recordUsage($record, '203.0.113.10', str_repeat('a', 600), new DateTimeImmutable('now'));

    expect(strlen((string) $repository->recordedUsages[0]['userAgent']))->toBe(512);
});

it('KeyContextFactory fills method, route, origin and referer from a real request', function (): void {
    $request = Request::create('https://api.example.com/posts', 'POST', server: [
        'HTTP_ORIGIN' => 'https://app.example.com',
        'HTTP_REFERER' => 'https://app.example.com/edit',
        'HTTP_USER_AGENT' => 'FactoryTest/1.0',
    ]);

    $context = KeyContextFactory::fromRequest($request);

    expect($context->method)->toBe('POST')
        ->and($context->origin)->toBe('https://app.example.com')
        ->and($context->referer)->toBe('https://app.example.com/edit')
        ->and($context->userAgent)->toBe('FactoryTest/1.0');
});

it('L5: KeyRestrictions parses version 1 and denies unknown keys', function (): void {
    $ok = KeyRestrictions::parse([
        'v' => 1,
        'request' => [
            'methods' => ['GET'],
            'route_names' => ['api.v1.posts.*'],
            'origins' => ['https://app.example.com'],
            'referrers' => ['https://app.example.com/*'],
        ],
        'resources' => [
            ['type' => 'collection', 'values' => ['news'], 'mode' => 'allow'],
        ],
    ]);

    expect($ok->isDenied)->toBeFalse()
        ->and($ok->request->methods)->toBe(['GET'])
        ->and($ok->resources->entries)->toHaveCount(1)
        ->and(KeyRestrictions::parse(['v' => 1, 'extra' => true])->isDenied)->toBeTrue()
        ->and(KeyRestrictions::parse(null)->request->isUnrestricted())->toBeTrue();
});

it('L7: product resource denial is 403 request_not_allowed', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $record = (new InMemoryApiKeyRecord(
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    ))->withRestrictions([
        'v' => 1,
        'resources' => [
            ['type' => 'collection', 'values' => ['news'], 'mode' => 'allow'],
        ],
    ]);

    try {
        mustAuth($record, $issued->plainText, (new FakeKeyAuthorizer)->denyResources())
            ->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
        test()->fail('expected resource denial');
    } catch (ApiKeyRejection $rejection) {
        expect($rejection->errorCode())->toBe('request_not_allowed');
    }
});

it('O2/T1/T2: oauth, unknown version and unknown algorithm each hit the failed-attempt brake', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $limiter = new FakeAttemptLimiter;
    $failed = new FailedAttemptLimiter($limiter, maxPerMinute: 20);

    $cases = [
        (new InMemoryApiKeyRecord(keyPrefix: $issued->keyPrefix, keyHash: $issued->keyHash, scopes: ['items:read']))
            ->withCredentialKind(CredentialKind::OauthGrant),
        (new InMemoryApiKeyRecord(keyPrefix: $issued->keyPrefix, keyHash: $issued->keyHash, scopes: ['items:read']))
            ->withTokenVersion(99),
        (new InMemoryApiKeyRecord(keyPrefix: $issued->keyPrefix, keyHash: $issued->keyHash, scopes: ['items:read']))
            ->withHashAlgorithm('md5'),
    ];

    foreach ($cases as $index => $record) {
        $auth = new ApiKeyAuthenticator(
            codec: $codec,
            repository: new FakeApiKeyRepository([$record]),
            authorizer: new FakeKeyAuthorizer,
            vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write']),
            ipAllowlist: new IpAllowlist,
            usageRecorder: new UsageRecorder,
            clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
            attemptLimiter: new FakeAttemptLimiter,
            failedAttemptLimiter: $failed,
            defaultRateLimitPerMinute: 0,
        );

        try {
            $auth->authenticate($issued->plainText, new KeyContext('203.0.113.10'));
            test()->fail('expected invalid_token for case '.$index);
        } catch (ApiKeyRejection $rejection) {
            expect($rejection->errorCode())->toBe('invalid_token');
        }

        expect($limiter->hitsFor('api-key-failures:v4:203.0.113.10'))->toBe($index + 1);
    }
});

it('N1: a zero maxAttempts bucket is skipped so later buckets still run', function (): void {
    $codec = mustCodec();
    $issued = $codec->issue();
    $record = new InMemoryApiKeyRecord(
        id: 'skip-zero',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    );
    $limiter = new FakeAttemptLimiter;
    $auth = new ApiKeyAuthenticator(
        codec: $codec,
        repository: new FakeApiKeyRepository([$record]),
        authorizer: (new FakeKeyAuthorizer)->withRateLimits([
            new RateLimitDecision('zero-bucket', 0, 60),
            new RateLimitDecision('live-bucket', 5, 60),
        ]),
        vocabulary: new ArrayScopeVocabulary(['items:read', 'items:write']),
        ipAllowlist: new IpAllowlist,
        usageRecorder: new UsageRecorder,
        clock: new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        attemptLimiter: $limiter,
        defaultRateLimitPerMinute: 0,
    );

    $auth->authenticate($issued->plainText, new KeyContext('203.0.113.10'));

    expect($limiter->hitsFor('zero-bucket'))->toBe(0)
        ->and($limiter->hitsFor('live-bucket'))->toBe(1);
});
