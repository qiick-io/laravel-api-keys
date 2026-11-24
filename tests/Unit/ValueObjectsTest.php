<?php

declare(strict_types=1);

use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\GeneratedToken;
use Qiick\ApiKeys\ParsedToken;
use Qiick\ApiKeys\RandomBytesSource;
use Qiick\ApiKeys\RateLimitDecision;
use Qiick\ApiKeys\Rotation;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

mutates(GeneratedToken::class);
mutates(ParsedToken::class);
mutates(Rotation::class);
mutates(RateLimitDecision::class);
mutates(RandomBytesSource::class);
mutates(ConfigLifetimePolicy::class);

it('issues the default token version unless told otherwise', function (): void {
    expect((new GeneratedToken('plain', 'prefix', 'hash'))->tokenVersion)->toBe(TokenCodec::DEFAULT_TOKEN_VERSION);
});

it('shows a parsed token without its secret', function (): void {
    $parsed = new ParsedToken('tst', TokenEnvironment::Live, 'ABCDEFGH', 'the-secret', 'tst_live_ABCDEFGH');

    expect($parsed->__debugInfo())->toBe([
        'productPrefix' => 'tst',
        'environment' => 'live',
        'publicId' => 'ABCDEFGH',
        'secret' => '[REDACTED]',
        'keyPrefix' => 'tst_live_ABCDEFGH',
    ]);
});

it('shows a rotation without its secrets, with or without a grace window', function (): void {
    $rotatedAt = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $withGrace = new Rotation('new-plain', 'tst_live_NEWPREFX', 'new-hash', 'old-hash', $rotatedAt->modify('+1 day'), $rotatedAt, 2, 'ek_OLDPREFIX');
    $withoutGrace = new Rotation('new-plain', 'tst_live_NEWPREFX', 'new-hash', null, null, $rotatedAt);

    expect($withGrace->__debugInfo())->toBe([
        'newKeyPrefix' => 'tst_live_NEWPREFX',
        'newKeyHash' => '[REDACTED]',
        'previousKeyHash' => '[REDACTED]',
        'previousKeyValidUntil' => '2026-01-16T12:00:00+00:00',
        'previousKeyPrefix' => 'ek_OLDPREFIX',
        'lastRotatedAt' => '2026-01-15T12:00:00+00:00',
        'tokenVersion' => 2,
        'newPlainText' => '[REDACTED]',
    ])
        ->and($withGrace->jsonSerialize())->toBe($withGrace->__debugInfo())
        ->and($withoutGrace->__debugInfo())->toMatchArray([
            'previousKeyHash' => null,
            'previousKeyValidUntil' => null,
            'previousKeyPrefix' => null,
            'tokenVersion' => TokenCodec::DEFAULT_TOKEN_VERSION,
        ]);
});

it('keeps a 60-second window by default and accepts a one-second window', function (): void {
    expect((new RateLimitDecision('bucket', 5))->decaySeconds)->toBe(60)
        ->and((new RateLimitDecision('bucket', 5, 1))->decaySeconds)->toBe(1);
});

it('draws the requested number of random bytes, at least one', function (): void {
    $source = new RandomBytesSource;

    expect(strlen($source->bytes(1)))->toBe(1)
        ->and(strlen($source->bytes(32)))->toBe(32)
        ->and(fn () => $source->bytes(0))->toThrow(InvalidArgumentException::class, 'Random byte length must be at least 1.');
});

it('allows any expiry when the lifetime policy is off', function (?int $maxLifetimeDays): void {
    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $policy = new ConfigLifetimePolicy($maxLifetimeDays);

    expect($policy->allowsExpiry(null, $now))->toBeTrue()
        ->and($policy->allowsExpiry($now->modify('+10 years'), $now))->toBeTrue();
})->with(['unset' => [null], 'zero' => [0], 'negative' => [-1]]);

it('requires an expiry within the window when the lifetime policy is on', function (): void {
    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $policy = new ConfigLifetimePolicy(1);

    expect($policy->allowsExpiry(null, $now))->toBeFalse()
        ->and($policy->allowsExpiry($now->modify('+1 day'), $now))->toBeTrue()
        ->and($policy->allowsExpiry($now->modify('+1 day +1 second'), $now))->toBeFalse();
});
