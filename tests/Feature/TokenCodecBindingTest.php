<?php

declare(strict_types=1);

use Qiick\ApiKeys\Contracts\Clock;
use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\RandomSource;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

mutates(ApiKeysServiceProvider::class);

it('binds clock, environment, random source and token codec', function (): void {
    expect(app(Clock::class))->toBeInstanceOf(Clock::class)
        ->and(app(EnvironmentResolver::class)->environment())->toBe(TokenEnvironment::Test)
        ->and(app(RandomSource::class))->toBeInstanceOf(RandomSource::class);

    $codec = app(TokenCodec::class);
    $token = $codec->issue();

    expect($token->keyPrefix)->toStartWith('tst_test_');
});

it('fails boot of the codec when legacy matchers lack accept_until', function (): void {
    config([
        'api-keys.legacy_matchers' => [stdClass::class],
        'api-keys.legacy.accept_until' => null,
    ]);

    app()->forgetInstance(TokenCodec::class);

    expect(fn () => app(TokenCodec::class))->toThrow(RuntimeException::class);
});
