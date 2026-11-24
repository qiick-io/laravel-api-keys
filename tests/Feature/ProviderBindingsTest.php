<?php

declare(strict_types=1);

use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

mutates(ApiKeysServiceProvider::class);

function freshBinding(string $abstract): mixed
{
    app()->forgetInstance($abstract);

    return app($abstract);
}

it('picks the token environment from config, else from the app environment', function (mixed $configured, string $appEnvironment, TokenEnvironment $expected): void {
    config(['api-keys.environment' => $configured]);
    app()->detectEnvironment(fn () => $appEnvironment);

    expect(freshBinding(EnvironmentResolver::class)->environment())->toBe($expected);
})->with([
    'configured live' => ['live', 'local', TokenEnvironment::Live],
    'configured test' => ['test', 'production', TokenEnvironment::Test],
    'unset, production' => [null, 'production', TokenEnvironment::Live],
    'empty, production' => ['', 'production', TokenEnvironment::Live],
    'unset, local' => [null, 'local', TokenEnvironment::Test],
    'not a string, local' => [1, 'local', TokenEnvironment::Test],
]);

it('refuses a token environment other than live or test', function (): void {
    config(['api-keys.environment' => 'staging']);

    expect(fn () => freshBinding(EnvironmentResolver::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.environment must be "live" or "test" when set.');
});

it('refuses to build the codec without a product prefix', function (mixed $productPrefix): void {
    config(['api-keys.product_prefix' => $productPrefix]);

    expect(fn () => freshBinding(TokenCodec::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.product_prefix must be set to a three-letter product code before issuing tokens.');
})->with(['unset' => [null], 'empty' => [''], 'not a string' => [123]]);

it('issues the configured token version, 1 or 2 only', function (int $tokenVersion): void {
    config(['api-keys.token_version' => $tokenVersion]);

    expect(freshBinding(TokenCodec::class)->issue()->tokenVersion)->toBe($tokenVersion);
})->with([1, 2]);

it('refuses any other token version', function (mixed $tokenVersion): void {
    config(['api-keys.token_version' => $tokenVersion]);

    expect(fn () => freshBinding(TokenCodec::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.token_version must be 1 or 2.');
})->with(['zero' => [0], 'three' => [3], 'string' => ['2']]);

it('takes legacy matchers as class names or instances, skipping anything else', function (): void {
    $cutOff = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $otherMatcher = new RegexLegacyTokenMatcher('/^(?<prefix>zz_[A-Za-z0-9]{9})[A-Za-z0-9]{31}$/D', $cutOff);
    app()->bind(RegexLegacyTokenMatcher::class, fn () => RegexLegacyTokenMatcher::externaEkStyle($cutOff));
    config([
        'api-keys.legacy.accept_until' => '2099-01-01T00:00:00Z',
        // Junk first: a matcher list must skip it, never stop at it or keep it.
        'api-keys.legacy_matchers' => [new stdClass, 42, RegexLegacyTokenMatcher::class, $otherMatcher],
    ]);

    $codec = freshBinding(TokenCodec::class);
    $now = new DateTimeImmutable('2026-01-01T00:00:00Z');

    expect($codec->prefixOf('ek_ABCDEFGHI'.str_repeat('a', 31), $now))->toBe('ek_ABCDEFGHI')
        ->and($codec->prefixOf('zz_ABCDEFGHI'.str_repeat('a', 31), $now))->toBe('zz_ABCDEFGHI');
});

it('stops accepting legacy tokens at the configured cut-off, even when a matcher would go on', function (): void {
    app()->bind(RegexLegacyTokenMatcher::class, fn () => RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2099-01-01T00:00:00Z')));
    config([
        'api-keys.legacy.accept_until' => '2027-01-01T00:00:00Z',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
    ]);

    $codec = freshBinding(TokenCodec::class);
    $legacyToken = 'ek_ABCDEFGHI'.str_repeat('a', 31);

    expect($codec->prefixOf($legacyToken, new DateTimeImmutable('2026-12-31T23:59:59Z')))->toBe('ek_ABCDEFGHI')
        ->and($codec->prefixOf($legacyToken, new DateTimeImmutable('2027-01-01T00:00:00Z')))->toBeNull();
});

it('refuses a legacy matcher class that is not a LegacyTokenMatcher', function (): void {
    config([
        'api-keys.legacy.accept_until' => '2099-01-01T00:00:00Z',
        'api-keys.legacy_matchers' => [stdClass::class],
    ]);

    expect(fn () => freshBinding(TokenCodec::class))
        ->toThrow(InvalidArgumentException::class, 'api-keys.legacy_matchers entries must resolve to LegacyTokenMatcher instances.');
});

it('reads a legacy matcher list that is not an array as empty', function (): void {
    config(['api-keys.legacy_matchers' => 'not-a-list', 'api-keys.legacy.accept_until' => null]);

    expect(freshBinding(TokenCodec::class)->prefixOf('ek_ABCDEFGHI'.str_repeat('a', 31), new DateTimeImmutable))->toBeNull();
});
