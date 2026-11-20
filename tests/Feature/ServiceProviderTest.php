<?php

declare(strict_types=1);

use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;

it('merges the package defaults into the api-keys config', function (): void {
    expect(config('api-keys'))->toMatchArray([
        'product_prefix' => 'tst',
        'environment' => null,
        'rotation_grace_hours' => 24,
        'rotation_max_grace_hours' => 168,
        'usage_throttle_seconds' => 60,
        'usage_bypass_throttle_on_ip_change' => true,
        'default_rate_limit_per_minute' => 60,
        'failed_attempts_per_minute' => 20,
        'legacy_matchers' => [],
    ]);

    expect(config('api-keys.legacy.accept_until'))->toBeNull();
});

it('binds RotationService with config rotation_max_grace_hours', function (): void {
    config(['api-keys.rotation_max_grace_hours' => 48]);

    $service = app(RotationService::class);

    expect($service)->toBeInstanceOf(RotationService::class)
        ->and($service->maxGraceHours())->toBe(48)
        ->and(app(RotationService::class))->toBe($service);
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'api-keys-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('api-keys.php'))->toBeFile();

    unlink(config_path('api-keys.php'));
});

it('fails boot when legacy_matchers is set without API_KEYS_LEGACY_ACCEPT_UNTIL', function (): void {
    config([
        'api-keys.product_prefix' => 'tst',
        'api-keys.legacy_matchers' => [RegexLegacyTokenMatcher::class],
        'api-keys.legacy.accept_until' => null,
    ]);

    app()->forgetInstance(TokenCodec::class);

    expect(fn () => app(TokenCodec::class))
        ->toThrow(RuntimeException::class, 'API_KEYS_LEGACY_ACCEPT_UNTIL');
});
