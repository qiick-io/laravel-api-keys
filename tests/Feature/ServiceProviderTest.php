<?php

declare(strict_types=1);

it('merges the package defaults into the api-keys config', function (): void {
    expect(config('api-keys'))->toMatchArray([
        'product_prefix' => 'tst',
        'environment' => null,
        'rotation_grace_hours' => 24,
        'usage_throttle_seconds' => 60,
        'usage_bypass_throttle_on_ip_change' => true,
        'default_rate_limit_per_minute' => 60,
        'failed_attempts_per_minute' => 20,
        'legacy_matchers' => [],
    ]);

    expect(config('api-keys.legacy.accept_until'))->toBeNull();
});

it('lets an app publish the config file', function (): void {
    $this->artisan('vendor:publish', ['--tag' => 'api-keys-config', '--force' => true])
        ->assertSuccessful();

    expect(config_path('api-keys.php'))->toBeFile();

    unlink(config_path('api-keys.php'));
});
