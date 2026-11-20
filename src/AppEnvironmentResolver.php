<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\EnvironmentResolver;

/**
 * @api Maps the Laravel app environment to live/test.
 *
 * `production` → live; everything else → test. An explicit `api-keys.environment`
 * config value overrides this when the service provider builds the codec.
 */
final class AppEnvironmentResolver implements EnvironmentResolver
{
    public function __construct(private bool $isProduction) {}

    public function environment(): TokenEnvironment
    {
        return $this->isProduction ? TokenEnvironment::Live : TokenEnvironment::Test;
    }
}
