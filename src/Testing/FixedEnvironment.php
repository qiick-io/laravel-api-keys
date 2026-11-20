<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\TokenEnvironment;

/** @api Test environment resolver with a fixed live/test value. */
final class FixedEnvironment implements EnvironmentResolver
{
    public function __construct(private TokenEnvironment $environment) {}

    public function environment(): TokenEnvironment
    {
        return $this->environment;
    }
}
