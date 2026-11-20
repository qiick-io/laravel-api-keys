<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\TokenEnvironment;

/**
 * @api Resolves live vs test for issuance (tests inject FixedEnvironment).
 */
interface EnvironmentResolver
{
    public function environment(): TokenEnvironment;
}
