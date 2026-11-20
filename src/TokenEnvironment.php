<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Live vs test segment embedded in issued tokens.
 */
enum TokenEnvironment: string
{
    case Live = 'live';
    case Test = 'test';
}
