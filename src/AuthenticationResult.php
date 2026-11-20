<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;

/**
 * @api Successful authentication outcome.
 */
final readonly class AuthenticationResult
{
    public function __construct(
        public ApiKeyRecord $record,
        public ScopeSet $grantedScopes,
        public bool $usedPreviousSecret,
    ) {}
}
