<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;

/**
 * @api Successful authentication outcome.
 *
 * When `$legacyMatcherClass` is non-null the presented token matched a legacy
 * matcher — products should dispatch {@see Events\LegacyTokenUsed} only then
 * (never on format/hash miss).
 */
final readonly class AuthenticationResult
{
    /**
     * @param  class-string|null  $legacyMatcherClass
     */
    public function __construct(
        public ApiKeyRecord $record,
        public ScopeSet $grantedScopes,
        public bool $usedPreviousSecret,
        public ?string $legacyMatcherClass = null,
    ) {}
}
