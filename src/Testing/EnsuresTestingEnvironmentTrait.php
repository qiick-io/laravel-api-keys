<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

/**
 * @internal Fakes stay autoloadable (like Laravel's) but refuse construction outside tests.
 *
 * Allowed when `app()->environment('testing')` or `QIICK_API_KEYS_ALLOW_FAKES=1`.
 */
trait EnsuresTestingEnvironmentTrait
{
    private static function ensureTestingEnvironment(): void
    {
        if (self::isTestingEnvironmentAllowed()) {
            return;
        }

        throw new \RuntimeException(
            'Qiick API key test doubles may only be constructed in the testing environment (or with QIICK_API_KEYS_ALLOW_FAKES=1).',
        );
    }

    private static function isTestingEnvironmentAllowed(): bool
    {
        $flag = getenv('QIICK_API_KEYS_ALLOW_FAKES');

        if ($flag === '1' || $flag === 'true') {
            return true;
        }

        if (! function_exists('app')) {
            return false;
        }

        try {
            $application = app();
        } catch (\Throwable) {
            return false;
        }

        return $application->environment('testing');
    }
}
