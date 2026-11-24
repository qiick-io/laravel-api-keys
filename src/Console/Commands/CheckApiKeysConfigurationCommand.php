<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Console\Command;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;

/**
 * @api Deploy-time check: `php artisan api-keys:check` fails (exit 1) when the
 * package cannot work as configured.
 *
 * It re-validates the settings and resolves the bound {@see AttemptLimiter},
 * which throws on a cache store that cannot count atomically (Laravel's
 * default `database` store among them). Boot deliberately skips that store
 * check so artisan keeps working; run this command in the deploy pipeline.
 */
final class CheckApiKeysConfigurationCommand extends Command
{
    protected $signature = 'api-keys:check';

    protected $description = 'Check that the API keys package can run with this configuration';

    public function handle(): int
    {
        try {
            // This provider registers the command, so it is always loaded here.
            /** @var ApiKeysServiceProvider $provider */
            $provider = $this->laravel->getProvider(ApiKeysServiceProvider::class);
            $provider->validateConfiguration();

            $this->laravel->make(AttemptLimiter::class);
        } catch (\InvalidArgumentException|\RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('API keys configuration is ready.');

        return self::SUCCESS;
    }
}
