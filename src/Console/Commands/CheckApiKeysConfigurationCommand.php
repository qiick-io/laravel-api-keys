<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Console\Command;
use Qiick\ApiKeys\CacheAttemptLimiter;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\DatabaseAttemptLimiter;
use Qiick\ApiKeys\Laravel\ApiKeysServiceProvider;
use Qiick\ApiKeys\TokenCodec;

/**
 * @api Deploy-time check: `php artisan api-keys:check` fails (exit 1) when the
 * package cannot work as configured.
 *
 * It re-validates the settings, checks that `app.timezone` is UTC, builds the
 * {@see TokenCodec} (product prefix, token version, environment), and resolves the bound {@see AttemptLimiter}
 * and prints which one is active. The cache limiter throws on a store that
 * cannot count atomically; the database limiter fails when its table is
 * missing. Boot deliberately skips both checks so artisan keeps working; run
 * this command in the deploy pipeline.
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

            $this->line('Attempt limiter: '.$this->describeAttemptLimiter($this->laravel->make(AttemptLimiter::class)));
            // Builds the environment resolver too: product prefix, token version and environment.
            $this->laravel->make(TokenCodec::class);

            // Expiry, grace and lease comparisons assume UTC timestamps (RFC 3339 on the wire).
            if (config('app.timezone') !== 'UTC') {
                throw new \RuntimeException('app.timezone must be UTC: API key timestamps are stored and compared in UTC.');
            }
        } catch (\InvalidArgumentException|\RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('API keys configuration is ready.');

        return self::SUCCESS;
    }

    /**
     * @throws \RuntimeException when the database limiter's table is missing
     */
    private function describeAttemptLimiter(AttemptLimiter $limiter): string
    {
        if ($limiter instanceof DatabaseAttemptLimiter) {
            if (! $limiter->hasTable()) {
                throw new \RuntimeException("The {$limiter->table()} table is missing: create it as docs/reference-schema.md describes.");
            }

            return "database (table {$limiter->table()}).";
        }

        if ($limiter instanceof CacheAttemptLimiter) {
            return 'cache ('.config()->string('cache.default').' store).';
        }

        return $limiter::class.' (bound by the application).';
    }
}
