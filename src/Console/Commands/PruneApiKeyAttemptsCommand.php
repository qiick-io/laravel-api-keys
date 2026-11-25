<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Console\Commands;

use Illuminate\Console\Command;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\DatabaseAttemptLimiter;

/**
 * @api `php artisan api-keys:prune-attempts` deletes the attempt windows that
 * have ended from the table of the bound {@see DatabaseAttemptLimiter}.
 *
 * Stale rows already count as empty, so pruning only keeps the table small.
 * Products that use the database limiter schedule it (hourly is plenty).
 */
final class PruneApiKeyAttemptsCommand extends Command
{
    protected $signature = 'api-keys:prune-attempts';

    protected $description = 'Delete ended attempt windows from the API key attempt table';

    public function handle(AttemptLimiter $limiter): int
    {
        // The bound limiter, so a product's own connection or table is the one pruned.
        if (! $limiter instanceof DatabaseAttemptLimiter) {
            $this->info('The attempt limiter does not use the database: nothing to prune.');

            return self::SUCCESS;
        }

        try {
            $pruned = $limiter->prune();
        } catch (\RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info("Pruned {$pruned} ended attempt windows.");

        return self::SUCCESS;
    }
}
