<?php

declare(strict_types=1);

/**
 * Real-store proof of CacheAttemptLimiter across processes, on Redis, Memcached
 * and Laravel's database cache store (sqlite, mysql, mariadb, pgsql).
 *
 * Runs only in the CI databases smoke job (API_KEYS_LIMITER_STORE=<store>)
 * or locally against a reachable server; every worker is a separate PHP
 * process started at the same instant, like parallel PHP-FPM workers.
 */
function limiterStoreUnderTest(): ?string
{
    $store = getenv('API_KEYS_LIMITER_STORE');

    // "both" is the in-process mutation job; the races run once per store in the smoke matrix.
    return in_array($store, ['redis', 'memcached', 'sqlite', 'mysql', 'mariadb', 'pgsql'], true) ? $store : null;
}

/**
 * Starts every operation in its own process at the same instant and returns
 * each process's output.
 *
 * @param  list<array{0: string, 1: string}>  $operations  [operation, ip-or-key]
 * @return list<string>
 */
function raceLimiterWorkers(array $operations, int $maxAttempts): array
{
    // Enough lead for every process to boot before the common start instant.
    $startAt = sprintf('%.6F', microtime(true) + 0.5 + 0.05 * count($operations));
    $processes = [];

    foreach ($operations as [$operation, $target]) {
        $command = [PHP_BINARY, __DIR__.'/../Support/attempt-limiter-worker.php', (string) limiterStoreUnderTest(), $operation, $target, (string) $maxAttempts, $startAt];
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $processes[] = [$process, $pipes];
    }

    $outputs = [];

    foreach ($processes as [$process, $pipes]) {
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        proc_close($process);

        expect($errors)->toBe('');
        $outputs[] = trim((string) $output);
    }

    return $outputs;
}

function limiterWorker(string $operation, string $target): string
{
    return raceLimiterWorkers([[$operation, $target]], 0)[0];
}

beforeEach(function (): void {
    if (limiterStoreUnderTest() === null) {
        $this->markTestSkipped('Set API_KEYS_LIMITER_STORE=redis|memcached|sqlite|mysql|mariadb|pgsql to race a real store.');
    }

    if (! in_array(limiterStoreUnderTest(), ['redis', 'memcached'], true)) {
        limiterWorker('setup', 'cache');
    }

    limiterWorker('forget', 'api-key-failures:v4:203.0.113.10');
    limiterWorker('forget', 'race:key');
});

/**
 * How many of the racing operations were admitted.
 *
 * @param  list<array{0: string, 1: string}>  $operations
 */
function admittedRacers(array $operations, int $maxAttempts): int
{
    return array_sum(array_map(intval(...), raceLimiterWorkers($operations, $maxAttempts)));
}

/*
 * Laravel's RateLimiter resets a counter with put() when a window opens, so the
 * increments that land in that instant can be lost and a burst can admit a few
 * more than the limit (accepted in docs/security.md). The bounds below hold
 * whatever the timing: at least the limit, less than twice the limit, at most one
 * such reset per window (a second burst admits nothing), and the next attempt
 * after the burst is refused.
 */
it('admits the limit, give or take the accepted window-start race, when 50 guesses from one IP race', function (): void {
    $admitted = admittedRacers(array_fill(0, 50, ['guess', '203.0.113.10']), 10);

    expect($admitted)->toBeGreaterThanOrEqual(10)->toBeLessThan(20)
        ->and(admittedRacers(array_fill(0, 50, ['guess', '203.0.113.10']), 10))->toBe(0)
        ->and(raceLimiterWorkers([['guess', '203.0.113.10']], 10)[0])->toBe('0')
        ->and((int) limiterWorker('count', 'api-key-failures:v4:203.0.113.10'))->toBeGreaterThanOrEqual(10);
});

it('caps visible guesses when valid requests from the same IP race them', function (): void {
    $operations = [];

    foreach (range(1, 60) as $index) {
        $operations[] = ['request', '203.0.113.10'];
        $operations[] = ['guess', '203.0.113.10'];
    }

    $outcomes = raceLimiterWorkers($operations, 10);
    $admittedGuesses = 0;

    foreach ($operations as $index => [$operation]) {
        if ($operation === 'guess') {
            $admittedGuesses += (int) $outcomes[$index];
        }
    }

    expect($admittedGuesses)->toBeGreaterThan(0)->toBeLessThan(20)
        ->and(raceLimiterWorkers([['guess', '203.0.113.10']], 10)[0])->toBe('0')
        ->and((int) limiterWorker('count', 'api-key-failures:v4:203.0.113.10'))->toBeGreaterThanOrEqual(10);
});

it('admits every valid request from one IP however many are verified at once', function (): void {
    $outcomes = raceLimiterWorkers(array_fill(0, 30, ['slow-request', '203.0.113.10']), 20);

    expect(array_sum(array_map(intval(...), $outcomes)))->toBe(30);
});

it('admits the limit, give or take the accepted window-start race, on a per-key bucket', function (): void {
    $admitted = admittedRacers(array_fill(0, 50, ['hit', 'race:key']), 10);

    expect($admitted)->toBeGreaterThanOrEqual(10)->toBeLessThan(20)
        ->and(admittedRacers(array_fill(0, 50, ['hit', 'race:key']), 10))->toBe(0)
        ->and(raceLimiterWorkers([['hit', 'race:key']], 10)[0])->toBe('0')
        ->and((int) limiterWorker('count', 'race:key'))->toBeGreaterThanOrEqual(10);
});

it('ignores a decrement that arrives after the window expired', function (): void {
    expect(limiterWorker('hit-short', 'race:key'))->toBe('1');

    usleep(2_100_000);

    limiterWorker('decrement', 'race:key');
    limiterWorker('decrement', 'race:key');

    expect(limiterWorker('count', 'race:key'))->toBe('missing')
        ->and(limiterWorker('hit-short', 'race:key'))->toBe('1');
});
