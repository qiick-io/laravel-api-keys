<?php

declare(strict_types=1);

/**
 * Real-store proof that CacheAttemptLimiter is atomic across processes.
 *
 * Runs only in the CI databases smoke job (API_KEYS_LIMITER_STORE=redis|memcached)
 * or locally against a reachable server; every worker is a separate PHP
 * process started at the same instant, like parallel PHP-FPM workers.
 */
function limiterStoreUnderTest(): ?string
{
    $store = getenv('API_KEYS_LIMITER_STORE');

    return is_string($store) && $store !== '' ? $store : null;
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
        $this->markTestSkipped('Set API_KEYS_LIMITER_STORE=redis|memcached to race a real store.');
    }

    limiterWorker('forget', 'api-key-failures:v4:203.0.113.10');
    limiterWorker('forget', 'race:key');
});

it('admits exactly the limit when 50 guesses from one IP race', function (): void {
    $outcomes = raceLimiterWorkers(array_fill(0, 50, ['guess', '203.0.113.10']), 10);

    expect(array_sum(array_map(intval(...), $outcomes)))->toBe(10)
        ->and(limiterWorker('count', 'api-key-failures:v4:203.0.113.10'))->toBe('10');
});

it('caps guesses and never goes negative when valid requests from the same IP race them', function (): void {
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

    expect($admittedGuesses)->toBeLessThanOrEqual(10)
        ->and($admittedGuesses)->toBeGreaterThan(0)
        ->and(limiterWorker('count', 'api-key-failures:v4:203.0.113.10'))->toBe((string) $admittedGuesses);
});

it('admits exactly the limit on a per-key bucket and leaves the counter at the limit', function (): void {
    $outcomes = raceLimiterWorkers(array_fill(0, 50, ['hit', 'race:key']), 10);

    expect(array_sum(array_map(intval(...), $outcomes)))->toBe(10)
        ->and(limiterWorker('count', 'race:key'))->toBe('10');
});

it('ignores a decrement that arrives after the window expired', function (): void {
    expect(limiterWorker('hit-short', 'race:key'))->toBe('1');

    usleep(2_100_000);

    limiterWorker('decrement', 'race:key');
    limiterWorker('decrement', 'race:key');

    expect(limiterWorker('count', 'race:key'))->toBe('missing')
        ->and(limiterWorker('hit-short', 'race:key'))->toBe('1');
});
