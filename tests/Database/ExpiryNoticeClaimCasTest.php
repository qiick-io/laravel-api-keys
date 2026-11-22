<?php

declare(strict_types=1);

use Qiick\ApiKeys\ExpiryNoticeClaimSql;

/**
 * Engine-level proof that ExpiryNoticeClaimSql::claim() is affected-row CAS.
 *
 * Default engine is sqlite (in-memory). CI databases smoke sets
 * API_KEYS_CLAIM_ENGINE=mysql|mariadb|pgsql with a reachable PDO DSN.
 */
function expiryNoticeClaimEngine(): string
{
    $engine = getenv('API_KEYS_CLAIM_ENGINE');

    if (! is_string($engine) || $engine === '') {
        return 'sqlite';
    }

    return strtolower($engine);
}

/**
 * @return array{0: PDO, 1: string}
 */
function expiryNoticeClaimPdo(): array
{
    $engine = expiryNoticeClaimEngine();

    return match ($engine) {
        'sqlite' => [
            new PDO('sqlite::memory:', options: [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ]),
            ExpiryNoticeClaimSql::createTableSqlite(),
        ],
        'mysql' => [
            new PDO(
                getenv('API_KEYS_CLAIM_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=api_keys_claim',
                getenv('API_KEYS_CLAIM_USER') ?: 'root',
                getenv('API_KEYS_CLAIM_PASSWORD') !== false
                    ? (string) getenv('API_KEYS_CLAIM_PASSWORD')
                    : 'password',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            ),
            ExpiryNoticeClaimSql::createTableMysql(),
        ],
        'mariadb' => [
            new PDO(
                getenv('API_KEYS_CLAIM_DSN') ?: 'mysql:host=127.0.0.1;port=3307;dbname=api_keys_claim',
                getenv('API_KEYS_CLAIM_USER') ?: 'root',
                getenv('API_KEYS_CLAIM_PASSWORD') !== false
                    ? (string) getenv('API_KEYS_CLAIM_PASSWORD')
                    : 'password',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            ),
            ExpiryNoticeClaimSql::createTableMysql(),
        ],
        'pgsql' => [
            new PDO(
                getenv('API_KEYS_CLAIM_DSN') ?: 'pgsql:host=127.0.0.1;port=5432;dbname=api_keys_claim',
                getenv('API_KEYS_CLAIM_USER') ?: 'postgres',
                getenv('API_KEYS_CLAIM_PASSWORD') !== false
                    ? (string) getenv('API_KEYS_CLAIM_PASSWORD')
                    : 'password',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            ),
            ExpiryNoticeClaimSql::createTablePgsql(),
        ],
        default => throw new InvalidArgumentException('Unknown API_KEYS_CLAIM_ENGINE: '.$engine),
    };
}

function expiryNoticeClaimBindTimestamp(PDO $pdo, DateTimeImmutable $moment): string
{
    $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

    if ($driver === 'pgsql') {
        return $moment->format(DateTimeInterface::ATOM);
    }

    return $moment->format('Y-m-d H:i:s');
}

it('N2: ExpiryNoticeClaimSql claim is affected-row CAS on the configured engine', function (): void {
    $engine = expiryNoticeClaimEngine();
    [$pdo, $createSql] = expiryNoticeClaimPdo();

    $pdo->exec('DROP TABLE IF EXISTS api_keys');
    $pdo->exec($createSql);

    $uuid = '018f0000-0000-7000-8000-00000000ca51';
    $insert = $pdo->prepare('INSERT INTO api_keys (uuid, expiry_notified_at, expiry_notice_claimed_at) VALUES (?, NULL, NULL)');
    $insert->execute([$uuid]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $leaseSeconds = 900;
    $leaseCutoff = $now->modify('-'.$leaseSeconds.' seconds');
    $claimedAt = expiryNoticeClaimBindTimestamp($pdo, $now);
    $cutoff = expiryNoticeClaimBindTimestamp($pdo, $leaseCutoff);

    $claim = $pdo->prepare(ExpiryNoticeClaimSql::claim());
    $claim->execute([$claimedAt, $uuid, $cutoff]);
    expect($claim->rowCount())->toBe(1);

    // Second claim while the lease is fresh must affect zero rows.
    $claim->execute([$claimedAt, $uuid, $cutoff]);
    expect($claim->rowCount())->toBe(0);

    // After the lease window, reclaim wins once.
    $afterLease = $now->modify('+'.($leaseSeconds + 1).' seconds');
    $afterClaimedAt = expiryNoticeClaimBindTimestamp($pdo, $afterLease);
    $afterCutoff = expiryNoticeClaimBindTimestamp($pdo, $afterLease->modify('-'.$leaseSeconds.' seconds'));
    $claim->execute([$afterClaimedAt, $uuid, $afterCutoff]);
    expect($claim->rowCount())->toBe(1);

    $mark = $pdo->prepare(ExpiryNoticeClaimSql::markNotified());
    $notifiedAt = expiryNoticeClaimBindTimestamp($pdo, $afterLease);
    $mark->execute([$notifiedAt, $uuid]);
    expect($mark->rowCount())->toBe(1);

    // Further claims after notify must lose.
    $claim->execute([$afterClaimedAt, $uuid, $afterCutoff]);
    expect($claim->rowCount())->toBe(0);

    echo "Engine={$engine}: claim CAS ok\n";
});
