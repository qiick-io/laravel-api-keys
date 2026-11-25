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

it('N2: ExpiryNoticeClaimSql claim is affected-row CAS, bound to the claim token and the selected expiry', function (): void {
    $engine = expiryNoticeClaimEngine();
    [$pdo, $createSql] = expiryNoticeClaimPdo();

    $pdo->exec('DROP TABLE IF EXISTS api_keys');
    $pdo->exec($createSql);

    $uuid = '018f0000-0000-7000-8000-00000000ca51';
    $expiresAt = expiryNoticeClaimBindTimestamp($pdo, new DateTimeImmutable('2026-01-15T00:00:00+00:00'));
    $rotatedExpiresAt = expiryNoticeClaimBindTimestamp($pdo, new DateTimeImmutable('2026-04-15T00:00:00+00:00'));
    $insert = $pdo->prepare('INSERT INTO api_keys (uuid, expires_at, expiry_notified_at, expiry_notice_claimed_at, expiry_notice_claim_token) VALUES (?, ?, NULL, NULL, NULL)');
    $insert->execute([$uuid, $expiresAt]);

    $now = new DateTimeImmutable('2026-01-10T12:00:00+00:00');
    $leaseSeconds = 900;
    $claimedAt = expiryNoticeClaimBindTimestamp($pdo, $now);
    $cutoff = expiryNoticeClaimBindTimestamp($pdo, $now->modify('-'.$leaseSeconds.' seconds'));
    $claim = $pdo->prepare(ExpiryNoticeClaimSql::claim());
    $mark = $pdo->prepare(ExpiryNoticeClaimSql::markNotified());
    $release = $pdo->prepare(ExpiryNoticeClaimSql::release());

    // A claim for an expiry the row no longer has (a rotation since the select) loses.
    $claim->execute([$claimedAt, 'token-a', $uuid, $rotatedExpiresAt, $cutoff]);
    expect($claim->rowCount())->toBe(0);

    // Run A claims; a second claim while the lease is fresh loses.
    $claim->execute([$claimedAt, 'token-a', $uuid, $expiresAt, $cutoff]);
    expect($claim->rowCount())->toBe(1);
    $claim->execute([$claimedAt, 'token-b', $uuid, $expiresAt, $cutoff]);
    expect($claim->rowCount())->toBe(0);

    // Only the claim's own token marks or releases it.
    $mark->execute([$claimedAt, $uuid, $expiresAt, 'token-b']);
    expect($mark->rowCount())->toBe(0);
    $release->execute([$uuid, $expiresAt, 'token-b']);
    expect($release->rowCount())->toBe(0);

    // After the lease, run B reclaims: run A, still sending, can neither mark nor release it.
    $afterLease = $now->modify('+'.($leaseSeconds + 1).' seconds');
    $afterClaimedAt = expiryNoticeClaimBindTimestamp($pdo, $afterLease);
    $afterCutoff = expiryNoticeClaimBindTimestamp($pdo, $afterLease->modify('-'.$leaseSeconds.' seconds'));
    $claim->execute([$afterClaimedAt, 'token-b', $uuid, $expiresAt, $afterCutoff]);
    expect($claim->rowCount())->toBe(1);
    $mark->execute([$afterClaimedAt, $uuid, $expiresAt, 'token-a']);
    expect($mark->rowCount())->toBe(0);
    $release->execute([$uuid, $expiresAt, 'token-a']);
    expect($release->rowCount())->toBe(0);

    // Run B releases after a failed send; its next claim wins at once.
    $release->execute([$uuid, $expiresAt, 'token-b']);
    expect($release->rowCount())->toBe(1);
    $claim->execute([$afterClaimedAt, 'token-c', $uuid, $expiresAt, $afterCutoff]);
    expect($claim->rowCount())->toBe(1);

    // A rotation between claim and mark: the new expiry is not stamped as notified.
    $pdo->prepare('UPDATE api_keys SET expires_at = ? WHERE uuid = ?')->execute([$rotatedExpiresAt, $uuid]);
    $mark->execute([$afterClaimedAt, $uuid, $expiresAt, 'token-c']);
    expect($mark->rowCount())->toBe(0);

    // The claim for the current expiry marks once and clears the claim.
    $pdo->prepare('UPDATE api_keys SET expires_at = ? WHERE uuid = ?')->execute([$expiresAt, $uuid]);
    $mark->execute([$afterClaimedAt, $uuid, $expiresAt, 'token-c']);
    expect($mark->rowCount())->toBe(1);
    $row = $pdo->query("SELECT expiry_notice_claimed_at, expiry_notice_claim_token, expiry_notified_at FROM api_keys WHERE uuid = '{$uuid}'")->fetch(PDO::FETCH_ASSOC);
    expect($row['expiry_notice_claimed_at'])->toBeNull()
        ->and($row['expiry_notice_claim_token'])->toBeNull()
        ->and($row['expiry_notified_at'])->not->toBeNull();

    // Further claims after notify lose.
    $claim->execute([$afterClaimedAt, 'token-d', $uuid, $expiresAt, $afterCutoff]);
    expect($claim->rowCount())->toBe(0);

    echo "Engine={$engine}: claim CAS ok\n";
});
