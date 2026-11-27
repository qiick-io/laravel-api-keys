import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

/** List the gate's targets without requiring Composer, a coverage driver or cache servers. */
function inventory(overrides = {}, workingDirectory = process.cwd()) {
    return spawnSync('bash', ['scripts/mutate-per-class.sh'], {
        cwd: workingDirectory,
        encoding: 'utf8',
        env: {
            ...process.env,
            API_KEYS_LIMITER_STORE: 'both',
            MUTATE_CLASSES: '[]',
            MUTATE_LIST: '1',
            MUTATE_ONLY: '',
            MUTATE_SCOPE: 'all',
            MUTATE_SHARD: '',
            ...overrides,
        },
    });
}

test('the full gate includes erasure and the real-store limiter, but no contracts or fakes', () => {
    const result = inventory();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^Qiick\\ApiKeys\\Erasure\\ApiKeysEraser$/m);
    assert.match(result.stdout, /^Qiick\\ApiKeys\\CacheAttemptLimiter$/m);
    assert.doesNotMatch(result.stdout, /^Qiick\\ApiKeys\\(?:Contracts|Testing)\\/m);
    assert.ok(result.stdout.trim().split('\n').length >= 49);
});

test('pull requests select only changed executable source paths', () => {
    const result = inventory({
        MUTATE_SCOPE: 'changed',
        MUTATE_CLASSES: JSON.stringify([
            'src/ExpiryNoticeClaimSql.php',
            'src/Contracts/ApiKeyRepository.php',
            'src/Testing/FakeApiKeyRepository.php',
        ]),
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'Qiick\\ApiKeys\\ExpiryNoticeClaimSql');
});

test('a misspelled explicit mutation target fails the gate', () => {
    const result = inventory({ MUTATE_ONLY: 'Qiick\\ApiKeys\\MissingTarget' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unknown mutation target/);
});

test('a noncanonical changed path fails instead of selecting nothing', () => {
    const result = inventory({
        MUTATE_SCOPE: 'changed',
        MUTATE_CLASSES: '["./src/ExpiryNoticeClaimSql.php"]',
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Invalid mutation path/);
});

test('an invalid shard cannot report an empty successful gate', () => {
    const result = inventory({ MUTATE_SHARD: '5/4' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Invalid mutation shard/);
});

test('the shards cover every source type once beside the dedicated cache limiter', () => {
    const full = inventory({ API_KEYS_LIMITER_STORE: '' });
    assert.equal(full.status, 0, full.stderr);

    const shardTargets = [1, 2, 3, 4].flatMap(shard => {
        const result = inventory({ API_KEYS_LIMITER_STORE: '', MUTATE_SHARD: shard + '/4' });
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.trim().split('\n');
    });

    assert.deepEqual(shardTargets.sort(), full.stdout.trim().split('\n').sort());
});

test('enumeration includes enums with behaviour and excludes case-only enums', context => {
    const fixture = mkdtempSync(join(tmpdir(), 'api-keys-mutation-inventory-'));
    context.after(() => rmSync(fixture, { recursive: true, force: true }));
    mkdirSync(join(fixture, 'src'));
    mkdirSync(join(fixture, 'scripts'));
    copyFileSync('scripts/mutate-per-class.sh', join(fixture, 'scripts/mutate-per-class.sh'));
    writeFileSync(join(fixture, 'src/ExecutableEnum.php'), '<?php\nenum ExecutableEnum { public function value(): int { return 1; } }\n');
    writeFileSync(join(fixture, 'src/CaseOnlyEnum.php'), '<?php\nenum CaseOnlyEnum { case Default; }\n');

    const result = inventory({}, fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'Qiick\\ApiKeys\\ExecutableEnum');
});
