import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

/** List the gate's targets without requiring Composer, a coverage driver or cache servers. */
function inventory(overrides = {}) {
    return spawnSync('bash', ['scripts/mutate-per-class.sh'], {
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
