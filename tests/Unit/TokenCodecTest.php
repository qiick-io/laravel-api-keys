<?php

declare(strict_types=1);

use Qiick\ApiKeys\GeneratedToken;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Tests\Support\RecordingLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;
use Qiick\ApiKeys\TokenMatch;

mutates(TokenCodec::class);
mutates(GeneratedToken::class);

function codec(
    string $product = 'tst',
    TokenEnvironment $environment = TokenEnvironment::Test,
    string $seed = 'fixed-seed-for-deterministic-api-key-tests!!',
    array $legacyMatchers = [],
): TokenCodec {
    return new TokenCodec(
        productPrefix: $product,
        environment: new FixedEnvironment($environment),
        random: new FixedRandomSource($seed),
        legacyMatchers: $legacyMatchers,
    );
}

it('pins ID_LENGTH and SECRET_LENGTH to the fleet sizes (A1)', function (): void {
    // Public consts are the @api names; operational lengths live in private
    // methods (typed class-const lines are not coverage-attributed by Pest mutate).
    expect(TokenCodec::ID_LENGTH)->toBe(8)
        ->and(TokenCodec::SECRET_LENGTH)->toBe(32);

    $token = codec()->issue();
    $id = substr($token->keyPrefix, -8);

    expect(strlen($id))->toBe(8)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(32)
        // Consts stay aligned with the operational methods used at issue time.
        ->and(strlen($id))->toBe(TokenCodec::ID_LENGTH)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(TokenCodec::SECRET_LENGTH);
});

it('issues a token with the fleet shape and hashes the full plaintext', function (): void {
    $codec = codec();
    $token = $codec->issue();

    // Hardcoded lengths also kill shrink/grow of the lengths used at issue time.
    expect($token->keyPrefix)->toMatch('/^tst_test_[A-Za-z0-9]{8}$/D')
        ->and($token->plainText)->toStartWith($token->keyPrefix)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(32)
        ->and(strlen($token->keyPrefix))->toBe(17)
        ->and($token->keyHash)->toBe(hash('sha256', $token->plainText))
        ->and($codec->parse($token->plainText))->not->toBeNull()
        ->and($codec->prefixOf($token->plainText))->toBe($token->keyPrefix);
});

it('redacts plaintext and hash in GeneratedToken debug output', function (): void {
    $token = codec()->issue();
    $debug = $token->__debugInfo();

    expect($debug)->toHaveKeys(['keyPrefix', 'keyHash', 'plainText'])
        ->and($debug['keyPrefix'])->toBe($token->keyPrefix)
        ->and($debug['keyHash'])->toBe('[REDACTED]')
        ->and($debug['plainText'])->toBe('[REDACTED]')
        ->and($debug['plainText'])->not->toBe($token->plainText)
        ->and($debug['keyHash'])->not->toBe($token->keyHash);
});

it('prefers an explicit environment override over the resolver', function (): void {
    $token = codec(environment: TokenEnvironment::Test)->issue(TokenEnvironment::Live);

    expect($token->keyPrefix)->toStartWith('tst_live_');
});

it('reissues a new secret behind the same public prefix', function (): void {
    $codec = codec();
    $first = $codec->issue();
    $second = $codec->reissueForPrefix($first->keyPrefix);

    expect($second->keyPrefix)->toBe($first->keyPrefix)
        ->and($second->plainText)->not->toBe($first->plainText)
        ->and($second->keyHash)->not->toBe($first->keyHash);
});

it('matches current and previous hashes with hash_equals semantics', function (): void {
    $codec = codec();
    $current = $codec->issue();
    $rotated = $codec->reissueForPrefix($current->keyPrefix);
    $now = new DateTimeImmutable('2026-11-20T12:00:00Z');
    $graceUntil = new DateTimeImmutable('2026-11-20T18:00:00Z');

    expect($codec->match($rotated->plainText, $rotated->keyHash, null, null, $now))
        ->toBe(TokenMatch::Current)
        ->and($codec->match(
            $current->plainText,
            $rotated->keyHash,
            $current->keyHash,
            $graceUntil,
            $now,
        ))->toBe(TokenMatch::Previous)
        // Exact grace boundary: previous is valid only while now < until (not <=).
        ->and($codec->match(
            $current->plainText,
            $rotated->keyHash,
            $current->keyHash,
            $graceUntil,
            $graceUntil,
        ))->toBe(TokenMatch::None)
        ->and($codec->match(
            $current->plainText,
            $rotated->keyHash,
            $current->keyHash,
            $graceUntil,
            new DateTimeImmutable('2026-11-20T19:00:00Z'),
        ))->toBe(TokenMatch::None)
        // Previous hash present but grace window null → never Previous.
        ->and($codec->match(
            $current->plainText,
            $rotated->keyHash,
            $current->keyHash,
            null,
            $now,
        ))->toBe(TokenMatch::None)
        // Grace window set but previous hash null → never Previous (kills AND→OR).
        ->and($codec->match(
            $current->plainText,
            $rotated->keyHash,
            null,
            $graceUntil,
            $now,
        ))->toBe(TokenMatch::None)
        ->and($codec->match('tst_test_AAAAAAAA'.str_repeat('B', 32), $rotated->keyHash, null, null, $now))
        ->toBe(TokenMatch::None);
});

it('rejects non-canonical shapes from prefixOf and parse', function (): void {
    $codec = codec();

    expect($codec->prefixOf('not-a-token'))->toBeNull()
        ->and($codec->parse('not-a-token'))->toBeNull()
        ->and($codec->prefixOf('ek_ABCDEFGHIx'.str_repeat('y', 31)))->toBeNull()
        ->and($codec->prefixOf('tst_test_SHORT'.str_repeat('z', 32)))->toBeNull()
        ->and($codec->prefixOf('tst_test_ABCDEFGH'.str_repeat('z', 32)."\n"))->toBeNull();
});

it('uses legacy matchers only when the canonical shape misses', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $hit = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil);
    $miss = new RecordingLegacyTokenMatcher('ek_OTHERPREF', $acceptUntil);
    $codec = codec(legacyMatchers: [$miss, $hit]);

    $legacyToken = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($legacyToken))->toBe('ek_ABCDEFGHI')
        ->and($miss->prefixOfCalls)->toBe(1)
        ->and($hit->prefixOfCalls)->toBe(1)
        // Canonical hit must not consult legacy matchers.
        ->and($codec->prefixOf('tst_test_ABCDEFGH'.str_repeat('z', 32)))->toBe('tst_test_ABCDEFGH')
        ->and($miss->prefixOfCalls)->toBe(1)
        ->and($hit->prefixOfCalls)->toBe(1);
});

it('returns null from prefixOf when every legacy matcher misses', function (): void {
    $miss = new RecordingLegacyTokenMatcher(null, new DateTimeImmutable('2099-01-01T00:00:00Z'));
    $codec = codec(legacyMatchers: [$miss]);

    expect($codec->prefixOf('ek_ABCDEFGHI'.str_repeat('y', 31)))->toBeNull()
        ->and($miss->prefixOfCalls)->toBe(1);
});

it('is deterministic for the same FixedEnvironment and FixedRandomSource seed', function (): void {
    $seed = 'same-seed-bytes-aaaaaaaaaaaaaaaaaaaa';
    $first = codec(seed: $seed)->issue();
    $second = codec(seed: $seed)->issue();

    expect($first->plainText)->toBe($second->plainText)
        ->and($first->keyPrefix)->toBe($second->keyPrefix)
        ->and(strlen($first->keyPrefix))->toBe(17)
        ->and(strlen($first->plainText) - strlen($first->keyPrefix))->toBe(32);
});

it('runs a dummy compare when asked and when match returns none', function (): void {
    $codec = codec();
    $codec->performDummyMatch('tst_test_ABCDEFGH'.str_repeat('z', 32));

    expect($codec->match(
        'tst_test_ABCDEFGH'.str_repeat('z', 32),
        hash('sha256', 'other'),
        null,
        null,
        new DateTimeImmutable('now'),
    ))->toBe(TokenMatch::None);
});

it('refuses a product prefix that is not three lowercase letters', function (): void {
    expect(fn () => codec(product: 'EXT'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => codec(product: 'ab'))->toThrow(InvalidArgumentException::class);
});
