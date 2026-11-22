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
    ?DateTimeImmutable $legacyAcceptUntil = null,
): TokenCodec {
    return new TokenCodec(
        productPrefix: $product,
        environment: new FixedEnvironment($environment),
        random: new FixedRandomSource($seed),
        legacyMatchers: $legacyMatchers,
        legacyAcceptUntil: $legacyAcceptUntil,
    );
}

function codecNow(): DateTimeImmutable
{
    return new DateTimeImmutable('2026-01-15T12:00:00Z');
}

it('pins ID_LENGTH and SECRET_LENGTH to the fleet sizes (A1)', function (): void {
    // Public consts are the @api names; operational lengths live in private
    // methods (typed class-const lines are not coverage-attributed by Pest mutate).
    expect(TokenCodec::ID_LENGTH)->toBe(8)
        ->and(TokenCodec::SECRET_LENGTH)->toBe(32)
        ->and(TokenCodec::CHECKSUM_LENGTH)->toBe(6)
        ->and(TokenCodec::DEFAULT_TOKEN_VERSION)->toBe(2);

    $token = codec()->issue();
    $id = substr($token->keyPrefix, -8);
    $remainder = strlen($token->plainText) - strlen($token->keyPrefix);

    expect(strlen($id))->toBe(8)
        ->and($remainder)->toBe(TokenCodec::SECRET_LENGTH + TokenCodec::CHECKSUM_LENGTH)
        // Consts stay aligned with the operational methods used at issue time.
        ->and(strlen($id))->toBe(TokenCodec::ID_LENGTH)
        ->and($token->tokenVersion)->toBe(2);
});

it('issues a token with the fleet shape and hashes the full plaintext', function (): void {
    $codec = codec();
    $token = $codec->issue();

    // Hardcoded lengths also kill shrink/grow of the lengths used at issue time.
    expect($token->keyPrefix)->toMatch('/^tst_test_[A-Za-z0-9]{8}$/D')
        ->and($token->plainText)->toStartWith($token->keyPrefix)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(38)
        ->and(strlen($token->keyPrefix))->toBe(17)
        ->and($token->tokenVersion)->toBe(2)
        ->and($token->keyHash)->toBe(hash('sha256', $token->plainText))
        ->and($codec->parse($token->plainText))->not->toBeNull()
        ->and($codec->prefixOf($token->plainText, codecNow()))->toBe($token->keyPrefix);
});

it('redacts plaintext and hash in GeneratedToken debug output', function (): void {
    $token = codec()->issue();
    $debug = $token->__debugInfo();

    expect($debug)->toHaveKeys(['keyPrefix', 'keyHash', 'tokenVersion', 'plainText'])
        ->and($debug['keyPrefix'])->toBe($token->keyPrefix)
        ->and($debug['keyHash'])->toBe('[REDACTED]')
        ->and($debug['tokenVersion'])->toBe(2)
        ->and($debug['plainText'])->toBe('[REDACTED]')
        ->and($debug['plainText'])->not->toBe($token->plainText)
        ->and($debug['keyHash'])->not->toBe($token->keyHash);
});

it('redacts plaintext via json_encode and serialize on GeneratedToken', function (): void {
    $token = codec()->issue();

    expect(json_encode($token))->not->toContain($token->plainText)
        ->and(json_encode($token))->toContain('[REDACTED]')
        ->and(serialize($token))->not->toContain($token->plainText)
        ->and(serialize($token))->toContain('[REDACTED]');

    expect(fn () => unserialize(serialize($token)))->toThrow(LogicException::class);
});

it('redacts the secret in ParsedToken debug, JSON, and serialize output', function (): void {
    $codec = codec();
    $token = $codec->issue();
    $parsed = $codec->parse($token->plainText);
    $debug = $parsed->__debugInfo();

    expect($debug['secret'])->toBe('[REDACTED]')
        ->and($debug['secret'])->not->toBe($parsed->secret)
        ->and($debug['keyPrefix'])->toBe($token->keyPrefix)
        ->and(json_encode($parsed))->not->toContain($parsed->secret)
        ->and(json_encode($parsed))->toContain('[REDACTED]')
        ->and(serialize($parsed))->not->toContain($parsed->secret)
        ->and(serialize($parsed))->toContain('[REDACTED]');

    expect(fn () => unserialize(serialize($parsed)))->toThrow(LogicException::class);
});

it('rejects secrets longer than exactly SECRET_LENGTH', function (): void {
    $codec = codec();
    $token = $codec->issue();
    $tooLong = $token->plainText.'x';

    expect($codec->prefixOf($tooLong, codecNow()))->toBeNull()
        ->and($codec->parse($tooLong))->toBeNull();
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
    $now = codecNow();

    expect($codec->prefixOf('not-a-token', $now))->toBeNull()
        ->and($codec->parse('not-a-token'))->toBeNull()
        ->and($codec->prefixOf('ek_ABCDEFGHIx'.str_repeat('y', 32), $now))->toBeNull()
        ->and($codec->prefixOf('tst_test_SHORT'.str_repeat('z', 32), $now))->toBeNull()
        ->and($codec->prefixOf('tst_test_ABCDEFGH'.str_repeat('z', 32)."\n", $now))->toBeNull();
});

it('uses legacy matchers only when the canonical shape misses', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $hit = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil);
    $miss = new RecordingLegacyTokenMatcher('ek_OTHERPREF', $acceptUntil);
    $codec = codec(legacyMatchers: [$miss, $hit]);
    $now = codecNow();

    $legacyToken = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($legacyToken, $now))->toBe('ek_ABCDEFGHI')
        ->and($miss->prefixOfCalls)->toBe(1)
        ->and($hit->prefixOfCalls)->toBe(1)
        // Canonical hit must not consult legacy matchers.
        ->and($codec->prefixOf('tst_test_ABCDEFGH'.str_repeat('z', 32), $now))->toBe('tst_test_ABCDEFGH')
        ->and($miss->prefixOfCalls)->toBe(1)
        ->and($hit->prefixOfCalls)->toBe(1)
        ->and($codec->legacyMatcherFor('tst_test_ABCDEFGH'.str_repeat('z', 32), $now))->toBeNull();
});

it('returns null from prefixOf when every legacy matcher misses', function (): void {
    $miss = new RecordingLegacyTokenMatcher(null, new DateTimeImmutable('2099-01-01T00:00:00Z'));
    $codec = codec(legacyMatchers: [$miss]);

    expect($codec->prefixOf('ek_ABCDEFGHI'.str_repeat('y', 31), codecNow()))->toBeNull()
        ->and($miss->prefixOfCalls)->toBe(1);
});

it('rejects matcher prefixes that are not a strict prefix leaving the matcher secret length', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    // Default secretLength 31 (Externa). Prefix equal to token → refused.
    $matcher = new RecordingLegacyTokenMatcher('ek_SHORT', $acceptUntil);
    $empty = new RecordingLegacyTokenMatcher('', $acceptUntil);
    $codec = codec(legacyMatchers: [$matcher]);
    $now = codecNow();

    expect($codec->prefixOf('ek_SHORT', $now))->toBeNull()
        ->and($codec->legacyMatcherFor('ek_SHORT', $now))->toBeNull()
        ->and($codec->prefixOf('ek_SHORT'.str_repeat('y', 30), $now))->toBeNull()
        ->and($codec->legacyMatcherFor('ek_SHORT'.str_repeat('y', 30), $now))->toBeNull()
        ->and($codec->prefixOf('ek_SHORT'.str_repeat('y', 31), $now))->toBe('ek_SHORT')
        ->and($codec->legacyMatcherFor('ek_SHORT'.str_repeat('y', 31), $now))->toBe($matcher);

    $emptyCodec = codec(legacyMatchers: [$empty]);
    expect($emptyCodec->prefixOf('ek_ABCDEFGHI'.str_repeat('y', 31), $now))->toBeNull()
        ->and($emptyCodec->legacyMatcherFor('ek_ABCDEFGHI'.str_repeat('y', 31), $now))->toBeNull();
});

it('honours isAccepting as an early-stop even before the cut-off', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $stopped = (new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil))->withoutAccepting();
    $codec = codec(legacyMatchers: [$stopped]);
    $now = codecNow();
    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($token, $now))->toBeNull()
        ->and($codec->isValidKeyPrefix('ek_ABCDEFGHI', $now))->toBeFalse()
        ->and($stopped->prefixOfCalls)->toBe(0);
});

it('returns null from legacyMatcherFor for canonical tokens even when a matcher would match', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    // Would greedily match any tst_test_… token if legacyMatcherFor did not bail on canonical.
    $greedy = new RecordingLegacyTokenMatcher('tst_test_', $acceptUntil);
    $codec = codec(legacyMatchers: [$greedy]);
    $now = codecNow();
    $canonical = 'tst_test_ABCDEFGH'.str_repeat('z', 32);

    expect($codec->legacyMatcherFor($canonical, $now))->toBeNull()
        ->and($codec->prefixOf($canonical, $now))->toBe('tst_test_ABCDEFGH');
});

it('skips expired matchers when recognising a stored legacy prefix for rotation', function (): void {
    $expired = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', new DateTimeImmutable('2020-01-01T00:00:00Z'));
    $live = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', new DateTimeImmutable('2099-01-01T00:00:00Z'));
    $codec = codec(legacyMatchers: [$expired, $live]);
    $now = codecNow();

    expect($codec->isValidKeyPrefix('ek_ABCDEFGHI', $now))->toBeTrue()
        ->and($expired->prefixOfCalls)->toBe(0)
        ->and($live->prefixOfCalls)->toBe(1);
});

it('recognises canonical and accepting legacy prefixes without secret-length probes', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $matcher = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil);
    $codec = codec(legacyMatchers: [$matcher]);
    $now = new DateTimeImmutable('2026-01-15T12:00:00Z');

    expect($codec->isCanonicalKeyPrefix('tst_test_ABCDEFGH'))->toBeTrue()
        ->and($codec->isValidKeyPrefix('tst_test_ABCDEFGH', $now))->toBeTrue()
        ->and($codec->isCanonicalKeyPrefix('ek_ABCDEFGHI'))->toBeFalse()
        ->and($codec->isValidKeyPrefix('ek_ABCDEFGHI', $now))->toBeTrue()
        ->and($matcher->prefixOfCalls)->toBe(1)
        ->and($codec->isValidKeyPrefix('not-a-prefix', $now))->toBeFalse();
});

it('rejects legacy prefixes once the matcher cut-off has passed', function (): void {
    $matcher = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', new DateTimeImmutable('2020-01-01T00:00:00Z'));
    $codec = codec(legacyMatchers: [$matcher]);

    expect($codec->isValidKeyPrefix('ek_ABCDEFGHI', new DateTimeImmutable('2026-01-15T12:00:00Z')))
        ->toBeFalse()
        ->and($matcher->prefixOfCalls)->toBe(0);
});

it('is deterministic for the same FixedEnvironment and FixedRandomSource seed', function (): void {
    $seed = 'same-seed-bytes-aaaaaaaaaaaaaaaaaaaa';
    $first = codec(seed: $seed)->issue();
    $second = codec(seed: $seed)->issue();

    expect($first->plainText)->toBe($second->plainText)
        ->and($first->keyPrefix)->toBe($second->keyPrefix)
        ->and(strlen($first->keyPrefix))->toBe(17)
        ->and(strlen($first->plainText) - strlen($first->keyPrefix))->toBe(38);
});

it('rejects bytes 248..255 when mapping onto the alphabet (no modulo bias)', function (): void {
    // Each randomAlphabet round draws a 32-byte chunk. For the id: eight
    // rejected bytes, eight usable \x01 → 'B', then sixteen surplus \x02 → 'C'
    // that must NOT be consumed (break at exact length). Secret chunk: 32×\x00 → 'A'.
    $idChunk = "\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
        .str_repeat("\x01", 8)
        .str_repeat("\x02", 16);
    $secretChunk = str_repeat("\x00", 32);
    $token = codec(seed: $idChunk.$secretChunk)->issue();
    $secret = substr($token->plainText, strlen($token->keyPrefix), 32);

    expect(strlen($token->keyPrefix))->toBe(17)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(38)
        ->and(substr($token->keyPrefix, -8))->toBe('BBBBBBBB')
        ->and($secret)->toBe(str_repeat('A', 32));
});

it('keeps byte 247 and skips byte 248 at the rejection threshold', function (): void {
    // 247 % 62 = 61 → '9'; if the check were `>` instead of `>=`, 248 would
    // become alphabet[0] = 'A' and this id would start with A.
    // Chunk of 32 for id, then 32 for secret.
    $idChunk = "\xF8\xF7".str_repeat("\x00", 30);
    $secretChunk = str_repeat("\x00", 32);
    $token = codec(seed: $idChunk.$secretChunk)->issue();

    expect(substr($token->keyPrefix, -8))->toStartWith('9')
        ->and(strlen(substr($token->keyPrefix, -8)))->toBe(8)
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(38);
});

it('refills after a whole chunk of rejected bytes', function (): void {
    // Exhausts the for-loop bound (`$index < $count`) on a 32-byte rejected
    // chunk; `$index <= $count` would read past the end (ord of '').
    $rejectedChunk = str_repeat("\xFF", 32);
    $idChunk = str_repeat("\x01", 32);
    $secretChunk = str_repeat("\x00", 32);
    $token = codec(seed: $rejectedChunk.$idChunk.$secretChunk)->issue();

    expect(substr($token->keyPrefix, -8))->toBe('BBBBBBBB')
        ->and(strlen($token->plainText) - strlen($token->keyPrefix))->toBe(38);
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
