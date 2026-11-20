<?php

declare(strict_types=1);

use Qiick\ApiKeys\Events\LegacyTokenUsed;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

use function Qiick\ApiKeys\Testing\assertLegacyTokenUsed;

it('accepts a real Externa ek_+9+31 token and refuses prefix-equal-to-token', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00+00:00');
    $matcher = RegexLegacyTokenMatcher::externaEkStyle($acceptUntil);
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
    );
    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect(strlen($token) - strlen('ek_ABCDEFGHI'))->toBe(31)
        ->and($codec->prefixOf($token, $now))->toBe('ek_ABCDEFGHI')
        ->and($codec->legacyMatcherFor($token, $now))->toBe($matcher)
        // Prefix equal to the whole presented string is not a usable match.
        ->and($codec->prefixOf('ek_ABCDEFGHI', $now))->toBeNull()
        ->and($codec->legacyMatcherFor('ek_ABCDEFGHI', $now))->toBeNull();
});

it('enforces legacy EOL when now is past accept_until (A13)', function (): void {
    $acceptUntil = new DateTimeImmutable('2026-06-01T00:00:00+00:00');
    $matcher = RegexLegacyTokenMatcher::externaEkStyle($acceptUntil);
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
    );

    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($token, new DateTimeImmutable('2026-05-31T00:00:00+00:00')))->toBe('ek_ABCDEFGHI')
        ->and($codec->legacyMatcherFor($token, new DateTimeImmutable('2026-05-31T00:00:00+00:00')))->toBe($matcher)
        // Exactly at cut-off is rejected (now >= until).
        ->and($codec->prefixOf($token, new DateTimeImmutable('2026-06-01T00:00:00+00:00')))->toBeNull()
        ->and($codec->legacyMatcherFor($token, new DateTimeImmutable('2026-06-01T00:00:00+00:00')))->toBeNull();
});

it('applies the earlier of config cut-off and matcher acceptUntil', function (): void {
    $matcher = RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2099-01-01T00:00:00+00:00'));
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
        legacyAcceptUntil: new DateTimeImmutable('2026-06-01T00:00:00+00:00'),
    );

    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($token, new DateTimeImmutable('2026-05-31T23:59:59+00:00')))->toBe('ek_ABCDEFGHI')
        ->and($codec->prefixOf($token, new DateTimeImmutable('2026-06-01T00:00:00+00:00')))->toBeNull();
});

it('builds LegacyTokenUsed from legacyMatcherFor for product dispatch', function (): void {
    $acceptUntil = new DateTimeImmutable('2027-01-01T00:00:00+00:00');
    $matcher = RegexLegacyTokenMatcher::externaEkStyle($acceptUntil);
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
    );

    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);
    $now = new DateTimeImmutable('2026-12-01T00:00:00+00:00');
    $hit = $codec->legacyMatcherFor($token, $now);
    expect($hit)->not->toBeNull();

    $event = new LegacyTokenUsed(
        keyPrefix: $hit->prefixOf($token) ?? '',
        matcherClass: $hit::class,
        acceptUntil: $hit->acceptUntil(),
    );

    assertLegacyTokenUsed($event, 'ek_ABCDEFGHI', RegexLegacyTokenMatcher::class, $acceptUntil);
});

it('continues past an expired matcher to a still-accepting one', function (): void {
    $expired = RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2020-01-01T00:00:00+00:00'));
    $live = new RegexLegacyTokenMatcher(
        pattern: '/^(?<prefix>old_[A-Za-z0-9]{8})[A-Za-z0-9]{32}$/D',
        acceptUntil: new DateTimeImmutable('2099-01-01T00:00:00+00:00'),
        barePrefixPattern: '/^(?<prefix>old_[A-Za-z0-9]{8})$/D',
        secretLength: 32,
    );
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$expired, $live],
    );

    $token = 'old_ABCDEFGH'.str_repeat('z', 32);
    $now = new DateTimeImmutable('2026-01-01T00:00:00+00:00');

    expect($codec->prefixOf($token, $now))->toBe('old_ABCDEFGH')
        ->and($codec->legacyMatcherFor($token, $now))->toBe($live);
});
