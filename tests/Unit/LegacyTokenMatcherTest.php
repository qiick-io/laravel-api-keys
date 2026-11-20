<?php

declare(strict_types=1);

use Qiick\ApiKeys\Events\LegacyTokenUsed;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

use function Qiick\ApiKeys\Testing\assertLegacyTokenUsed;

it('enforces legacy EOL when now is past accept_until (A13)', function (): void {
    $acceptUntil = new DateTimeImmutable('2026-06-01T00:00:00Z');
    $matcher = RegexLegacyTokenMatcher::externaEkStyle($acceptUntil);
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
    );

    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);

    expect($codec->prefixOf($token, new DateTimeImmutable('2026-05-31T00:00:00Z')))->toBe('ek_ABCDEFGHI')
        ->and($codec->legacyMatcherFor($token, new DateTimeImmutable('2026-05-31T00:00:00Z')))->toBe($matcher)
        ->and($codec->prefixOf($token, new DateTimeImmutable('2026-06-01T00:00:00Z')))->toBeNull()
        ->and($codec->legacyMatcherFor($token, new DateTimeImmutable('2026-06-01T00:00:00Z')))->toBeNull();
});

it('builds LegacyTokenUsed from legacyMatcherFor for product dispatch', function (): void {
    $acceptUntil = new DateTimeImmutable('2027-01-01T00:00:00Z');
    $matcher = RegexLegacyTokenMatcher::externaEkStyle($acceptUntil);
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$matcher],
    );

    $token = 'ek_ABCDEFGHI'.str_repeat('y', 31);
    $now = new DateTimeImmutable('2026-12-01T00:00:00Z');
    $hit = $codec->legacyMatcherFor($token, $now);
    expect($hit)->not->toBeNull();

    $event = new LegacyTokenUsed(
        keyPrefix: $hit->prefixOf($token),
        matcherClass: $hit::class,
        acceptUntil: $hit->acceptUntil(),
    );

    assertLegacyTokenUsed($event, 'ek_ABCDEFGHI', RegexLegacyTokenMatcher::class, $acceptUntil);
});

it('continues past an expired matcher to a still-accepting one', function (): void {
    $expired = RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2020-01-01T00:00:00Z'));
    $live = new RegexLegacyTokenMatcher(
        '/^(?<prefix>old_[A-Za-z0-9]{8})[A-Za-z0-9]{32}$/D',
        new DateTimeImmutable('2099-01-01T00:00:00Z'),
    );
    $codec = new TokenCodec(
        productPrefix: 'ext',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-legacy-tests!!!'),
        legacyMatchers: [$expired, $live],
    );

    $token = 'old_ABCDEFGH'.str_repeat('z', 32);
    $now = new DateTimeImmutable('2026-01-01T00:00:00Z');

    expect($codec->prefixOf($token, $now))->toBe('old_ABCDEFGH')
        ->and($codec->legacyMatcherFor($token, $now))->toBe($live);
});
