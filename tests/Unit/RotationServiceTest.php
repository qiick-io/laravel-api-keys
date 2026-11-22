<?php

declare(strict_types=1);

use Qiick\ApiKeys\Rotation;
use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\Testing\FixedClock;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;
use Qiick\ApiKeys\Tests\Support\RecordingLegacyTokenMatcher;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

mutates(RotationService::class);
mutates(Rotation::class);

function rotationCodec(array $legacyMatchers = []): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-rotation-tests!!'),
        legacyMatchers: $legacyMatchers,
    );
}

function rotationRecord(TokenCodec $codec, ?DateTimeImmutable $now = null): InMemoryApiKeyRecord
{
    $issued = $codec->issue();

    return new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
        scopes: ['items:read'],
    );
}

it('normalizes invalid, negative, and above-max grace hours to zero', function (): void {
    expect(RotationService::normalizeGraceHours(24))->toBe(24)
        ->and(RotationService::normalizeGraceHours(0))->toBe(0)
        ->and(RotationService::normalizeGraceHours(-1))->toBe(0)
        ->and(RotationService::normalizeGraceHours('12'))->toBe(12)
        ->and(RotationService::normalizeGraceHours('nope'))->toBe(0)
        ->and(RotationService::normalizeGraceHours(1.5))->toBe(0)
        ->and(RotationService::normalizeGraceHours(true))->toBe(0)
        ->and(RotationService::normalizeGraceHours(null))->toBe(0)
        ->and(RotationService::normalizeGraceHours([]))->toBe(0)
        ->and(RotationService::normalizeGraceHours(169))->toBe(0)
        ->and(RotationService::normalizeGraceHours(168))->toBe(168)
        ->and(RotationService::normalizeGraceHours(PHP_INT_MAX))->toBe(0)
        ->and(RotationService::normalizeGraceHours(100, maxGraceHours: 48))->toBe(0)
        ->and(RotationService::normalizeGraceHours(48, maxGraceHours: 48))->toBe(48);
});

it('rotates with a grace window that preserves the previous hash', function (): void {
    $codec = rotationCodec();
    $record = rotationRecord($codec);
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $record,
        $codec,
        new FixedClock($now),
        24,
    );

    expect($rotation->newPlainText)->not->toBe('')
        ->and($rotation->newKeyHash)->toBe(hash('sha256', $rotation->newPlainText))
        ->and($rotation->previousKeyHash)->toBe($record->keyHash())
        ->and($rotation->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-16 12:00:00')
        ->and(str_starts_with($rotation->newPlainText, $record->keyPrefix()))->toBeTrue();
});

it('keeps a one-hour grace window (boundary of the zero check)', function (): void {
    $codec = rotationCodec();
    $record = rotationRecord($codec);
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $record,
        $codec,
        new FixedClock($now),
        1,
    );

    expect($rotation->previousKeyHash)->toBe($record->keyHash())
        ->and($rotation->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-15 13:00:00');
});

it('drops the previous secret when grace hours are zero', function (): void {
    $codec = rotationCodec();
    $record = rotationRecord($codec);

    $rotation = (new RotationService)->rotate(
        $record,
        $codec,
        new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        0,
    );

    expect($rotation->previousKeyHash)->toBeNull()
        ->and($rotation->previousKeyValidUntil)->toBeNull()
        ->and($rotation->newKeyHash)->not->toBe($record->keyHash());
});

it('normalizes grace inside rotate so a negative or over-max config cannot extend the old secret', function (): void {
    $codec = rotationCodec();
    $record = rotationRecord($codec);
    $clock = new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00'));

    $negative = (new RotationService)->rotate($record, $codec, $clock, -5);
    expect($negative->previousKeyHash)->toBeNull()
        ->and($negative->previousKeyValidUntil)->toBeNull();

    $capped = (new RotationService)->rotate($record, $codec, $clock, 10_000);
    expect($capped->previousKeyHash)->toBeNull()
        ->and($capped->previousKeyValidUntil)->toBeNull();
});

it('replaces the previous grace secret on a second rotation', function (): void {
    $codec = rotationCodec();
    $first = rotationRecord($codec);
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $service = new RotationService;

    $once = $service->rotate($first, $codec, new FixedClock($now), 24);
    $secondRecord = new InMemoryApiKeyRecord(
        id: '42',
        keyPrefix: $first->keyPrefix(),
        keyHash: $once->newKeyHash,
        scopes: ['items:read'],
    );
    $twice = $service->rotate($secondRecord, $codec, new FixedClock($now->modify('+1 hour')), 24);

    expect($twice->previousKeyHash)->toBe($once->newKeyHash)
        ->and($twice->previousKeyHash)->not->toBe($first->keyHash())
        ->and($twice->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-16 13:00:00');
});

it('refuses to rotate a revoked or expired key (expiresAt == now is expired)', function (): void {
    $codec = rotationCodec();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $clock = new FixedClock($now);
    $service = new RotationService;

    expect($service->maxGraceHours())->toBe(168);

    $issued = $codec->issue();
    $revoked = (new InMemoryApiKeyRecord(
        id: '1',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
    ))->withRevokedAt($now->modify('-1 minute'));

    expect(fn () => $service->rotate($revoked, $codec, $clock, 24))
        ->toThrow(InvalidArgumentException::class, 'revoked');

    $expiredPast = (new InMemoryApiKeyRecord(
        id: '2',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
    ))->withExpiresAt($now->modify('-1 second'));

    expect(fn () => $service->rotate($expiredPast, $codec, $clock, 24))
        ->toThrow(InvalidArgumentException::class, 'expired');

    $expiredExact = (new InMemoryApiKeyRecord(
        id: '3',
        keyPrefix: $issued->keyPrefix,
        keyHash: $issued->keyHash,
    ))->withExpiresAt($now);

    expect(fn () => $service->rotate($expiredExact, $codec, $clock, 24))
        ->toThrow(InvalidArgumentException::class, 'expired');
});

it('clamps a negative maxGraceHours constructor arg to a zero ceiling', function (): void {
    expect(RotationService::normalizeGraceHours(5, maxGraceHours: -10))->toBe(0)
        ->and((new RotationService(-3))->maxGraceHours())->toBe(-3);
});

it('throws when the key prefix is not canonical and not recognised by a legacy matcher', function (): void {
    $codec = rotationCodec();
    $clock = new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00'));
    $bad = new InMemoryApiKeyRecord(
        id: '9',
        keyPrefix: 'not-a-valid-prefix',
        keyHash: 'abc',
    );

    expect(fn () => (new RotationService)->rotate($bad, $codec, $clock, 24))
        ->toThrow(InvalidArgumentException::class, 'prefix');
});

it('migrates a legacy-shaped prefix to a fresh canonical token on rotate', function (): void {
    $acceptUntil = new DateTimeImmutable('2099-01-01T00:00:00Z');
    $matcher = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil);
    $codec = rotationCodec([$matcher]);
    $clock = new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00'));
    $legacy = new InMemoryApiKeyRecord(
        id: 'ek',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: hash('sha256', 'ek_ABCDEFGHI'.str_repeat('y', 31)),
    );

    $rotation = (new RotationService)->rotate($legacy, $codec, $clock, 0);

    expect($rotation->previousKeyHash)->toBeNull()
        ->and($rotation->newKeyPrefix)->not->toBe('ek_ABCDEFGHI')
        ->and($codec->isCanonicalKeyPrefix($rotation->newKeyPrefix))->toBeTrue()
        ->and(str_starts_with($rotation->newPlainText, $rotation->newKeyPrefix))->toBeTrue();
});

it('F10: rotates an Externa ek_ row with previous_key_prefix grace across formats', function (): void {
    $matcher = RegexLegacyTokenMatcher::externaEkStyle(new DateTimeImmutable('2099-01-01T00:00:00+00:00'));
    $codec = rotationCodec([$matcher]);
    $now = new DateTimeImmutable('2026-01-15T12:00:00+00:00');
    $clock = new FixedClock($now);
    $legacyPlain = 'ek_ABCDEFGHI'.str_repeat('y', 31);
    $legacy = new InMemoryApiKeyRecord(
        id: 'ek',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: hash('sha256', $legacyPlain),
    );

    expect($codec->isValidKeyPrefix('ek_ABCDEFGHI', $now))->toBeTrue()
        ->and($matcher->prefixOf('ek_ABCDEFGHI'))->toBe('ek_ABCDEFGHI');

    // F10 / Luca 2026-11-22: graceHours > 0 keeps the old hash and previous_key_prefix.
    $rotation = (new RotationService)->rotate($legacy, $codec, $clock, 24);

    expect($rotation->previousKeyHash)->toBe($legacy->keyHash())
        ->and($rotation->previousKeyPrefix)->toBe('ek_ABCDEFGHI')
        ->and($rotation->previousKeyValidUntil)->not->toBeNull()
        ->and($codec->isCanonicalKeyPrefix($rotation->newKeyPrefix))->toBeTrue()
        ->and($codec->prefixOf($legacyPlain, $now))->toBe('ek_ABCDEFGHI')
        ->and($rotation->newKeyPrefix)->not->toBe('ek_ABCDEFGHI')
        ->and($rotation->lastRotatedAt->format(DateTimeInterface::ATOM))->toBe($now->format(DateTimeInterface::ATOM));
});

it('refuses to rotate a legacy prefix once the matcher cut-off has passed', function (): void {
    $acceptUntil = new DateTimeImmutable('2020-01-01T00:00:00Z');
    $matcher = new RecordingLegacyTokenMatcher('ek_ABCDEFGHI', $acceptUntil);
    $codec = rotationCodec([$matcher]);
    $clock = new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00'));
    $legacy = new InMemoryApiKeyRecord(
        id: 'ek',
        keyPrefix: 'ek_ABCDEFGHI',
        keyHash: hash('sha256', 'ek_ABCDEFGHI'.str_repeat('y', 31)),
    );

    expect(fn () => (new RotationService)->rotate($legacy, $codec, $clock, 0))
        ->toThrow(InvalidArgumentException::class, 'prefix');
});

it('redacts plaintext and hashes in Rotation debug, JSON, and serialize output', function (): void {
    $codec = rotationCodec();
    $record = rotationRecord($codec);
    $rotation = (new RotationService)->rotate(
        $record,
        $codec,
        new FixedClock(new DateTimeImmutable('2026-01-15 12:00:00')),
        24,
    );

    expect(json_encode($rotation))->not->toContain($rotation->newPlainText)
        ->and(json_encode($rotation))->toContain('[REDACTED]')
        ->and(serialize($rotation))->not->toContain($rotation->newPlainText)
        ->and($rotation->__debugInfo()['newPlainText'])->toBe('[REDACTED]');

    expect(fn () => unserialize(serialize($rotation)))->toThrow(LogicException::class);
});
