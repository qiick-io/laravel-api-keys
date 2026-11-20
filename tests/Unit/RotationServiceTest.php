<?php

declare(strict_types=1);

use Qiick\ApiKeys\Rotation;
use Qiick\ApiKeys\RotationService;
use Qiick\ApiKeys\Testing\FixedEnvironment;
use Qiick\ApiKeys\Testing\FixedRandomSource;
use Qiick\ApiKeys\TokenCodec;
use Qiick\ApiKeys\TokenEnvironment;

mutates(RotationService::class);
mutates(Rotation::class);

function rotationCodec(): TokenCodec
{
    return new TokenCodec(
        productPrefix: 'tst',
        environment: new FixedEnvironment(TokenEnvironment::Test),
        random: new FixedRandomSource('fixed-seed-for-deterministic-rotation-tests!!'),
    );
}

it('normalizes invalid and negative grace hours to zero', function (): void {
    expect(RotationService::normalizeGraceHours(24))->toBe(24)
        ->and(RotationService::normalizeGraceHours(0))->toBe(0)
        ->and(RotationService::normalizeGraceHours(-1))->toBe(0)
        ->and(RotationService::normalizeGraceHours('12'))->toBe(12)
        ->and(RotationService::normalizeGraceHours('nope'))->toBe(0)
        ->and(RotationService::normalizeGraceHours(1.5))->toBe(0)
        ->and(RotationService::normalizeGraceHours(true))->toBe(0)
        ->and(RotationService::normalizeGraceHours(null))->toBe(0)
        ->and(RotationService::normalizeGraceHours([]))->toBe(0);
});

it('rotates with a grace window that preserves the previous hash', function (): void {
    $codec = rotationCodec();
    $current = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $current->keyPrefix,
        $current->keyHash,
        $now,
        24,
        $codec,
    );

    expect($rotation->newPlainText)->not->toBe($current->plainText)
        ->and($rotation->newKeyHash)->toBe(hash('sha256', $rotation->newPlainText))
        ->and($rotation->previousKeyHash)->toBe($current->keyHash)
        ->and($rotation->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-16 12:00:00')
        ->and(str_starts_with($rotation->newPlainText, $current->keyPrefix))->toBeTrue();
});

it('keeps a one-hour grace window (boundary of the zero check)', function (): void {
    $codec = rotationCodec();
    $current = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $current->keyPrefix,
        $current->keyHash,
        $now,
        1,
        $codec,
    );

    expect($rotation->previousKeyHash)->toBe($current->keyHash)
        ->and($rotation->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-15 13:00:00');
});

it('drops the previous secret when grace hours are zero', function (): void {
    $codec = rotationCodec();
    $current = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $current->keyPrefix,
        $current->keyHash,
        $now,
        0,
        $codec,
    );

    expect($rotation->previousKeyHash)->toBeNull()
        ->and($rotation->previousKeyValidUntil)->toBeNull()
        ->and($rotation->newKeyHash)->not->toBe($current->keyHash);
});

it('normalizes grace inside rotate so a negative config cannot extend the old secret', function (): void {
    $codec = rotationCodec();
    $current = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');

    $rotation = (new RotationService)->rotate(
        $current->keyPrefix,
        $current->keyHash,
        $now,
        -5,
        $codec,
    );

    expect($rotation->previousKeyHash)->toBeNull()
        ->and($rotation->previousKeyValidUntil)->toBeNull();
});

it('replaces the previous grace secret on a second rotation', function (): void {
    $codec = rotationCodec();
    $first = $codec->issue();
    $now = new DateTimeImmutable('2026-01-15 12:00:00');
    $service = new RotationService;

    $once = $service->rotate($first->keyPrefix, $first->keyHash, $now, 24, $codec);
    $twice = $service->rotate($first->keyPrefix, $once->newKeyHash, $now->modify('+1 hour'), 24, $codec);

    expect($twice->previousKeyHash)->toBe($once->newKeyHash)
        ->and($twice->previousKeyHash)->not->toBe($first->keyHash)
        ->and($twice->previousKeyValidUntil?->format('Y-m-d H:i:s'))->toBe('2026-01-16 13:00:00');
});

it('redacts plaintext and hashes in Rotation debug, JSON, and serialize output', function (): void {
    $codec = rotationCodec();
    $current = $codec->issue();
    $rotation = (new RotationService)->rotate(
        $current->keyPrefix,
        $current->keyHash,
        new DateTimeImmutable('2026-01-15 12:00:00'),
        24,
        $codec,
    );

    expect(json_encode($rotation))->not->toContain($rotation->newPlainText)
        ->and(json_encode($rotation))->toContain('[REDACTED]')
        ->and(serialize($rotation))->not->toContain($rotation->newPlainText)
        ->and($rotation->__debugInfo()['newPlainText'])->toBe('[REDACTED]');

    expect(fn () => unserialize(serialize($rotation)))->toThrow(LogicException::class);
});
