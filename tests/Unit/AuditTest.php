<?php

declare(strict_types=1);

use Qiick\ApiKeys\Audit;

mutates(Audit::class);

it('merges api_key_id as a lowercase public UUID without dropping other properties', function (): void {
    $uuid = '550e8400-e29b-41d4-a716-446655440000';

    $merged = Audit::withApiKeyId(['action' => 'created'], $uuid);

    expect($merged)->toBe([
        'action' => 'created',
        'api_key_id' => $uuid,
    ]);

    $upper = Audit::withApiKeyId([], '550E8400-E29B-41D4-A716-446655440000');
    expect($upper['api_key_id'])->toBe($uuid);
});

it('allows an existing api_key_id when it equals the passed UUID (case-insensitive)', function (): void {
    $uuid = '550e8400-e29b-41d4-a716-446655440000';

    $merged = Audit::withApiKeyId(['api_key_id' => '550E8400-E29B-41D4-A716-446655440000'], $uuid);

    expect($merged['api_key_id'])->toBe($uuid);
});

it('throws when an existing api_key_id differs from the one passed', function (): void {
    $uuid = '550e8400-e29b-41d4-a716-446655440000';

    expect(fn () => Audit::withApiKeyId(['api_key_id' => 'stale'], $uuid))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId(
            ['api_key_id' => '11111111-1111-1111-1111-111111111111'],
            $uuid,
        ))->toThrow(InvalidArgumentException::class);
});

it('rejects numeric, non-UUID, and nil public ids (A16)', function (): void {
    expect(fn () => Audit::withApiKeyId([], '42'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], 'not-a-uuid'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], ''))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], '00000000-0000-0000-0000-000000000000'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], '00000000-0000-0000-0000-000000000000'))
        ->toThrow(InvalidArgumentException::class);
});
