<?php

declare(strict_types=1);

use Qiick\ApiKeys\Audit;

mutates(Audit::class);

it('merges api_key_id as the public UUID without dropping other properties', function (): void {
    $uuid = '550e8400-e29b-41d4-a716-446655440000';

    $merged = Audit::withApiKeyId(['action' => 'created', 'api_key_id' => 'stale'], $uuid);

    expect($merged)->toBe([
        'action' => 'created',
        'api_key_id' => $uuid,
    ]);
});

it('rejects numeric and non-UUID public ids (A16)', function (): void {
    expect(fn () => Audit::withApiKeyId([], '42'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], 'not-a-uuid'))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => Audit::withApiKeyId([], ''))
        ->toThrow(InvalidArgumentException::class);
});
