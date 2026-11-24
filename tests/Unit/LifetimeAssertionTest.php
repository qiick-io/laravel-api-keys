<?php

declare(strict_types=1);

use Qiick\ApiKeys\ConfigLifetimePolicy;
use Qiick\ApiKeys\LifetimeAssertion;

mutates(LifetimeAssertion::class);

it('lets an issuance through when the policy allows its expiry', function (): void {
    $now = new DateTimeImmutable('2026-01-15T12:00:00Z');

    LifetimeAssertion::assertAllows(new ConfigLifetimePolicy(30), $now->modify('+30 days'), $now);
    LifetimeAssertion::assertAllows(new ConfigLifetimePolicy(null), null, $now);

    expect(true)->toBeTrue();
});

it('refuses an issuance whose expiry the policy does not allow', function (?string $expiresIn): void {
    $now = new DateTimeImmutable('2026-01-15T12:00:00Z');
    $expiresAt = $expiresIn === null ? null : $now->modify($expiresIn);

    expect(fn () => LifetimeAssertion::assertAllows(new ConfigLifetimePolicy(30), $expiresAt, $now))
        ->toThrow(InvalidArgumentException::class, 'The API key expiry exceeds the lifetime policy.');
})->with([
    'one second too late' => ['+30 days +1 second'],
    'no expiry under a policy' => [null],
]);
