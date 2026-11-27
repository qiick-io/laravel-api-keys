<?php

declare(strict_types=1);

use Qiick\ApiKeys\Events\ApiKeyAuthenticatedEvent;
use Qiick\ApiKeys\Events\LegacyTokenUsedEvent;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\Tests\Support\RegexLegacyTokenMatcher;

use function Qiick\ApiKeys\Testing\assertInsufficientScope;
use function Qiick\ApiKeys\Testing\assertInvalidToken;
use function Qiick\ApiKeys\Testing\assertIpNotAllowed;
use function Qiick\ApiKeys\Testing\assertLegacyTokenUsed;
use function Qiick\ApiKeys\Testing\assertTokenAbsentFrom;

it('assertTokenAbsentFrom rejects haystacks that still contain the token', function (): void {
    $token = 'tst_test_abcdefgh'.str_repeat('x', 32);

    assertTokenAbsentFrom(['message' => 'ok'], $token);
    assertTokenAbsentFrom('safe-string', $token);

    expect(fn () => assertTokenAbsentFrom(['leak' => $token], $token))->toThrow(Exception::class);
});

it('assert helpers pin the RFC 6750 rejection shapes', function (): void {
    assertInvalidToken(ApiKeyRejection::invalidToken());
    assertInsufficientScope(ApiKeyRejection::insufficientScope('items:read'));
    assertInsufficientScope(ApiKeyRejection::noUsableScopes());
    assertIpNotAllowed(ApiKeyRejection::ipNotAllowed());
});

it('assertLegacyTokenUsed checks the event payload', function (): void {
    $until = new DateTimeImmutable('2027-01-01T00:00:00Z');
    $event = new LegacyTokenUsedEvent('ek_ABCDEFGHI', RegexLegacyTokenMatcher::class, $until);

    assertLegacyTokenUsed($event, 'ek_ABCDEFGHI', RegexLegacyTokenMatcher::class, $until);
});

it('ApiKeyAuthenticatedEvent carries ids without a plaintext token field', function (): void {
    $event = new ApiKeyAuthenticatedEvent(
        apiKeyId: '00000000-0000-7000-8000-000000000042',
        keyPrefix: 'tst_test_abcdefgh',
        usedPreviousSecret: false,
        clientIp: '203.0.113.10',
    );

    expect($event->apiKeyId)->toBe('00000000-0000-7000-8000-000000000042')
        ->and(json_encode($event))->not->toContain('plainText')
        ->and(json_encode($event))->not->toContain('secret');
});
