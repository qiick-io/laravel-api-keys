<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Events\LegacyTokenUsedEvent;
use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\KeyRejectionCode;

/**
 * @param  mixed  $haystack  string, array, or json_encodeable value
 */
function assertTokenAbsentFrom(mixed $haystack, string $token): void
{
    if ($token === '') {
        throw new \InvalidArgumentException('Token under assertion must not be empty.');
    }

    $encoded = is_string($haystack)
        ? $haystack
        : json_encode($haystack, JSON_THROW_ON_ERROR);

    expect($encoded)->not->toContain($token);
}

function assertInvalidToken(ApiKeyRejection $rejection): void
{
    expect($rejection->getStatusCode())->toBe(401)
        ->and($rejection->errorCode())->toBe(KeyRejectionCode::InvalidToken->value)
        ->and($rejection->render()->headers->get('WWW-Authenticate'))->toContain('invalid_token');
}

function assertInsufficientScope(ApiKeyRejection $rejection): void
{
    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe(KeyRejectionCode::InsufficientScope->value)
        ->and($rejection->render()->headers->get('WWW-Authenticate'))->toContain('insufficient_scope');
}

function assertIpNotAllowed(ApiKeyRejection $rejection): void
{
    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe(KeyRejectionCode::IpNotAllowed->value)
        ->and($rejection->render()->headers->get('WWW-Authenticate'))->toBeNull();
}

/**
 * @param  class-string  $matcherClass
 */
function assertLegacyTokenUsed(
    LegacyTokenUsedEvent $event,
    string $keyPrefix,
    string $matcherClass,
    \DateTimeImmutable $acceptUntil,
): void {
    expect($event->keyPrefix)->toBe($keyPrefix)
        ->and($event->matcherClass)->toBe($matcherClass)
        ->and($event->acceptUntil->getTimestamp())->toBe($acceptUntil->getTimestamp());
}
