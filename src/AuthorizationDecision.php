<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Allow/deny from {@see Contracts\KeyAuthorizer}.
 */
final readonly class AuthorizationDecision
{
    public function __construct(
        public bool $allowed,
        public ?string $denialMessage = null,
    ) {}

    public static function allow(): self
    {
        return new self(true);
    }

    public static function deny(string $message): self
    {
        return new self(false, $message);
    }
}
