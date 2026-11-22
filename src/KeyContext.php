<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Request context for authentication.
 *
 * `ip` MUST be {@see Http\ClientIp::from} / `Request::ip()` after TrustProxies
 * is configured correctly. Never pass raw X-Forwarded-For / X-Real-IP from
 * untrusted clients.
 *
 * `method`, `routeName`, `origin` and `referer` feed request restrictions.
 * Origin and Referer are client-supplied (defence in depth only).
 */
final readonly class KeyContext
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        public ?string $ip,
        public ?string $userAgent = null,
        public ?string $method = null,
        public ?string $routeName = null,
        public ?string $origin = null,
        public ?string $referer = null,
        public array $attributes = [],
    ) {}
}
