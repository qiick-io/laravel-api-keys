<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Http;

use Illuminate\Http\Request;

/**
 * @api Recipe helper: resolve client IP for KeyContext.
 *
 * Returns `$request->ip()` only. TrustProxies must be configured correctly —
 * never pass raw X-Forwarded-For / X-Real-IP from untrusted clients.
 */
final class ClientIp
{
    public static function from(Request $request): ?string
    {
        return $request->ip();
    }
}
