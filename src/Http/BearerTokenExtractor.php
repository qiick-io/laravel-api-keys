<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Http;

use Illuminate\Http\Request;

/**
 * @api Extract Authorization Bearer as presented — no trim.
 *
 * Scheme match is case-insensitive (RFC 7235). Whitespace / newline in the
 * token must fail the later format check (`invalid_token`), not be stripped.
 */
final class BearerTokenExtractor
{
    public function fromRequest(Request $request): ?string
    {
        $header = $request->header('Authorization');

        if (! is_string($header) || preg_match('/^Bearer\s/i', $header, $matches) !== 1) {
            return null;
        }

        // Strip only the matched scheme + separator; do not trim the token.
        $token = substr($header, strlen($matches[0]));

        return $token !== '' ? $token : null;
    }
}
