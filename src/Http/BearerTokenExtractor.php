<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Http;

use Illuminate\Http\Request;

/**
 * @api Extract Authorization Bearer as presented — no trim.
 *
 * Whitespace / newline in the token must fail the later format check
 * (`invalid_token`), not be silently stripped before validation.
 */
final class BearerTokenExtractor
{
    public function fromRequest(Request $request): ?string
    {
        $header = $request->header('Authorization');

        if (! is_string($header) || ! str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $token = substr($header, 7);

        return $token !== '' ? $token : null;
    }
}
