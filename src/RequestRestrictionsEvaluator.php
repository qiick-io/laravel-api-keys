<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Evaluates {@see RequestRestrictions} against a {@see KeyContext}.
 *
 * Fail closed: when a dimension is non-empty, the context value must match.
 * Missing or unparseable context for a constrained dimension denies.
 *
 * Patterns arrive validated by the {@see RequestRestrictions} constructor, so
 * only the request side is parsed defensively here. Route names keep a single
 * trailing `*` as a prefix match. Origins match exactly or on a host-label
 * wildcard (`*.example.com`, scheme and port exact); referrers match exactly
 * or on a path prefix after an exact origin. Scheme and host compare
 * case-insensitively; path and query are case-sensitive.
 *
 * @phpstan-type ParsedUrl array{scheme: string, host: string, port: int|null, path: string, query: string|null, hasFragment: bool}
 */
final class RequestRestrictionsEvaluator
{
    public function allows(RequestRestrictions $restrictions, KeyContext $context): bool
    {
        if ($restrictions->methods !== [] && ! $this->methodAllowed($restrictions->methods, $context->method)) {
            return false;
        }

        if ($restrictions->routeNames !== [] && ! $this->routeAllowed($restrictions->routeNames, $context->routeName)) {
            return false;
        }

        if ($restrictions->origins !== [] && ! $this->originAllowed($restrictions->origins, $context->origin)) {
            return false;
        }

        if ($restrictions->referrers !== [] && ! $this->referrerAllowed($restrictions->referrers, $context->referer)) {
            return false;
        }

        return true;
    }

    /**
     * @param  list<string>  $methods
     */
    private function methodAllowed(array $methods, ?string $method): bool
    {
        if ($method === null) {
            return false;
        }

        $normalized = strtoupper($method);

        foreach ($methods as $allowed) {
            if (strtoupper($allowed) === $normalized) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $routeNames
     */
    private function routeAllowed(array $routeNames, ?string $routeName): bool
    {
        // An empty name must not satisfy the catch-all pattern `*`.
        if ($routeName === null || $routeName === '') {
            return false;
        }

        foreach ($routeNames as $pattern) {
            $isPrefixMatch = str_ends_with($pattern, '*')
                && str_starts_with($routeName, substr($pattern, 0, -1));

            if ($isPrefixMatch || $pattern === $routeName) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $patterns
     */
    private function originAllowed(array $patterns, ?string $origin): bool
    {
        $request = $origin === null ? null : $this->parseAbsoluteUrl($origin);

        // An Origin header is a bare origin: nothing after the host but an optional `/`.
        if ($request === null || $request['query'] !== null || $request['hasFragment'] || ! in_array($request['path'], ['', '/'], true)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesOriginPattern($this->validatedPattern($this->parseAbsoluteUrl($pattern)), $request)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $patterns
     */
    private function referrerAllowed(array $patterns, ?string $referer): bool
    {
        $request = $referer === null ? null : $this->parseAbsoluteUrl($referer);

        if ($request === null) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesReferrerPattern($pattern, $request)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Exact origin, or `*.example.com` on the host-label boundary.
     *
     * @param  ParsedUrl  $pattern
     * @param  ParsedUrl  $request
     */
    private function matchesOriginPattern(array $pattern, array $request): bool
    {
        if (! str_starts_with($pattern['host'], '*.')) {
            return $this->isSameOrigin($pattern, $request);
        }

        // `*.example.com` keeps the dot, and every label must be non-empty:
        // `api.example.com` matches; `example.com`, `evilexample.com`, `.example.com` and `a..example.com` do not.
        return $pattern['scheme'] === $request['scheme']
            && $pattern['port'] === $request['port']
            && str_ends_with($request['host'], substr($pattern['host'], 1))
            && ! in_array('', explode('.', $request['host']), true);
    }

    /**
     * Exact referer (fragment ignored), or a path prefix after an exact origin
     * (`https://app.example.com/admin/*`). Patterns never carry a query, so a
     * prefix only ever applies to the path.
     *
     * @param  ParsedUrl  $request
     */
    private function matchesReferrerPattern(string $pattern, array $request): bool
    {
        if (! str_ends_with($pattern, '*')) {
            $exact = $this->validatedPattern($this->parseAbsoluteUrl($pattern));

            return $this->isSameOrigin($exact, $request)
                && $exact['path'] === $request['path']
                && $request['query'] === null;
        }

        $prefix = $this->validatedPattern($this->parseAbsoluteUrl(substr($pattern, 0, -1)));

        return $this->isSameOrigin($prefix, $request)
            && str_starts_with($request['path'], $prefix['path']);
    }

    /**
     * @param  ParsedUrl  $first
     * @param  ParsedUrl  $second
     */
    private function isSameOrigin(array $first, array $second): bool
    {
        return $first['scheme'] === $second['scheme']
            && $first['host'] === $second['host']
            && $first['port'] === $second['port'];
    }

    /**
     * An absolute URL with scheme and host lowercased. Userinfo is refused:
     * `https://app.example.com@evil.example/` is not the app.
     *
     * @return ParsedUrl|null
     */
    private function parseAbsoluteUrl(string $url): ?array
    {
        // parse_url() returns false on a seriously malformed URL, and isset() on false is false.
        $parts = parse_url($url);

        if (! isset($parts['scheme'], $parts['host']) || isset($parts['user'])) {
            return null;
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => strtolower($parts['host']),
            'port' => $parts['port'] ?? null,
            'path' => $parts['path'] ?? '',
            'query' => $parts['query'] ?? null,
            'hasFragment' => isset($parts['fragment']),
        ];
    }

    /**
     * @template TParsed of array
     *
     * @param  TParsed|null  $parsed
     * @return TParsed
     *
     * @throws \LogicException never for a pattern that passed the RequestRestrictions constructor
     */
    private function validatedPattern(?array $parsed): array
    {
        return $parsed ?? throw new \LogicException('RequestRestrictions accepted a pattern the evaluator cannot parse.');
    }
}
