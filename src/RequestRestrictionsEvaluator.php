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
        $requestOrigin = $origin === null ? null : $this->bareOrigin($origin);

        if ($requestOrigin === null) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesOriginPattern($this->validatedPattern($this->bareOrigin($pattern)), $requestOrigin)) {
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
        $requestReferer = $referer === null ? null : $this->splitUrl($referer);

        if ($requestReferer === null) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesReferrerPattern($pattern, $requestReferer)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Exact origin, or `*.example.com` on the host-label boundary.
     *
     * @param  array{scheme: string, host: string, port: int|null}  $pattern
     * @param  array{scheme: string, host: string, port: int|null}  $request
     */
    private function matchesOriginPattern(array $pattern, array $request): bool
    {
        if ($pattern['scheme'] !== $request['scheme'] || $pattern['port'] !== $request['port']) {
            return false;
        }

        if (! str_starts_with($pattern['host'], '*.')) {
            return $pattern['host'] === $request['host'];
        }

        // `*.example.com` keeps the dot: `api.example.com` matches, `example.com` and `evilexample.com` do not.
        $boundary = substr($pattern['host'], 1);

        if (! str_ends_with($request['host'], $boundary)) {
            return false;
        }

        // Every label before the boundary must be non-empty: no `.example.com`, `a..example.com`, `.a.example.com`.
        $subdomainLabels = explode('.', substr($request['host'], 0, -strlen($boundary)));

        return ! in_array('', $subdomainLabels, true);
    }

    /**
     * Exact referer, or a path prefix (`https://app.example.com/admin/*`).
     *
     * @param  array{origin: string, pathAndQuery: string}  $request
     */
    private function matchesReferrerPattern(string $pattern, array $request): bool
    {
        if (! str_ends_with($pattern, '*')) {
            return $this->validatedPattern($this->splitUrl($pattern)) === $request;
        }

        $prefix = $this->validatedPattern($this->splitUrl(substr($pattern, 0, -1)));

        return $prefix['origin'] === $request['origin']
            && str_starts_with($request['pathAndQuery'], $prefix['pathAndQuery']);
    }

    /**
     * A bare origin: scheme and host lowercased, port, at most a `/` path.
     *
     * @return array{scheme: string, host: string, port: int|null}|null
     */
    private function bareOrigin(string $url): ?array
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        if (isset($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) {
            return null;
        }

        if (($parts['path'] ?? '/') !== '/') {
            return null;
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => strtolower($parts['host']),
            'port' => $parts['port'] ?? null,
        ];
    }

    /**
     * An absolute URL as its lowercased `scheme://host[:port]` and its
     * case-sensitive path and query (the fragment never reaches a server).
     * Userinfo is refused: `https://app.example.com@evil.example/` is not
     * the app.
     *
     * @return array{origin: string, pathAndQuery: string}|null
     */
    private function splitUrl(string $url): ?array
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host']) || isset($parts['user'])) {
            return null;
        }

        $origin = strtolower($parts['scheme']).'://'.strtolower($parts['host']);

        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        $pathAndQuery = $parts['path'] ?? '';

        if (isset($parts['query'])) {
            $pathAndQuery .= '?'.$parts['query'];
        }

        return ['origin' => $origin, 'pathAndQuery' => $pathAndQuery];
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
