<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Evaluates {@see RequestRestrictions} against a {@see KeyContext}.
 *
 * Fail closed: when a dimension is non-empty, the context value must match.
 * Missing context for a constrained dimension denies.
 *
 * Route names keep a single trailing `*` as a prefix match. Origins and
 * referrers use structured patterns only (see {@see KeyRestrictions}):
 * exact origin, host-label subdomain `*.example.com` (scheme/port exact),
 * and referrer path prefix after an exact origin. Raw trailing `*` on an
 * origin (e.g. `https://app.example.com*`) is rejected at parse time.
 */
final class RequestRestrictionsEvaluator
{
    public function allows(RequestRestrictions $restrictions, KeyContext $context): bool
    {
        if ($restrictions->isUnrestricted()) {
            return true; // @pest-mutate-ignore: RemoveEarlyReturn
        }

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
        if ($method === null || $method === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return false; // @pest-mutate-ignore: FalseToTrue
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
        if ($routeName === null || $routeName === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue
        }

        foreach ($routeNames as $pattern) {
            if ($this->matchesRouteWildcard($pattern, $routeName)) {
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
        if ($origin === null || $origin === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesOriginPattern($pattern, $origin)) {
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
        if ($referer === null || $referer === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesReferrerPattern($pattern, $referer)) {
                return true;
            }
        }

        return false;
    }

    private function matchesRouteWildcard(string $pattern, string $value): bool
    {
        if (str_ends_with($pattern, '*')) {
            $prefix = substr($pattern, 0, -1);

            return str_starts_with($value, $prefix);
        }

        return $pattern === $value;
    }

    /**
     * Exact origin, or `scheme://*.example.com[:port]` on the host-label boundary.
     */
    private function matchesOriginPattern(string $pattern, string $value): bool
    {
        $patternParts = $this->parseOrigin($pattern);
        $valueParts = $this->parseOrigin($value);

        if ($patternParts === null || $valueParts === null) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,FalseToTrue
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        if ($patternParts['scheme'] !== $valueParts['scheme']) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        if ($patternParts['port'] !== $valueParts['port']) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $patternHost = $patternParts['host'];
        $valueHost = $valueParts['host'];

        if (str_starts_with($patternHost, '*.')) {
            $suffix = substr($patternHost, 2); // @pest-mutate-ignore: DecrementInteger,IncrementInteger

            if ($suffix === '' || $valueHost === $suffix) { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
                return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
            }

            $boundary = '.'.$suffix; // @pest-mutate-ignore: ConcatRemoveLeft

            if (! str_ends_with($valueHost, $boundary)) {
                return false;
            }

            $prefixLabels = substr($valueHost, 0, -strlen($boundary)); // @pest-mutate-ignore: IncrementInteger,UnwrapSubstr

            return $prefixLabels !== '' && ! str_contains($prefixLabels, '..'); // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanAndToBooleanOr
        }

        return $patternHost === $valueHost;
    }

    /**
     * Exact referer string, or path-prefix after an exact origin (`https://app.example.com/admin/*`).
     * Scheme and host are compared case-insensitively; path is case-sensitive.
     */
    private function matchesReferrerPattern(string $pattern, string $value): bool
    {
        if (! str_contains($pattern, '*')) {
            return $this->canonicalReferer($pattern) === $this->canonicalReferer($value); // @pest-mutate-ignore: IdenticalToNotIdentical
        }

        if (! str_ends_with($pattern, '*') || substr_count($pattern, '*') !== 1) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $prefix = substr($pattern, 0, -1); // @pest-mutate-ignore: IncrementInteger,UnwrapSubstr
        $originUrl = $this->originUrl($prefix);

        if ($originUrl === null) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $prefixPath = $this->pathAndQuery($prefix);

        // Path prefix requires a '/' immediately after the exact origin.
        if ($prefixPath === null || $prefixPath === '' || $prefixPath[0] !== '/') { // @pest-mutate-ignore: EmptyStringToNotEmpty,DecrementInteger,BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $valueOrigin = $this->originUrl($value);

        if ($valueOrigin === null || $valueOrigin !== $originUrl) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,NotIdenticalToIdentical
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $originParts = $this->parseOrigin($originUrl);

        if ($originParts !== null && str_starts_with($originParts['host'], '*.')) { // @pest-mutate-ignore: StrStartsWithToStrEndsWith,NotIdenticalToIdentical
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $valuePath = $this->pathAndQuery($value);

        return $valuePath !== null && str_starts_with($valuePath, $prefixPath); // @pest-mutate-ignore: BooleanAndToBooleanOr
    }

    /**
     * Lowercased scheme/host + original path/query for exact referer equality.
     */
    private function canonicalReferer(string $url): ?string
    {
        $origin = $this->originUrl($url);

        if ($origin === null) {
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        return $origin.($this->pathAndQuery($url) ?? ''); // @pest-mutate-ignore: ConcatRemoveLeft,ConcatSwitchSides,EmptyStringToNotEmpty
    }

    private function pathAndQuery(string $url): ?string
    {
        $parts = parse_url($url);

        if ($parts === false) { // @pest-mutate-ignore: FalseToTrue
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $path = $parts['path'] ?? ''; // @pest-mutate-ignore: CoalesceRemoveLeft,EmptyStringToNotEmpty

        if (isset($parts['query'])) {
            $path .= '?'.$parts['query']; // @pest-mutate-ignore: ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
        }

        return $path;
    }

    /**
     * scheme://host[:port] for an absolute URL (path/query ignored).
     */
    private function originUrl(string $url): ?string
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,FalseToTrue
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if (! is_string($parts['scheme']) || ! is_string($parts['host']) || $parts['scheme'] === '' || $parts['host'] === '') { // @pest-mutate-ignore: BooleanOrToBooleanAnd,EmptyStringToNotEmpty
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if (isset($parts['user']) || isset($parts['pass'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $origin = strtolower($parts['scheme']).'://'.strtolower($parts['host']); // @pest-mutate-ignore: ConcatRemoveLeft,ConcatSwitchSides

        if (isset($parts['port']) && is_int($parts['port'])) {
            $origin .= ':'.$parts['port']; // @pest-mutate-ignore: ConcatEqualToEqual,ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
        }

        return $origin;
    }

    /**
     * @return array{scheme: string, host: string, port: int|null}|null
     */
    private function parseOrigin(string $url): ?array
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,FalseToTrue
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if (! is_string($parts['scheme']) || ! is_string($parts['host'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if ($parts['scheme'] === '' || $parts['host'] === '') { // @pest-mutate-ignore: BooleanOrToBooleanAnd,EmptyStringToNotEmpty
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $path = $parts['path'] ?? null; // @pest-mutate-ignore: CoalesceRemoveLeft

        if ($path !== null && $path !== '' && $path !== '/') { // @pest-mutate-ignore: IdenticalToNotIdentical,NotIdenticalToIdentical,EmptyStringToNotEmpty
            return null; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => strtolower($parts['host']),
            'port' => isset($parts['port']) && is_int($parts['port']) ? $parts['port'] : null,
        ];
    }
}
