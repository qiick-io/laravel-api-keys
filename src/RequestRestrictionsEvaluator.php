<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Evaluates {@see RequestRestrictions} against a {@see KeyContext}.
 *
 * Fail closed: when a dimension is non-empty, the context value must match.
 * Missing context for a constrained dimension denies. Origin/referrer patterns
 * support a single trailing `*` (prefix match); otherwise exact string match.
 */
final class RequestRestrictionsEvaluator
{
    public function allows(RequestRestrictions $restrictions, KeyContext $context): bool
    {
        if ($restrictions->isUnrestricted()) {
            return true;
        }

        if ($restrictions->methods !== [] && ! $this->methodAllowed($restrictions->methods, $context->method)) {
            return false;
        }

        if ($restrictions->routeNames !== [] && ! $this->routeAllowed($restrictions->routeNames, $context->routeName)) {
            return false;
        }

        if ($restrictions->origins !== [] && ! $this->patternAllowed($restrictions->origins, $context->origin)) {
            return false;
        }

        if ($restrictions->referrers !== [] && ! $this->patternAllowed($restrictions->referrers, $context->referer)) {
            return false;
        }

        return true;
    }

    /**
     * @param  list<string>  $methods
     */
    private function methodAllowed(array $methods, ?string $method): bool
    {
        if ($method === null || $method === '') {
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
        if ($routeName === null || $routeName === '') {
            return false;
        }

        foreach ($routeNames as $pattern) {
            if ($this->matchesWildcard($pattern, $routeName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $patterns
     */
    private function patternAllowed(array $patterns, ?string $value): bool
    {
        if ($value === null || $value === '') {
            return false;
        }

        foreach ($patterns as $pattern) {
            if ($this->matchesWildcard($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    private function matchesWildcard(string $pattern, string $value): bool
    {
        if (str_ends_with($pattern, '*')) {
            $prefix = substr($pattern, 0, -1);

            return str_starts_with($value, $prefix);
        }

        return $pattern === $value;
    }
}
