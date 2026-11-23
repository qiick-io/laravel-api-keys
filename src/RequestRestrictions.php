<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api The `restrictions.request` section: methods, route names, origins, referrers.
 *
 * An empty list leaves that dimension unrestricted. The constructor validates
 * every list, so an instance always holds patterns that
 * {@see RequestRestrictionsEvaluator} understands, whether it came from
 * {@see KeyRestrictions::parse()} or was built by a product by hand.
 *
 * Pattern grammar:
 * - origin: `scheme://host[:port]` with an optional trailing `/`, or a
 *   host-label wildcard `scheme://*.example.com[:port]` over a registrable
 *   domain (never a public suffix such as `*.com`, `*.co.uk` or `*.github.io`); no userinfo, path,
 *   query or fragment, and no other `*`;
 * - referrer: an exact absolute URL without userinfo, query or fragment, or a
 *   path prefix `scheme://host[:port]/path*` with a single trailing `*` after
 *   an exact origin.
 */
final readonly class RequestRestrictions
{
    /** @var list<string> */
    public array $methods;

    /** @var list<string> */
    public array $routeNames;

    /** @var list<string> */
    public array $origins;

    /** @var list<string> */
    public array $referrers;

    /**
     * Takes untrusted arrays (stored JSON, product code) and keeps them only
     * once validated.
     *
     * @param  array<mixed>  $methods
     * @param  array<mixed>  $routeNames
     * @param  array<mixed>  $origins
     * @param  array<mixed>  $referrers
     *
     * @throws \InvalidArgumentException when a list is not a list of non-empty
     *                                   strings, or a pattern breaks the grammar
     */
    public function __construct(
        array $methods = [],
        array $routeNames = [],
        array $origins = [],
        array $referrers = [],
    ) {
        self::assertNonEmptyStringList($methods, 'methods');
        self::assertNonEmptyStringList($routeNames, 'route_names');
        self::assertNonEmptyStringList($origins, 'origins');
        self::assertNonEmptyStringList($referrers, 'referrers');

        foreach ($origins as $origin) {
            if (! self::isValidOriginPattern($origin)) {
                throw new \InvalidArgumentException('Invalid origin pattern in request restrictions.');
            }
        }

        foreach ($referrers as $referrer) {
            if (! self::isValidReferrerPattern($referrer)) {
                throw new \InvalidArgumentException('Invalid referrer pattern in request restrictions.');
            }
        }

        $this->methods = $methods;
        $this->routeNames = $routeNames;
        $this->origins = $origins;
        $this->referrers = $referrers;
    }

    public function isUnrestricted(): bool
    {
        return $this->methods === []
            && $this->routeNames === []
            && $this->origins === []
            && $this->referrers === [];
    }

    /**
     * @param  array<mixed>  $values
     *
     * @phpstan-assert list<non-empty-string> $values
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNonEmptyStringList(array $values, string $dimension): void
    {
        if (! array_is_list($values)) {
            throw new \InvalidArgumentException("Request restriction {$dimension} must be a list.");
        }

        foreach ($values as $value) {
            if (! is_string($value) || $value === '') {
                throw new \InvalidArgumentException("Request restriction {$dimension} must hold non-empty strings.");
            }
        }
    }

    private static function isValidOriginPattern(string $pattern): bool
    {
        // parse_url() returns false on a seriously malformed URL, and isset() on false is false.
        $parts = parse_url($pattern);

        if (! isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        if (isset($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) {
            return false;
        }

        if (($parts['path'] ?? '/') !== '/') {
            return false;
        }

        $host = $parts['host'];

        // The only `*` allowed is the leading label of a host wildcard, `*.example.com`.
        if (str_starts_with($host, '*.')) {
            return substr_count($pattern, '*') === 1 && self::isWildcardableBase(substr($host, 2));
        }

        return ! str_contains($pattern, '*');
    }

    /**
     * A wildcard must sit on a registrable domain. Over a public suffix (`*.com`,
     * `*.co.uk`, `*.github.io`) anyone can register a matching origin; over an IP
     * literal (`*.0.0.1`) or a trailing dot it would never mean a real site.
     */
    private static function isWildcardableBase(string $base): bool
    {
        if ($base === '' || str_ends_with($base, '.') || preg_match('/^[0-9.]+$/D', $base) === 1) {
            return false;
        }

        return ! PublicSuffixList::isPublicSuffix($base);
    }

    private static function isValidReferrerPattern(string $pattern): bool
    {
        if (! str_ends_with($pattern, '*')) {
            $parts = parse_url($pattern);

            return isset($parts['scheme'], $parts['host'])
                && ! isset($parts['user'])
                && ! isset($parts['query'])
                && ! isset($parts['fragment'])
                && ! str_contains($pattern, '*');
        }

        $prefix = substr($pattern, 0, -1);
        $parts = parse_url($prefix);

        if (! isset($parts['scheme'], $parts['host']) || str_contains($prefix, '*')) {
            return false;
        }

        if (isset($parts['query']) || isset($parts['fragment'])) {
            return false;
        }

        $origin = $parts['scheme'].'://'.$parts['host'];

        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        // The prefix must be the origin verbatim, then `/`: this refuses userinfo
        // (`https://user@host/`), padded ports (`:0443`) and `https://host*`.
        return str_starts_with($prefix, $origin.'/');
    }
}
