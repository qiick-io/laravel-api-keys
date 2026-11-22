<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Versioned `restrictions` JSON parsed fail-closed.
 *
 * Null/absent input → unrestricted. Malformed shape, unknown `v`, or unknown
 * keys → {@see self::denied()} so the authenticator refuses the request.
 */
final readonly class KeyRestrictions
{
    public const int VERSION = 1; // @pest-mutate-ignore: IncrementInteger,DecrementInteger

    private function __construct(
        public bool $isDenied,
        public RequestRestrictions $request,
        public ResourceRestrictions $resources,
    ) {}

    public static function unrestricted(): self
    {
        return new self(
            isDenied: false,
            request: new RequestRestrictions,
            resources: new ResourceRestrictions,
        );
    }

    public static function denied(): self
    {
        return new self(
            isDenied: true,
            request: new RequestRestrictions,
            resources: new ResourceRestrictions,
        );
    }

    /**
     * Parse stored JSON / array. Fail closed on any structural surprise.
     */
    public static function parse(mixed $raw): self
    {
        if ($raw === null) {
            return self::unrestricted();
        }

        if (is_string($raw)) {
            if ($raw === '') {
                return self::unrestricted();
            }

            try {
                $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); // @pest-mutate-ignore: IncrementInteger,DecrementInteger
            } catch (\JsonException) {
                return self::denied();
            }

            $raw = $decoded;
        }

        if (! is_array($raw)) {
            return self::denied();
        }

        if ($raw === []) {
            return self::unrestricted();
        }

        if (! array_key_exists('v', $raw)) {
            return self::denied();
        }

        if ($raw['v'] !== self::VERSION) {
            return self::denied();
        }

        // Values are unused; presence of the key is the allow-list (TrueToFalse is equivalent).
        $allowedKeys = ['v' => true, 'request' => true, 'resources' => true]; // @pest-mutate-ignore: TrueToFalse

        foreach (array_keys($raw) as $key) {
            if (! is_string($key) || ! array_key_exists($key, $allowedKeys)) {
                return self::denied();
            }
        }

        $request = self::parseRequest($raw['request'] ?? null);
        if ($request === null) {
            return self::denied();
        }

        $resources = self::parseResources($raw['resources'] ?? null);
        if ($resources === null) {
            return self::denied();
        }

        return new self(
            isDenied: false,
            request: $request,
            resources: $resources,
        );
    }

    /**
     * @return RequestRestrictions|null null when malformed
     */
    private static function parseRequest(mixed $raw): ?RequestRestrictions
    {
        if ($raw === null) {
            return new RequestRestrictions;
        }

        if (! is_array($raw)) {
            return null;
        }

        // Values unused; key presence is the allow-list.
        $allowedKeys = [
            'methods' => true, // @pest-mutate-ignore: TrueToFalse
            'route_names' => true, // @pest-mutate-ignore: TrueToFalse
            'origins' => true, // @pest-mutate-ignore: TrueToFalse
            'referrers' => true, // @pest-mutate-ignore: TrueToFalse
        ];

        foreach (array_keys($raw) as $key) {
            if (! is_string($key) || ! array_key_exists($key, $allowedKeys)) {
                return null;
            }
        }

        $methods = self::stringList($raw['methods'] ?? []);
        $routeNames = self::stringList($raw['route_names'] ?? []);
        $origins = self::originPatternList($raw['origins'] ?? []);
        $referrers = self::referrerPatternList($raw['referrers'] ?? []);

        if ($methods === null || $routeNames === null || $origins === null || $referrers === null) {
            return null;
        }

        return new RequestRestrictions(
            methods: $methods,
            routeNames: $routeNames,
            origins: $origins,
            referrers: $referrers,
        );
    }

    /**
     * Exact origin or `scheme://*.example.com[:port]`. Any other `*` is rejected.
     *
     * @return list<string>|null
     */
    private static function originPatternList(mixed $raw): ?array
    {
        $values = self::stringList($raw);

        if ($values === null) {
            return null;
        }

        foreach ($values as $pattern) {
            if (! self::isValidOriginPattern($pattern)) {
                return null;
            }
        }

        return $values;
    }

    /**
     * Exact referer, or path prefix after an exact origin (`https://app.example.com/*`).
     *
     * @return list<string>|null
     */
    private static function referrerPatternList(mixed $raw): ?array
    {
        $values = self::stringList($raw);

        if ($values === null) {
            return null;
        }

        foreach ($values as $pattern) {
            if (! self::isValidReferrerPattern($pattern)) {
                return null;
            }
        }

        return $values;
    }

    private static function isValidOriginPattern(string $pattern): bool
    {
        // >1 and >0 are equivalent: a single mid-host `*` still fails the host-shape checks below.
        if (substr_count($pattern, '*') > 1) { // @pest-mutate-ignore: IncrementInteger
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $parts = parse_url($pattern);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,FalseToTrue
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $path = $parts['path'] ?? null; // @pest-mutate-ignore: CoalesceRemoveLeft

        if ($path !== null && $path !== '' && $path !== '/') { // @pest-mutate-ignore: NotIdenticalToIdentical,EmptyStringToNotEmpty
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $host = $parts['host'];

        if (str_contains($host, '*')) {
            $suffix = substr($host, 2); // @pest-mutate-ignore: DecrementInteger,IncrementInteger

            // Host-label subdomain wildcards only: `*.example.com`.
            return str_starts_with($host, '*.')
                && $suffix !== '' // @pest-mutate-ignore: EmptyStringToNotEmpty
                && ! str_contains($suffix, '*'); // @pest-mutate-ignore: BooleanAndToBooleanOr
        }

        return ! str_contains($pattern, '*');
    }

    private static function isValidReferrerPattern(string $pattern): bool
    {
        if (! str_contains($pattern, '*')) {
            $parts = parse_url($pattern);

            // Exact referer: absolute URL with scheme+host; path allowed; no userinfo/query/fragment.
            return $parts !== false // @pest-mutate-ignore: BooleanAndToBooleanOr,FalseToTrue
                && isset($parts['scheme'], $parts['host'])
                && ! isset($parts['user'])
                && ! isset($parts['pass'])
                && ! isset($parts['query'])
                && ! isset($parts['fragment']);
        }

        if (! str_ends_with($pattern, '*') || substr_count($pattern, '*') !== 1) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $prefix = substr($pattern, 0, -1); // @pest-mutate-ignore: IncrementInteger,UnwrapSubstr
        $parts = parse_url($prefix);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,FalseToTrue
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }
        if (str_contains((string) $parts['host'], '*')) { // @pest-mutate-ignore: RemoveStringCast
            return false;
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            return false;
        }

        $origin = $parts['scheme'].'://'.$parts['host'];

        if (isset($parts['port'])) {
            $origin .= ':'.$parts['port']; // @pest-mutate-ignore: ConcatEqualToEqual,ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
        }

        if (! str_starts_with($prefix, $origin)) {
            return false;
        }

        // Require `/…` after the exact origin so `https://app.example.com*` is rejected.
        return strlen($prefix) > strlen($origin) && $prefix[strlen($origin)] === '/';
    }

    /**
     * @return ResourceRestrictions|null null when malformed
     */
    private static function parseResources(mixed $raw): ?ResourceRestrictions
    {
        if ($raw === null) {
            return new ResourceRestrictions;
        }

        if (! is_array($raw)) {
            return null;
        }

        if (! array_is_list($raw)) {
            return null;
        }

        $entries = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
                return null;
            }

            // Values unused; key presence is the allow-list.
            $allowedKeys = ['type' => true, 'values' => true, 'mode' => true]; // @pest-mutate-ignore: TrueToFalse

            foreach (array_keys($entry) as $key) {
                if (! is_string($key) || ! array_key_exists($key, $allowedKeys)) {
                    return null;
                }
            }

            if (! isset($entry['type'], $entry['values']) || ! is_string($entry['type']) || $entry['type'] === '') {
                return null;
            }

            $mode = $entry['mode'] ?? 'allow';
            if ($mode !== 'allow') {
                return null;
            }

            $values = self::stringList($entry['values']);
            if ($values === null) {
                return null;
            }

            $entries[] = new ResourceRestriction(
                type: $entry['type'],
                values: $values,
                mode: 'allow',
            );
        }

        return new ResourceRestrictions($entries);
    }

    /**
     * @return list<string>|null
     */
    private static function stringList(mixed $raw): ?array
    {
        if (! is_array($raw) || ! array_is_list($raw)) {
            return null;
        }

        $values = [];

        foreach ($raw as $item) {
            if (! is_string($item) || $item === '') {
                return null;
            }

            $values[] = $item;
        }

        return $values;
    }
}
