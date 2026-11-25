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
    // Pest gives constant declarations no line coverage; KeyRestrictionsTest pins the value.
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
            try {
                // Equivalent mutant: a document deeper than the schema is denied by the shape checks
                // anyway; the depth only caps decoder work on stored data.
                $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR); // @pest-mutate-ignore: IncrementInteger,DecrementInteger
            } catch (\JsonException) {
                return self::denied();
            }

            $raw = $decoded;
        }

        if (! is_array($raw)) {
            return self::denied();
        }

        // An empty document (`{}`, `[]`, `''`) has no `v`: only null means unrestricted.
        if (! array_key_exists('v', $raw)) {
            return self::denied();
        }

        if ($raw['v'] !== self::VERSION) {
            return self::denied();
        }

        if (! self::hasOnlyKeys($raw, ['v', 'request', 'resources'])) {
            return self::denied();
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

        if (! self::hasOnlyKeys($raw, ['methods', 'route_names', 'origins', 'referrers'])) {
            return null;
        }

        $methods = $raw['methods'] ?? [];
        $routeNames = $raw['route_names'] ?? [];
        $origins = $raw['origins'] ?? [];
        $referrers = $raw['referrers'] ?? [];

        if (! is_array($methods) || ! is_array($routeNames) || ! is_array($origins) || ! is_array($referrers)) {
            return null;
        }

        // RequestRestrictions owns the list and pattern grammar; a refusal there is a malformed document.
        try {
            return new RequestRestrictions(
                methods: $methods,
                routeNames: $routeNames,
                origins: $origins,
                referrers: $referrers,
            );
        } catch (\InvalidArgumentException) {
            return null;
        }
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

            if (! self::hasOnlyKeys($entry, ['type', 'values', 'mode'])) {
                return null;
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
     * Unknown keys make a section malformed (fail closed); integer keys never match.
     *
     * @param  array<mixed>  $section
     * @param  list<string>  $allowedKeys
     */
    private static function hasOnlyKeys(array $section, array $allowedKeys): bool
    {
        foreach (array_keys($section) as $key) {
            if (! in_array($key, $allowedKeys, true)) {
                return false;
            }
        }

        return true;
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
