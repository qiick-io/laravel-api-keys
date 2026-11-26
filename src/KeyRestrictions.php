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
     *
     * Every input is read as a JSON tree, where an object is a `stdClass` and a
     * list a PHP list, so `{}` and `[]` never stand in for each other at any
     * depth: a JSON string is decoded as is, a decoded tree (`stdClass`) is
     * taken as is, and an array a product passes is re-encoded first. An array
     * cannot tell `{}` from `[]`, so an empty section read from one is a list
     * and denies; products pass the stored string instead
     * ({@see Contracts\ApiKeyRecord::rawRestrictions()}).
     */
    public static function parse(mixed $raw): self
    {
        if ($raw === null) {
            return self::unrestricted();
        }

        $document = self::fields(self::jsonTree($raw));

        if ($document === null) {
            return self::denied();
        }

        // `v` must be the integer 1: "1" or 1.0 is an unknown version.
        if (($document['v'] ?? null) !== self::VERSION) {
            return self::denied();
        }

        if (! self::hasOnlyKeys($document, ['v', 'request', 'resources'])) {
            return self::denied();
        }

        $request = self::parseRequest($document['request'] ?? null);
        if ($request === null) {
            return self::denied();
        }

        $resources = self::parseResources($document['resources'] ?? null);
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
     * The input as a JSON tree (objects as `stdClass`), or null when it is not JSON.
     */
    private static function jsonTree(mixed $raw): mixed
    {
        // The authenticator hands over its own object decode: no need to encode and decode it again.
        // Equivalent mutant: without the shortcut the round trip yields the same tree.
        if ($raw instanceof \stdClass) {
            return $raw; // @pest-mutate-ignore
        }

        try {
            $json = is_string($raw) ? $raw : json_encode($raw, JSON_THROW_ON_ERROR);

            // Equivalent mutant: a document deeper than the schema is denied by the shape checks
            // anyway; the depth only caps decoder work on stored data.
            return json_decode($json, false, 32, JSON_THROW_ON_ERROR); // @pest-mutate-ignore: IncrementInteger,DecrementInteger
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * The fields of a JSON object, or null for anything else (a list included).
     *
     * @return array<mixed>|null
     */
    private static function fields(mixed $node): ?array
    {
        return $node instanceof \stdClass ? get_object_vars($node) : null;
    }

    /**
     * A JSON list, or null for anything else (an object included): in the tree only
     * a JSON list decodes to a PHP array.
     *
     * @return array<mixed>|null
     */
    private static function items(mixed $node): ?array
    {
        return is_array($node) ? $node : null;
    }

    /**
     * A list field of a section: absent is an empty list (unrestricted), but a
     * present JSON null, like any other non-list, is malformed. Reading it as
     * empty would skip that check.
     *
     * @param  array<mixed>  $section
     * @return array<mixed>|null
     */
    private static function listField(array $section, string $field): ?array
    {
        return array_key_exists($field, $section) ? self::items($section[$field]) : [];
    }

    /**
     * @return RequestRestrictions|null null when malformed
     */
    private static function parseRequest(mixed $raw): ?RequestRestrictions
    {
        if ($raw === null) {
            return new RequestRestrictions;
        }

        $section = self::fields($raw);

        if ($section === null || ! self::hasOnlyKeys($section, ['methods', 'route_names', 'origins', 'referrers'])) {
            return null;
        }

        $methods = self::listField($section, 'methods');
        $routeNames = self::listField($section, 'route_names');
        $origins = self::listField($section, 'origins');
        $referrers = self::listField($section, 'referrers');

        if ($methods === null || $routeNames === null || $origins === null || $referrers === null) {
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

        $list = self::items($raw);

        if ($list === null) {
            return null;
        }

        $entries = [];

        foreach ($list as $item) {
            $entry = self::fields($item);

            if ($entry === null || ! self::hasOnlyKeys($entry, ['type', 'values', 'mode'])) {
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
        $items = self::items($raw);

        if ($items === null) {
            return null;
        }

        $values = [];

        foreach ($items as $item) {
            if (! is_string($item) || $item === '') {
                return null;
            }

            $values[] = $item;
        }

        return $values;
    }
}
