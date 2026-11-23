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
    public const int VERSION = 1;

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
                $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
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
        $allowedKeys = ['v' => true, 'request' => true, 'resources' => true];

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
            'methods' => true,
            'route_names' => true,
            'origins' => true,
            'referrers' => true,
        ];

        foreach (array_keys($raw) as $key) {
            if (! is_string($key) || ! array_key_exists($key, $allowedKeys)) {
                return null;
            }
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

            // Values unused; key presence is the allow-list.
            $allowedKeys = ['type' => true, 'values' => true, 'mode' => true];

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
