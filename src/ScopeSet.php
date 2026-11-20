<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\ScopeVocabulary;

/**
 * @api Fail-closed set of granted scopes.
 *
 * parseStored → empty when: not a list; empty; any element not a string;
 * any element failing PATTERN; any element not exactly in vocabulary;
 * any duplicate value; any leading/trailing/internal whitespace;
 * any case variant (e.g. Users:Read). No silent trim/lower.
 * Highest-per-resource after successful parse (write drops sibling read).
 */
final readonly class ScopeSet
{
    /**
     * @param  list<Scope>  $scopes
     */
    public function __construct(public array $scopes) {}

    public static function parseStored(mixed $stored, ScopeVocabulary $vocabulary): self
    {
        if (! is_array($stored) || $stored === [] || ! array_is_list($stored)) {
            return new self([]);
        }

        /** @var list<string> $seen */
        $seen = [];
        $parsed = [];

        foreach ($stored as $element) {
            if (! is_string($element)) {
                return new self([]);
            }

            $scope = Scope::tryFromString($element);
            if ($scope === null) {
                return new self([]);
            }

            if (! $vocabulary->contains($element)) {
                return new self([]);
            }

            if (in_array($element, $seen, true)) {
                return new self([]);
            }

            $seen[] = $element;
            $parsed[] = $scope;
        }

        return new self(self::highestPerResource($parsed));
    }

    public function allows(Scope $required): bool
    {
        foreach ($this->scopes as $scope) {
            if ($scope->satisfies($required)) {
                return true;
            }
        }

        return false;
    }

    public function isEmpty(): bool
    {
        return $this->scopes === [];
    }

    /**
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(
            static fn (Scope $scope): string => $scope->value(),
            $this->scopes,
        );
    }

    /**
     * @param  list<Scope>  $scopes
     * @return list<Scope>
     */
    private static function highestPerResource(array $scopes): array
    {
        $values = array_map(static fn (Scope $scope): string => $scope->value(), $scopes);

        return array_values(array_filter(
            $scopes,
            static function (Scope $scope) use ($values): bool {
                if ($scope->action !== 'read') {
                    return true;
                }

                return ! in_array($scope->resource.':write', $values, true);
            },
        ));
    }
}
