<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Strict scope atom.
 *
 * PATTERN rejects any whitespace, uppercase, or non-exact match (no silent trim/lower).
 */
final readonly class Scope
{
    public const string PATTERN = '/^[a-z][a-z0-9-]*:(read|write)$/D';

    public function __construct(
        public string $resource,
        public string $action,
    ) {}

    public static function tryFromString(string $value): ?self
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            return null;
        }

        // PATTERN guarantees exactly one colon separating resource and action.
        [$resource, $action] = explode(':', $value);

        return new self($resource, $action);
    }

    public function value(): string
    {
        return $this->resource.':'.$this->action;
    }

    /**
     * write ⊇ read on the same resource; never the other way round.
     */
    public function satisfies(self $required): bool
    {
        if ($this->resource !== $required->resource) {
            return false;
        }

        if ($this->action === $required->action) {
            return true;
        }

        // Only write may stand in for read (same resource already checked).
        // After the guards above, AND→OR on this line is behaviourally equivalent.
        return $this->action === 'write' && $required->action === 'read'; // @pest-mutate-ignore BooleanAndToBooleanOr
    }
}
