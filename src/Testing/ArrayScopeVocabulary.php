<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ScopeVocabulary;

/** @api In-memory vocabulary for tests and examples. */
final class ArrayScopeVocabulary implements ScopeVocabulary
{
    use EnsuresTestingEnvironmentTrait;

    /**
     * @param  list<string>  $scopes
     */
    public function __construct(private array $scopes)
    {
        self::ensureTestingEnvironment();
    }

    public function all(): array
    {
        return $this->scopes;
    }

    public function contains(string $value): bool
    {
        return in_array($value, $this->scopes, true);
    }
}
