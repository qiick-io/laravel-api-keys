<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Product-owned list of exact scope strings the key may hold.
 */
interface ScopeVocabulary
{
    /**
     * @return list<string>
     */
    public function all(): array;

    public function contains(string $value): bool;
}
