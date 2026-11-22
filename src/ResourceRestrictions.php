<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Parsed `restrictions.resources` list for the product to enforce (BOLA).
 *
 * The package never evaluates these; it only validates shape and hands them over.
 */
final readonly class ResourceRestrictions
{
    /**
     * @param  list<ResourceRestriction>  $entries
     */
    public function __construct(
        public array $entries = [],
    ) {}

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }
}
