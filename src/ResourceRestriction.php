<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api One entry from `restrictions.resources` (product-enforced).
 *
 * `type` is an opaque product string. Version 1 accepts only `mode = allow`.
 */
final readonly class ResourceRestriction
{
    /**
     * @param  list<string>  $values
     */
    public function __construct(
        public string $type,
        public array $values,
        public string $mode = 'allow',
    ) {}
}
