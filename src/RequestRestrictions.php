<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Parsed `restrictions.request` section (methods, routes, origins, referrers).
 *
 * Null/empty lists mean unrestricted for that dimension. Evaluation is fail-closed
 * for malformed input at parse time; this object only holds validated lists.
 */
final readonly class RequestRestrictions
{
    /**
     * @param  list<string>  $methods
     * @param  list<string>  $routeNames
     * @param  list<string>  $origins
     * @param  list<string>  $referrers
     */
    public function __construct(
        public array $methods = [],
        public array $routeNames = [],
        public array $origins = [],
        public array $referrers = [],
    ) {}

    public function isUnrestricted(): bool
    {
        return $this->methods === []
            && $this->routeNames === []
            && $this->origins === []
            && $this->referrers === [];
    }
}
