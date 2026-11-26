<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Events;

use Qiick\ApiKeys\Erasure\ErasureReport;

/** @api Published after commit and cache cleanup, carrying aggregate counts only. */
final readonly class SubjectErasedEvent
{
    public function __construct(public ErasureReport $report) {}
}
