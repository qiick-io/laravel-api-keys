<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Optional hook after a quiet usage write (e.g. first-use side effects).
 */
interface UsageSideEffect
{
    public function afterRecorded(ApiKeyRecord $record, ?string $ip, bool $wasFirstUse): void;
}
