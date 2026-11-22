<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;

/**
 * @api In-memory {@see LegacyFormatWarningGate} for tests.
 */
final class FakeLegacyFormatWarningGate implements LegacyFormatWarningGate
{
    /** @var array<string, true> */
    private array $claimed = [];

    public function claim(string $idempotencyKey): bool
    {
        if (isset($this->claimed[$idempotencyKey])) {
            return false;
        }

        $this->claimed[$idempotencyKey] = true;

        return true;
    }
}
