<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Idempotency for the legacy-format T−90 warning (N2).
 *
 * {@see claim()} returns true only the first time a key is seen, so repeated
 * daily runs of `api-keys:notify-expiring` do not re-send the same warning.
 */
interface LegacyFormatWarningGate
{
    public function claim(string $idempotencyKey): bool;
}
