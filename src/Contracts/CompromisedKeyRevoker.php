<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

/**
 * @api Seam for automatic revocation when a key is reported exposed.
 *
 * Scanner adapters call this; the product persists `exposed_at`,
 * `exposure_source`, and the revocation attribution.
 */
interface CompromisedKeyRevoker
{
    public function revokeExposed(ApiKeyRecord $record, string $exposureSource, \DateTimeImmutable $exposedAt): void;
}
