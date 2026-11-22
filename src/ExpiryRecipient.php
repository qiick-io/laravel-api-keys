<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Configurable roles for expiry notices (`api-keys.expiry.recipients`).
 */
enum ExpiryRecipient: string
{
    case Owner = 'owner';
    case Issuer = 'issuer';
    case Organisation = 'organisation';
}
