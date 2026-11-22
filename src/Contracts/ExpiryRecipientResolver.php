<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Qiick\ApiKeys\ExpiryRecipient;

/**
 * @api Resolves who receives an expiry notice for a key.
 *
 * Roles come from config (`owner`, `issuer`, `organisation`); the product maps
 * them to notifiable entities.
 */
interface ExpiryRecipientResolver
{
    /**
     * @param  list<ExpiryRecipient>  $roles
     * @return iterable<object>
     */
    public function recipientsFor(ApiKeyRecord $record, array $roles): iterable;
}
