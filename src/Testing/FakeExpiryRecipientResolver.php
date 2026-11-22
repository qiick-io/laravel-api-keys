<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;

/**
 * @api Fixed recipient list for expiry-notice tests.
 */
final class FakeExpiryRecipientResolver implements ExpiryRecipientResolver
{
    /**
     * @param  list<object>  $recipients
     */
    public function __construct(
        private array $recipients = [],
    ) {}

    public function recipientsFor(ApiKeyRecord $record, array $roles): iterable
    {
        return $this->recipients;
    }
}
