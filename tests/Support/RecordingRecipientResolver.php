<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ExpiryRecipientResolver;
use Qiick\ApiKeys\ExpiryRecipient;

/**
 * Test double: recipients per key public id, recording the roles it was asked for.
 */
final class RecordingRecipientResolver implements ExpiryRecipientResolver
{
    /** @var list<list<ExpiryRecipient>> */
    public array $requestedRoles = [];

    /**
     * @param  array<string, list<object>>  $recipientsByPublicId
     */
    public function __construct(
        private array $recipientsByPublicId = [],
    ) {}

    public function recipientsFor(ApiKeyRecord $record, array $roles): iterable
    {
        $this->requestedRoles[] = $roles;

        return $this->recipientsByPublicId[$record->publicId()] ?? [];
    }
}
