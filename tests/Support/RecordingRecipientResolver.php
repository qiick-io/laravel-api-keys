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
        private bool $isYieldedOneByOne = false,
    ) {}

    public function recipientsFor(ApiKeyRecord $record, array $roles): iterable
    {
        $this->requestedRoles[] = $roles;
        $recipients = $this->recipientsByPublicId[$record->publicId()] ?? [];

        return $this->isYieldedOneByOne ? $this->yieldOneByOne($recipients) : $recipients;
    }

    /**
     * Like a product resolver that chains sources with `yield from`: every
     * recipient arrives under the key 0.
     *
     * @param  list<object>  $recipients
     * @return \Generator<int, object>
     */
    private function yieldOneByOne(array $recipients): \Generator
    {
        foreach ($recipients as $recipient) {
            yield from [$recipient];
        }
    }
}
