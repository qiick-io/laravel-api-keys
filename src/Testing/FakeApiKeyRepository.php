<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Testing;

use Qiick\ApiKeys\Contracts\ApiKeyRecord;
use Qiick\ApiKeys\Contracts\ApiKeyRepository;

/**
 * @api In-memory repository for authenticator tests.
 */
final class FakeApiKeyRepository implements ApiKeyRepository
{
    /** @var list<ApiKeyRecord> */
    private array $records;

    /** @var list<array{record: ApiKeyRecord, ip: ?string, usedAt: \DateTimeImmutable}> */
    public array $recordedUsages = [];

    /**
     * @param  list<ApiKeyRecord>  $records
     */
    public function __construct(array $records = [])
    {
        $this->records = $records;
    }

    /**
     * @return list<ApiKeyRecord>
     */
    public function findCandidatesByPrefix(#[\SensitiveParameter] string $keyPrefix): iterable
    {
        $matches = [];

        foreach ($this->records as $record) {
            if ($record->keyPrefix() === $keyPrefix) {
                $matches[] = $record;
            }
        }

        return $matches;
    }

    public function recordUsage(ApiKeyRecord $record, ?string $ip, \DateTimeImmutable $usedAt): void
    {
        $this->recordedUsages[] = [
            'record' => $record,
            'ip' => $ip,
            'usedAt' => $usedAt,
        ];
    }

    /**
     * @param  list<ApiKeyRecord>  $records
     */
    public function setRecords(array $records): void
    {
        $this->records = $records;
    }
}
