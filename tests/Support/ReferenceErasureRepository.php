<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\ApiKeys\Contracts\ApiKeyErasureRepositoryContract;
use Qiick\ApiKeys\Erasure\ApiKeysEraser;
use stdClass;

/**
 * A product adapter over the reference schema. The fixture supplies the
 * person's principal IDs in the snapshot, as a product orchestrator would.
 */
final class ReferenceErasureRepository implements ApiKeyErasureRepositoryContract
{
    public const string TOMBSTONE_PRINCIPAL = '00000000-0000-4000-8000-000000000000';

    /** @param array<string, array<string, int|string>> $keyIdsBySubjectPublicId  Fixture stand-in for the encrypted request. */
    public function __construct(private readonly array $keyIdsBySubjectPublicId = []) {}

    public function connection(): Connection
    {
        return DB::connection('api_keys_erasure');
    }

    public function keyIdsFromSnapshot(#[\SensitiveParameter] string $userPublicId): array
    {
        return $this->keyIdsBySubjectPublicId[$userPublicId] ?? [];
    }

    public function eraseForUser(
        string $userId,
        string $userPublicId,
        string $mode,
        array $publicIds,
        array $identifiers,
        bool $isDryRun,
    ): array {
        $connection = $this->connection();
        $owned = $connection->table('api_keys')
            ->whereIn('owner_principal_id', [$userPublicId, ...$publicIds])
            ->orWhereIn('uuid', $publicIds);
        $keyIdsByPublicId = $owned->lockForUpdate()->pluck('id', 'uuid')->all();
        // ponytail: the fixture is small enough to scan third-party rows.
        // A product with a large key table should stream its own candidates.
        $otherKeys = $connection->table('api_keys')
            ->whereNotIn('id', array_values($keyIdsByPublicId))
            ->lockForUpdate()
            ->get(['id', 'created_by', 'revoked_by', 'name', 'description', 'revocation_note', 'metadata']);
        $isDeleting = $mode === ApiKeysEraser::DELETE;
        $anonymised = 0;
        $identifierPattern = $this->identifierPattern($identifiers);

        foreach ($otherKeys as $key) {
            $scrubbed = $this->scrubbedAttribution($key, $userId, $identifierPattern);

            if ($scrubbed === []) {
                continue;
            }

            $anonymised++;

            if (! $isDryRun) {
                $connection->table('api_keys')->where('id', $key->id)->update($scrubbed);
            }
        }

        if (! $isDryRun) {
            foreach ($keyIdsByPublicId as $keyId) {
                $key = $connection->table('api_keys')->where('id', $keyId);
                $isDeleting ? $key->delete() : $key->update($this->tombstoneValues());
            }
        }

        return [
            'deleted' => $isDeleting ? count($keyIdsByPublicId) : 0,
            'anonymised' => $anonymised + ($isDeleting ? 0 : count($keyIdsByPublicId)),
            'keyIdsByPublicId' => $keyIdsByPublicId,
        ];
    }

    /** @param list<string> $identifiers */
    private function identifierPattern(array $identifiers): ?string
    {
        if ($identifiers === []) {
            return null;
        }

        // Match a full email or name before a shorter identifier inside it.
        usort($identifiers, static fn (string $left, string $right): int => strlen($right) <=> strlen($left));
        $alternatives = array_map(static fn (string $identifier): string => preg_quote($identifier, '~'), $identifiers);

        return '~\[erased\](*SKIP)(*F)|'.implode('|', $alternatives).'~iu';
    }

    /** @return array<string, string|null> Only changed columns, so repeated runs predict zero updates. */
    private function scrubbedAttribution(stdClass $key, string $userId, ?string $pattern): array
    {
        $scrubbed = (string) $key->created_by === $userId ? ['created_by' => null] : [];

        if ((string) $key->revoked_by === $userId) {
            $scrubbed += ['revoked_by' => null, 'revocation_note' => null];
        }

        if ($pattern === null) {
            return $scrubbed;
        }

        foreach (['name', 'description', 'revocation_note'] as $column) {
            if (isset($key->{$column}) && ! array_key_exists($column, $scrubbed)) {
                $redacted = $this->redactText($pattern, $key->{$column});

                if ($redacted !== $key->{$column}) {
                    $scrubbed[$column] = $redacted;
                }
            }
        }

        if ($key->metadata !== null) {
            $metadata = json_decode($key->metadata, flags: JSON_THROW_ON_ERROR);
            $redacted = $this->redactMetadata($pattern, $metadata);

            if ($redacted != $metadata) {
                $scrubbed['metadata'] = json_encode($redacted, JSON_THROW_ON_ERROR);
            }
        }

        return $scrubbed;
    }

    private function redactText(string $pattern, string $text): string
    {
        return preg_replace($pattern, '[erased]', $text) ?? throw new \RuntimeException('Erasure could not scrub free text.');
    }

    /** Preserve unrelated JSON entries and remove object properties named with personal data. */
    private function redactMetadata(string $pattern, mixed $value): mixed
    {
        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => $this->redactMetadata($pattern, $item), $value);
        }

        if ($value instanceof stdClass) {
            $scrubbed = new stdClass;

            foreach (get_object_vars($value) as $property => $item) {
                if ($this->redactText($pattern, (string) $property) === (string) $property) {
                    $scrubbed->{$property} = $this->redactMetadata($pattern, $item);
                }
            }

            return $scrubbed;
        }

        return is_string($value) ? $this->redactText($pattern, $value) : $value;
    }

    /** @return array<string, mixed> */
    private function tombstoneValues(): array
    {
        return [
            'uuid' => (string) Str::uuid(),
            'name' => 'Erased credential',
            'description' => null,
            'key_prefix' => Str::random(32),
            'key_hash' => hash('sha256', Str::random(64)),
            'previous_key_prefix' => null,
            'previous_key_hash' => null,
            'previous_key_valid_until' => null,
            'credential_kind' => 'api_key',
            'oauth_client_id' => null,
            'owner_principal_id' => self::TOMBSTONE_PRINCIPAL,
            'created_by' => null,
            'scopes' => '[]',
            'ip_allowlist' => null,
            'restrictions' => null,
            'metadata' => null,
            'expiry_notice_claimed_at' => null,
            'expiry_notice_claim_token' => null,
            'last_used_at' => null,
            'last_used_ip' => null,
            'last_used_user_agent' => null,
            'revoked_at' => now(),
            'revoked_by' => null,
            'revoked_reason' => 'owner',
            'revocation_note' => null,
        ];
    }
}
