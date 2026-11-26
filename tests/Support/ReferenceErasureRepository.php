<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\ApiKeys\Contracts\ApiKeyErasureRepositoryContract;
use Qiick\ApiKeys\Erasure\ApiKeysEraser;

/**
 * A product adapter over the reference schema. The fixture supplies the
 * person's principal IDs in the snapshot, as a product orchestrator would.
 */
final class ReferenceErasureRepository implements ApiKeyErasureRepositoryContract
{
    public const string TOMBSTONE_PRINCIPAL = '00000000-0000-4000-8000-000000000000';

    public function connection(): Connection
    {
        return DB::connection('api_keys_erasure');
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
        $attributed = $connection->table('api_keys')
            ->whereNotIn('id', array_values($keyIdsByPublicId))
            ->where(function ($query) use ($userId): void {
                $query->where('created_by', $userId)->orWhere('revoked_by', $userId);
            })
            ->lockForUpdate()
            ->get(['id', 'created_by', 'revoked_by']);
        $isDeleting = $mode === ApiKeysEraser::DELETE;

        if (! $isDryRun) {
            foreach ($attributed as $key) {
                $scrubbed = (string) $key->created_by === $userId ? ['created_by' => null] : [];

                if ((string) $key->revoked_by === $userId) {
                    $scrubbed += ['revoked_by' => null, 'revocation_note' => null];
                }

                $connection->table('api_keys')->where('id', $key->id)->update($scrubbed);
            }

            foreach ($keyIdsByPublicId as $keyId) {
                $key = $connection->table('api_keys')->where('id', $keyId);
                $isDeleting ? $key->delete() : $key->update($this->tombstoneValues());
            }
        }

        return [
            'deleted' => $isDeleting ? count($keyIdsByPublicId) : 0,
            'anonymised' => $attributed->count() + ($isDeleting ? 0 : count($keyIdsByPublicId)),
            'keyIdsByPublicId' => $keyIdsByPublicId,
        ];
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
