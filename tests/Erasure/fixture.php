<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\ApiKeys\Contracts\AttemptLimiter;
use Qiick\ApiKeys\Contracts\LegacyFormatWarningGate;
use Qiick\ApiKeys\Erasure\ApiKeysEraser;
use Qiick\ApiKeys\Tests\Support\ErasureTestCase;
use Qiick\Standards\Erasure\Support\ErasureFixture;
use Qiick\Standards\Erasure\Support\ErasurePerson;

/**
 * Seeds the configured attempt store's api-key:{id} minute, :day and :month
 * counters with their :timer entries through the package limiter. The default
 * array store holds the sent marker api-keys:legacy-format-warning:{uuid}:{cutoff}
 * through the package warning gate. The IP-only 60-second failure brake has no
 * association to a user or credential.
 */
return new class implements ErasureFixture
{
    public function packageName(): string
    {
        return 'qiick/laravel-api-keys';
    }

    public function eraserClass(): string
    {
        return ApiKeysEraser::class;
    }

    public function connectionName(): ?string
    {
        return 'api_keys_erasure';
    }

    public function tables(): array
    {
        return ['api_keys' => array_fill_keys([
            'uuid', 'name', 'description', 'key_prefix', 'key_hash',
            'previous_key_prefix', 'previous_key_hash', 'oauth_client_id', 'owner_principal_id',
            'created_by', 'scopes', 'ip_allowlist', 'restrictions', 'metadata',
            'expiry_notice_claim_token', 'last_used_ip', 'last_used_user_agent', 'revoked_by', 'revocation_note',
        ], 'personal') + array_fill_keys([
            'id', 'token_version', 'hash_algorithm', 'previous_key_valid_until',
            'credential_kind', 'rate_limit_per_minute', 'rate_limit_per_day', 'rate_limit_per_month',
            'expires_at', 'expiry_notified_at', 'expiry_notice_claimed_at', 'last_used_at',
            'last_rotated_at', 'exposed_at', 'exposure_source', 'revoked_at', 'revoked_reason',
            'created_at', 'updated_at',
        ], 'other')];
    }

    public function retainedCleartextColumns(): array
    {
        return [];
    }

    public function diskPaths(ErasurePerson $person): array
    {
        return [];
    }

    public function additionalConnections(): array
    {
        return [];
    }

    public function makePerson(): ErasurePerson
    {
        $userId = DB::table('users')->insertGetId(['id' => random_int(100_000_000, 999_999_999)]);

        return ErasurePerson::fresh((string) $userId);
    }

    public function seed(ErasurePerson $person, ?string $organisationId): void
    {
        DB::table('api_keys')->insert([
            'id' => $this->keyId($person),
            'uuid' => $person->publicIds[1],
            'name' => $person->identifiers[2],
            'description' => $person->identifiers[0],
            'key_prefix' => Str::random(32),
            'key_hash' => hash('sha256', Str::random(32)),
            'previous_key_prefix' => Str::random(32),
            'previous_key_hash' => hash('sha256', Str::random(32)),
            'previous_key_valid_until' => now()->addDay(),
            'credential_kind' => 'oauth_grant',
            'oauth_client_id' => (string) Str::uuid(),
            'owner_principal_id' => $person->publicIds[0],
            'created_by' => $person->userId,
            'scopes' => json_encode([$person->identifiers[1]], JSON_THROW_ON_ERROR),
            'ip_allowlist' => json_encode([$person->otherPersonalValues[0].'/32'], JSON_THROW_ON_ERROR),
            'restrictions' => json_encode(['v' => 1, 'request' => ['route_names' => [$person->identifiers[1]]]], JSON_THROW_ON_ERROR),
            'metadata' => json_encode(['labels' => [$person->identifiers[1]]], JSON_THROW_ON_ERROR),
            'expiry_notice_claim_token' => Str::random(64),
            'last_used_ip' => $person->otherPersonalValues[0],
            'last_used_user_agent' => $person->otherPersonalValues[1],
            'revoked_by' => $person->userId,
            'revocation_note' => $person->identifiers[0],
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $limiter = app(AttemptLimiter::class);
        foreach ($this->attemptKeys($person) as $key) {
            $limiter->hit($key, 3600);
        }

        $gate = app(LegacyFormatWarningGate::class);
        $marker = $this->warningKey($person);
        $lease = $gate->claim($marker, 900);
        $gate->markSent($marker, $lease ?? throw new LogicException('Expected a fresh warning lease.'));
    }

    public function supportsOrganisationScope(): bool
    {
        return false;
    }

    public function organisationScopedTables(): array
    {
        return [];
    }

    public function cacheKeys(ErasurePerson $person): array
    {
        $keys = ['array' => [$this->warningKey($person)]];
        foreach ($this->attemptKeys($person) as $key) {
            $keys[config('api-keys.cache_store')][] = $key;
            $keys[config('api-keys.cache_store')][] = $key.':timer';
        }

        return $keys;
    }

    public function call(Closure $erase): object
    {
        return $erase();
    }

    /** @return list<string> */
    private function attemptKeys(ErasurePerson $person): array
    {
        $base = 'api-key:'.$this->keyId($person);

        return [$base, $base.':day', $base.':month'];
    }

    private function keyId(ErasurePerson $person): int
    {
        return (int) $person->userId + 1_000_000;
    }

    private function warningKey(ErasurePerson $person): string
    {
        return 'api-keys:legacy-format-warning:'.$person->publicIds[1].':'.ErasureTestCase::LEGACY_CUTOFF;
    }
};
