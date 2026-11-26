<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Qiick\ApiKeys\Contracts\ApiKeyErasureRepositoryContract;

/**
 * Gives each erasure check a private product database. The database cache
 * variant uses a second private connection, like a separate cache backend.
 */
abstract class ErasureTestCase extends PackageTestCase
{
    public const string LEGACY_CUTOFF = '2038-01-01T00:00:00+00:00';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $sqlite = ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => ''];
        $app['config']->set('database.default', 'api_keys_erasure');
        $app['config']->set('database.connections.api_keys_erasure', $sqlite);
        $app['config']->set('database.connections.api_keys_erasure_cache', $sqlite);
        $app['config']->set('cache.default', 'array');
        $attemptCachePath = sys_get_temp_dir().'/api-keys-erasure-'.Str::uuid();
        $app['config']->set('cache.stores.api-key-attempts', ['driver' => 'file', 'path' => $attemptCachePath]);
        $this->beforeApplicationDestroyed(fn () => (new Filesystem)->deleteDirectory($attemptCachePath));
        $app['config']->set('cache.stores.database', [
            'driver' => 'database',
            'connection' => 'api_keys_erasure_cache',
            'table' => 'cache',
        ]);
        $app['config']->set('api-keys.cache_store', getenv('API_KEYS_ERASURE_CACHE_STORE') === 'database' ? 'database' : 'api-key-attempts');
        $app['config']->set('api-keys.legacy.accept_until', self::LEGACY_CUTOFF);
        $app->bind(ApiKeyErasureRepositoryContract::class, ReferenceErasureRepository::class);
    }

    /**
     * The reference api_keys schema, with the product's user table and its
     * principal directory represented by the fixture repository.
     */
    protected function defineDatabaseMigrations(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
        });

        Schema::create('api_keys', function (Blueprint $table): void {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->string('name');
            $table->text('description')->nullable();
            $table->string('key_prefix', 32)->unique();
            $table->string('key_hash', 64)->unique();
            $table->unsignedSmallInteger('token_version')->default(1);
            $table->string('hash_algorithm', 16)->default('sha256');
            $table->string('previous_key_prefix', 32)->nullable()->index();
            $table->string('previous_key_hash', 64)->nullable();
            $table->dateTime('previous_key_valid_until')->nullable();
            $table->string('credential_kind', 16)->default('api_key');
            $table->uuid('oauth_client_id')->nullable()->index();
            $table->uuid('owner_principal_id')->index();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->json('scopes');
            $table->json('ip_allowlist')->nullable();
            $table->json('restrictions')->nullable();
            $table->unsignedInteger('rate_limit_per_minute')->nullable();
            $table->unsignedInteger('rate_limit_per_day')->nullable();
            $table->unsignedInteger('rate_limit_per_month')->nullable();
            $table->json('metadata')->nullable();
            $table->dateTime('expires_at')->nullable()->index();
            $table->timestamp('expiry_notified_at')->nullable();
            $table->timestamp('expiry_notice_claimed_at')->nullable();
            $table->string('expiry_notice_claim_token', 64)->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->string('last_used_ip', 45)->nullable();
            $table->string('last_used_user_agent', 512)->nullable();
            $table->timestamp('last_rotated_at')->nullable();
            $table->timestamp('exposed_at')->nullable()->index();
            $table->string('exposure_source', 64)->nullable();
            $table->timestamp('revoked_at')->nullable()->index();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->string('revoked_reason', 32)->nullable();
            $table->text('revocation_note')->nullable();
            $table->timestamps();
            $table->index(['credential_kind', 'revoked_at']);
        });

        Schema::connection('api_keys_erasure_cache')->create('cache', function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->mediumText('value');
            $table->integer('expiration')->index();
        });
    }
}
