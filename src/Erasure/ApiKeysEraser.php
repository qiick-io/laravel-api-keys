<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Erasure;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Qiick\ApiKeys\Contracts\ApiKeyErasureRepositoryContract;
use Qiick\ApiKeys\Events\SubjectErasedEvent;
use Qiick\ApiKeys\LegacyCutoff;
use Qiick\ApiKeys\RateLimitDecision;
use RuntimeException;
use Throwable;

/** @api Fleet erasure for credentials persisted through the product repository. */
final class ApiKeysEraser
{
    public const string DELETE = 'delete';

    public const string ANONYMISE = 'anonymise';

    public function __construct(private readonly ApiKeyErasureRepositoryContract $repository) {}

    /**
     * @param  list<string>  $publicIds
     * @param  list<string>  $identifiers
     *
     * @throws InvalidArgumentException
     * @throws OrganisationScopeUnsupportedException
     */
    public function erase(
        #[\SensitiveParameter] string $userId,
        #[\SensitiveParameter] string $userPublicId,
        #[\SensitiveParameter] string $mode,
        #[\SensitiveParameter] array $publicIds = [],
        #[\SensitiveParameter] array $identifiers = [],
        #[\SensitiveParameter] ?string $organisationId = null,
        bool $dryRun = false,
    ): ErasureReport {
        $this->validate($userPublicId, $mode, $publicIds, $identifiers);

        if ($organisationId !== null) {
            throw new OrganisationScopeUnsupportedException('The API key schema cannot filter erasures by organisation.');
        }

        $connection = $this->repository->connection();

        try {
            return $connection->transaction(function () use ($connection, $userId, $userPublicId, $mode, $publicIds, $identifiers, $dryRun): ErasureReport {
                $result = $this->repository->eraseForUser($userId, $userPublicId, $mode, $publicIds, $identifiers, $dryRun);
                $cacheKeys = $this->cacheKeys($result['keyIdsByPublicId'], $publicIds);
                $stores = [
                    'api_keys' => $this->counts($result['deleted'], $result['anonymised']),
                    ...$this->cacheCounts($cacheKeys),
                ];
                $report = new ErasureReport('qiick/laravel-api-keys', $mode, $dryRun, $stores);

                if (! $dryRun) {
                    $connection->afterCommit(function () use ($cacheKeys, $report): void {
                        $this->forget($cacheKeys);
                        event(new SubjectErasedEvent($report));
                    });
                }

                return $report;
            });
        } catch (QueryException) {
            // Laravel query errors can include bound personal values. Keep the
            // exception chain clean when the product reports the failure.
            throw new RuntimeException('API key erasure could not complete its database operation.');
        }
    }

    /**
     * @param  list<string>  $publicIds
     * @param  list<string>  $identifiers
     */
    private function validate(
        #[\SensitiveParameter] string $userPublicId,
        #[\SensitiveParameter] string $mode,
        #[\SensitiveParameter] array $publicIds,
        #[\SensitiveParameter] array $identifiers,
    ): void {
        if ($mode !== self::DELETE && $mode !== self::ANONYMISE) {
            throw new InvalidArgumentException('The erasure mode must be delete or anonymise.');
        }

        foreach ([$userPublicId, ...$publicIds] as $publicId) {
            if (! Str::isUuid($publicId)) {
                throw new InvalidArgumentException('Erasure public IDs must be UUIDs.');
            }
        }

        foreach ($identifiers as $identifier) {
            if (! is_string($identifier) || trim($identifier) === '') {
                throw new InvalidArgumentException('Erasure identifiers must be non-empty strings.');
            }
        }
    }

    /**
     * @param  array<string, int|string>  $keyIdsByPublicId
     * @param  list<string>  $publicIds
     * @return array<string, list<string>> Store names to unique cache keys.
     */
    private function cacheKeys(#[\SensitiveParameter] array $keyIdsByPublicId, #[\SensitiveParameter] array $publicIds): array
    {
        $defaultStore = Cache::getDefaultDriver();
        $configuredStore = config('api-keys.cache_store');
        $attemptStore = is_string($configuredStore) ? $configuredStore : $defaultStore;
        $keysByStore = [$attemptStore => [], $defaultStore => []];

        foreach ($keyIdsByPublicId as $keyId) {
            foreach (['', RateLimitDecision::DAY_BUCKET_SUFFIX, RateLimitDecision::MONTH_BUCKET_SUFFIX] as $suffix) {
                $bucket = RateLimitDecision::API_KEY_BUCKET_PREFIX.$keyId.$suffix;
                $keysByStore[$attemptStore][] = $bucket;
                $keysByStore[$attemptStore][] = $bucket.':timer';
            }
        }

        $legacyCutoff = LegacyCutoff::parse(config('api-keys.legacy.accept_until'));

        if ($legacyCutoff !== null) {
            foreach (array_unique([...array_keys($keyIdsByPublicId), ...$publicIds]) as $publicId) {
                $keysByStore[$defaultStore][] = LegacyCutoff::warningKey($publicId, $legacyCutoff);
            }
        }

        return $keysByStore;
    }

    /**
     * @param  array<string, list<string>>  $cacheKeys
     * @return array<string, array{deleted: int, anonymised: int, kept: int, reason: null}>
     */
    private function cacheCounts(#[\SensitiveParameter] array $cacheKeys): array
    {
        $counts = [];

        try {
            foreach ($cacheKeys as $store => $keys) {
                // The store itself does not dispatch cache hit/miss events
                // carrying the subject's cache keys.
                $cache = Cache::store($store)->getStore();
                $existing = array_filter($cache->many($keys), static fn (mixed $value): bool => $value !== null);
                $counts['cache:'.$store] = $this->counts(count($existing), 0);
            }
        } catch (Throwable) {
            throw new RuntimeException('API key erasure could not inspect its cache entries.');
        }

        return $counts;
    }

    /** @param array<string, list<string>> $cacheKeys */
    private function forget(#[\SensitiveParameter] array $cacheKeys): void
    {
        try {
            foreach ($cacheKeys as $store => $keys) {
                $cache = Cache::store($store)->getStore();

                foreach ($keys as $key) {
                    if (! $cache->forget($key) && $cache->get($key) !== null) {
                        throw new RuntimeException('A cache entry survived erasure.');
                    }

                    // A lease uses Laravel's lock backend. The count covers
                    // cache values, since a lock cannot be inspected portably.
                    if (str_starts_with($key, LegacyCutoff::WARNING_KEY_PREFIX)) {
                        Cache::lock($key.LegacyCutoff::WARNING_LEASE_SUFFIX)->forceRelease();
                    }
                }
            }
        } catch (Throwable) {
            throw new RuntimeException('API key erasure could not forget its cache entries.');
        }
    }

    /** @return array{deleted: int, anonymised: int, kept: int, reason: null} */
    private function counts(int $deleted, int $anonymised): array
    {
        return ['deleted' => $deleted, 'anonymised' => $anonymised, 'kept' => 0, 'reason' => null];
    }
}
