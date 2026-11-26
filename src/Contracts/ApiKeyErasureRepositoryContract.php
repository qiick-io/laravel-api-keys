<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Contracts;

use Illuminate\Database\Connection;

/**
 * @api Product-owned persistence for API key erasure. Bind it only where the
 * product's erasure orchestrator uses it. Authentication keeps its own contract.
 */
interface ApiKeyErasureRepositoryContract
{
    /** The eraser opens a transaction or savepoint on this exact connection. */
    public function connection(): Connection;

    /**
     * Delete or anonymise owned credentials and scrub the subject's attribution
     * on other keys. Dry runs are read-only and predict the same counts.
     *
     * Key identifiers refer to owned credentials before deletion or unlinking.
     * Supply the original identities on retries from the product's encrypted
     * snapshot so post-commit cache cleanup can be retried after rows are gone.
     * Do not emit model events or include personal data in diagnostics.
     *
     * @param  list<string>  $publicIds  Trusted snapshot of principal and key UUIDs.
     * @param  list<string>  $identifiers  Values to scrub from free text.
     * @return array{deleted: int, anonymised: int, keyIdsByPublicId: array<string, int|string>}
     */
    public function eraseForUser(
        string $userId,
        string $userPublicId,
        string $mode,
        array $publicIds,
        array $identifiers,
        bool $isDryRun,
    ): array;
}
