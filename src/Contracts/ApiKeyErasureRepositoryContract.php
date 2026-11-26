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
     * Read the original owned key UUID-to-internal-ID map from the current
     * encrypted erasure request for this subject. Return an empty map when
     * there is no snapshot. Its IDs address cache entries only, including on
     * a retry after rows were deleted or anonymised.
     *
     * @return array<string, int|string>
     */
    public function keyIdsFromSnapshot(#[\SensitiveParameter] string $userPublicId): array;

    /**
     * Delete or anonymise owned credentials and scrub the subject's attribution
     * on other keys. Dry runs are read-only and predict the same counts.
     *
     * Return the identifiers of live owned credentials before deletion or
     * unlinking. Scrub matching free text even when the subject has no
     * attribution link to the row. Do not emit model events or identifying
     * diagnostics.
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
