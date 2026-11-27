<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migrator;

/**
 * The fleet checks indexes on package-owned foreign keys. Here the host owns
 * the API key schema, so keep the package from supplying a second migration
 * path for the same table.
 */
it('leaves API key migrations to the host product', function (): void {
    expect(app(Migrator::class)->paths())->toBe([])
        ->and(glob(dirname(__DIR__, 2).'/database/migrations/*.php'))->toBe([]);
});
