<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (Laravel namespace, Fake test doubles, @api surface) are in
 * `PackageArchitectureTest.php`.
 */
return [
    'namespace' => 'Qiick\ApiKeys',

    'ignoring' => [],

    'suffixes' => [
        'Laravel' => 'ServiceProvider',
    ],
];
