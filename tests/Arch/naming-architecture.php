<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (Laravel namespace, Fake test doubles, @api surface) are in
 * `PackageArchitectureTest.php`.
 *
 * Public API names follow the binding design (not the shared Contract/Enum suffix
 * table): those design-mandated types are listed under ignoring with reasons.
 */
return [
    'namespace' => 'Qiick\ApiKeys',

    'ignoring' => [
        'Contracts' => [
            // Design §3.1: Clock, EnvironmentResolver, RandomSource (no Contract suffix).
            'Qiick\ApiKeys\Contracts\Clock',
            'Qiick\ApiKeys\Contracts\EnvironmentResolver',
            'Qiick\ApiKeys\Contracts\RandomSource',
        ],
    ],

    'suffixes' => [
        'Laravel' => 'ServiceProvider',
    ],
];
