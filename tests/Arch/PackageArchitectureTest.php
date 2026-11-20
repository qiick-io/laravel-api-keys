<?php

declare(strict_types=1);

/**
 * Package-only architecture rules. Naming, suffixes, strict types and readonly
 * DTOs are the shared qiick rules in NamingArchitectureTest.php (configured in
 * naming-architecture.php).
 *
 * Rules for Enums, Events and Testing grow as those namespaces appear.
 */
arch('the Laravel namespace only holds the service provider')
    ->expect('Qiick\ApiKeys\Laravel')
    ->toHaveSuffix('ServiceProvider');
