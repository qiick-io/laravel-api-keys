<?php

declare(strict_types=1);

use Qiick\ApiKeys\Tests\Support\ErasureTestCase;
use Qiick\ApiKeys\Tests\Support\PackageTestCase;

// Package Pest helpers live in autoload-dev (`src/Testing/functions.php`).
// Consumer apps should require the same file from their Pest.php (not production autoload).

pest()->extend(PackageTestCase::class)->in('Feature', 'Unit');
pest()->extend(ErasureTestCase::class)->in('Erasure');
