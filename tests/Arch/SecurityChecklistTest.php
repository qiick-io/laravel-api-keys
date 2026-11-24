<?php

declare(strict_types=1);

/*
 * 1.0 checklist item 2: every numbered item of the design's security checklist
 * (design §6, A1–A18) has a test that names it, so the release PR can link
 * each item to its evidence.
 */
it('names every design security item in at least one test', function (string $item): void {
    $testFiles = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__), FilesystemIterator::SKIP_DOTS));
    $namingTests = 0;

    foreach ($testFiles as $testFile) {
        if (! str_ends_with((string) $testFile, 'Test.php') || str_ends_with((string) $testFile, 'SecurityChecklistTest.php')) {
            continue;
        }

        // The item id inside a test description: `(A3)`, `(A5, A5b)` or `A15: …`.
        $namingTests += preg_match_all(
            "/it\\('[^']*(?:\\(|, |')".preg_quote($item, '/').'(?:\\)|,|:)/',
            (string) file_get_contents((string) $testFile),
        );
    }

    expect($namingTests)->toBeGreaterThan(0, "No test names security item {$item}.");
})->with([
    'A1', 'A2', 'A2b', 'A3', 'A3b', 'A4', 'A5', 'A5b', 'A6', 'A7', 'A8', 'A9', 'A9b',
    'A10', 'A11', 'A12', 'A13', 'A13b', 'A14', 'A15', 'A16', 'A17', 'A18',
]);
