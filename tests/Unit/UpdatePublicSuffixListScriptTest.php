<?php

declare(strict_types=1);

/*
 * scripts/update-public-suffix-list.php regenerates the snapshot origin
 * wildcards are checked against: a bad input must never replace a good list.
 */
function runPublicSuffixListUpdate(string $list, string $target): int
{
    $source = tempnam(sys_get_temp_dir(), 'psl-source-');
    file_put_contents($source, $list);
    $process = proc_open(
        [PHP_BINARY, dirname(__DIR__, 2).'/scripts/update-public-suffix-list.php', $source, $target],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
    );
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    $exitCode = proc_close($process);
    unlink($source);

    return $exitCode;
}

function realisticPublicSuffixList(int $rules): string
{
    $lines = ['// ===BEGIN ICANN DOMAINS==='];

    foreach (range(1, $rules) as $index) {
        $lines[] = "suffix{$index}.example";
    }

    $lines[] = '// ===BEGIN PRIVATE DOMAINS===';
    $lines[] = 'github.io';

    return implode("\n", $lines)."\n";
}

beforeEach(function (): void {
    if (! function_exists('idn_to_ascii')) {
        $this->markTestSkipped('The update script needs ext-intl.');
    }

    $this->target = tempnam(sys_get_temp_dir(), 'psl-target-');
    file_put_contents($this->target, '<?php return ["previous" => true];');
});

afterEach(function (): void {
    @unlink($this->target);
});

it('refuses a list that is not valid UTF-8 and keeps the previous snapshot', function (): void {
    $invalidUtf8 = realisticPublicSuffixList(1500)."\xff\xfe broken\n";

    expect(runPublicSuffixListUpdate($invalidUtf8, $this->target))->not->toBe(0)
        ->and(file_get_contents($this->target))->toBe('<?php return ["previous" => true];');
});

it('refuses a list with too few rules and keeps the previous snapshot', function (int $rules): void {
    expect(runPublicSuffixListUpdate(realisticPublicSuffixList($rules), $this->target))->not->toBe(0)
        ->and(file_get_contents($this->target))->toBe('<?php return ["previous" => true];');
})->with(['empty' => [0], 'truncated' => [10]]);

it('writes a complete list', function (): void {
    expect(runPublicSuffixListUpdate(realisticPublicSuffixList(1500), $this->target))->toBe(0);

    $rules = require $this->target;

    expect($rules)->toHaveKey('github.io')
        ->and(count($rules))->toBe(1501);
});
