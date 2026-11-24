<?php

declare(strict_types=1);

use Qiick\ApiKeys\PublicSuffixList;

mutates(PublicSuffixList::class);

it('follows the Public Suffix List rules, private section included', function (string $domain, bool $isPublicSuffix): void {
    expect(PublicSuffixList::isPublicSuffix($domain))->toBe($isPublicSuffix);
})->with([
    'top-level domain' => ['com', true],
    'unlisted top-level label (implicit *)' => ['notatld', true],
    'registrable domain' => ['example.com', false],
    'ICANN second level' => ['co.uk', true],
    'mixed case' => ['Co.UK', true],
    'below a second-level suffix' => ['example.co.uk', false],
    'private section' => ['github.io', true],
    'below a private suffix' => ['myapp.github.io', false],
    'wildcard rule *.ck' => ['foo.ck', true],
    'exception rule !www.ck' => ['www.ck', false],
    'below a wildcard match' => ['example.foo.ck', false],
    'IDN rule in punycode' => ['xn--fiqs8s', true],
]);

it('keeps multi-label IDN rules whose UTF-8 bytes include 0x85', function (): void {
    // 公司.cn: "公" is e5 85 ac, and 0x85 is a line break to a byte-wise \R.
    expect(PublicSuffixList::isPublicSuffix('xn--55qx5d.cn'))->toBeTrue()
        ->and(PublicSuffixList::isPublicSuffix('xn--55qx5d.hk'))->toBeTrue()
        ->and(PublicSuffixList::isPublicSuffix('example.xn--55qx5d.cn'))->toBeFalse();
});

it('holds only ASCII rules in the bundled snapshot', function (): void {
    $rules = require __DIR__.'/../../resources/public_suffix_list.php';
    $nonAsciiRules = array_filter(array_keys($rules), fn (string $rule): bool => preg_match('/[^\x20-\x7e]/', $rule) === 1);

    expect($nonAsciiRules)->toBe([]);
});
