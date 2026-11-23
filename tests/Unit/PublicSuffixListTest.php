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
