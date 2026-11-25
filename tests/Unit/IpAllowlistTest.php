<?php

declare(strict_types=1);

use Qiick\ApiKeys\IpAllowlist;

mutates(IpAllowlist::class);

function allowlist(): IpAllowlist
{
    return new IpAllowlist;
}

it('allows every address when the allowlist is null or empty', function (): void {
    expect(allowlist()->allows('203.0.113.10', null))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', []))->toBeTrue()
        ->and(allowlist()->allows('2001:db8::1', null))->toBeTrue()
        // null/empty short-circuit before zone-id / parse checks
        ->and(allowlist()->allows('fe80::1%eth0', null))->toBeTrue();
});

it('denies a stored allowlist that is not a list of strings', function (): void {
    expect(allowlist()->allows('203.0.113.10', '203.0.113.10'))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['a' => '203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', [203]))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10', null]))->toBeFalse();
});

it('matches v4 and v6 addresses and CIDR via IpUtils (A9)', function (): void {
    expect(allowlist()->allows('203.0.113.10', ['203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.11', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/24']))->toBeTrue()
        ->and(allowlist()->allows('198.51.100.1', ['203.0.113.0/24']))->toBeFalse()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::1']))->toBeTrue()
        ->and(allowlist()->allows('2001:db8::2', ['2001:db8::/32']))->toBeTrue()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::/64']))->toBeTrue()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::1/128']))->toBeTrue()
        ->and(allowlist()->allows('2001:db9::1', ['2001:db8::/32']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10/32']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', ['0.0.0.0/0']))->toBeTrue();
});

it('unwraps only IPv4-mapped forms, keeping ::1 and :: as IPv6 (A9b)', function (): void {
    expect(allowlist()->allows('::ffff:203.0.113.10', ['203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', ['::ffff:203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('::ffff:203.0.113.10', ['203.0.113.0/24']))->toBeTrue()
        ->and(allowlist()->allows('::ffff:203.0.113.10', ['198.51.100.0/24']))->toBeFalse()
        // IPv4-compatible must NOT unwrap: ::1 stays loopback IPv6.
        ->and(allowlist()->allows('::1', ['::1']))->toBeTrue()
        ->and(allowlist()->allows('::1', ['0.0.0.1']))->toBeFalse()
        ->and(allowlist()->allows('0.0.0.1', ['::1']))->toBeFalse()
        ->and(allowlist()->allows('::', ['::']))->toBeTrue()
        ->and(allowlist()->allows('0.0.0.0', ['::']))->toBeFalse()
        ->and(allowlist()->allows('::', ['0.0.0.0']))->toBeFalse()
        // Deprecated compatible form is not unwrapped to dotted IPv4.
        ->and(allowlist()->allows('::203.0.113.10', ['203.0.113.10']))->toBeFalse();
});

it('rewrites mapped CIDR prefixes (prefix−96) and denies prefix < 96 (A9b)', function (): void {
    // ::ffff:10.0.0.0/104 → 10.0.0.0/8
    expect(allowlist()->allows('10.0.0.5', ['::ffff:10.0.0.0/104']))->toBeTrue()
        ->and(allowlist()->allows('11.0.0.5', ['::ffff:10.0.0.0/104']))->toBeFalse()
        ->and(allowlist()->allows('10.0.0.5', ['::ffff:10.0.0.0/96']))->toBeTrue() // /96 → /0
        ->and(allowlist()->allows('10.0.0.5', ['::ffff:10.0.0.0/95']))->toBeFalse()
        // Fail-closed: a matching sibling must not salvage a mapped prefix < 96.
        ->and(allowlist()->allows('10.0.0.5', ['10.0.0.5', '::ffff:10.0.0.0/95']))->toBeFalse()
        ->and(allowlist()->allows('10.0.0.0', ['::ffff:10.0.0.0/128']))->toBeTrue() // /128 → /32
        ->and(allowlist()->allows('10.0.0.5', ['::ffff:10.0.0.0/128']))->toBeFalse();
});

it('denies zone-id client IPs and malformed addresses or entries (A9, A9b)', function (): void {
    expect(allowlist()->allows('fe80::1%eth0', ['fe80::1']))->toBeFalse()
        ->and(allowlist()->allows('fe80::1%eth0', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('not-an-ip', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['not-an-ip']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10%eth0']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/abc']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/24/extra']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['not-an-ip/24']))->toBeFalse();
});

it('fail-closes when a prefix is out of range for the address family', function (): void {
    expect(allowlist()->allows('203.0.113.10', ['203.0.113.0/33']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/99']))->toBeFalse()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::/129']))->toBeFalse()
        // Mapped with prefix that becomes > 32 after −96
        ->and(allowlist()->allows('10.0.0.5', ['::ffff:10.0.0.0/129']))->toBeFalse()
        // Fail-closed across the whole list: a valid match must not salvage a bad prefix.
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10', '203.0.113.0/33']))->toBeFalse()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::1', '2001:db8::/129']))->toBeFalse()
        ->and(allowlist()->allows('10.0.0.5', ['10.0.0.5', '::ffff:10.0.0.0/129']))->toBeFalse();
});

it('reads a zero-padded CIDR prefix as its number', function (): void {
    $allowlist = new IpAllowlist;

    // '::/00' is /0: every IPv6 address. Kept as the string "00", IpUtils would not see a zero prefix.
    expect($allowlist->allows('2001:db8::1', ['::/00']))->toBeTrue()
        ->and($allowlist->allows('fe80::1', ['::/00']))->toBeTrue()
        ->and($allowlist->allows('203.0.113.10', ['203.0.113.0/024']))->toBeTrue()
        ->and($allowlist->allows('203.0.114.10', ['203.0.113.0/024']))->toBeFalse();
});
