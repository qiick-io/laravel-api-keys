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

it('matches v4 and v6 addresses and CIDR via IpUtils', function (): void {
    expect(allowlist()->allows('203.0.113.10', ['203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.11', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/24']))->toBeTrue()
        ->and(allowlist()->allows('198.51.100.1', ['203.0.113.0/24']))->toBeFalse()
        ->and(allowlist()->allows('2001:db8::1', ['2001:db8::1']))->toBeTrue()
        ->and(allowlist()->allows('2001:db8::2', ['2001:db8::/32']))->toBeTrue()
        ->and(allowlist()->allows('2001:db9::1', ['2001:db8::/32']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10/32']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', ['0.0.0.0/0']))->toBeTrue();
});

it('canonicalises IPv4-mapped and IPv4-compatible forms before compare', function (): void {
    expect(allowlist()->allows('::ffff:203.0.113.10', ['203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', ['::ffff:203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('::ffff:203.0.113.10', ['203.0.113.0/24']))->toBeTrue()
        ->and(allowlist()->allows('::ffff:203.0.113.10', ['198.51.100.0/24']))->toBeFalse()
        ->and(allowlist()->allows('::203.0.113.10', ['203.0.113.10']))->toBeTrue()
        ->and(allowlist()->allows('203.0.113.10', ['::203.0.113.10']))->toBeTrue();
});

it('denies zone-id client IPs and malformed addresses or entries', function (): void {
    expect(allowlist()->allows('fe80::1%eth0', ['fe80::1']))->toBeFalse()
        ->and(allowlist()->allows('fe80::1%eth0', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('not-an-ip', ['203.0.113.10']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['not-an-ip']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.10%eth0']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/abc']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/24/extra']))->toBeFalse()
        ->and(allowlist()->allows('203.0.113.10', ['not-an-ip/24']))->toBeFalse()
        // Oversize prefix: expand succeeds, IpUtils refuses the match.
        ->and(allowlist()->allows('203.0.113.10', ['203.0.113.0/99']))->toBeFalse();
});
