<?php

declare(strict_types=1);

use Qiick\ApiKeys\LegacyCutoff;

mutates(LegacyCutoff::class);

it('reads an unset cut-off as none', function (mixed $configured): void {
    expect(LegacyCutoff::parse($configured))->toBeNull();
})->with([null, '']);

it('parses an absolute timestamp with an offset or UTC Z', function (string $configured, string $expected): void {
    expect(LegacyCutoff::parse($configured)?->format(DateTimeInterface::ATOM))->toBe($expected);
})->with([
    'offset' => ['2027-01-01T00:00:00+02:00', '2027-01-01T00:00:00+02:00'],
    'utc offset' => ['2027-01-01T00:00:00+00:00', '2027-01-01T00:00:00+00:00'],
    'zulu' => ['2027-01-01T00:00:00Z', '2027-01-01T00:00:00+00:00'],
]);

it('refuses anything but an absolute timestamp', function (mixed $configured): void {
    expect(fn () => LegacyCutoff::parse($configured))
        ->toThrow(RuntimeException::class, 'API_KEYS_LEGACY_ACCEPT_UNTIL');
})->with([
    'relative' => ['+10 years'],
    'now' => ['now'],
    'date only' => ['2027-01-01'],
    'overflowing day' => ['2027-02-30T00:00:00+00:00'],
    'zulu overflowing day' => ['2027-02-30T00:00:00Z'],
    'no offset' => ['2027-01-01T00:00:00'],
    'lower-case z' => ['2027-01-01T00:00:00z'],
    'trailing text' => ['2027-01-01T00:00:00+00:00x'],
    'not a string' => [1798761600],
]);
