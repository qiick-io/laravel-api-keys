<?php

declare(strict_types=1);

use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RequestRestrictions;
use Qiick\ApiKeys\RequestRestrictionsEvaluator;

mutates(RequestRestrictionsEvaluator::class);

function evaluatesReferer(string $pattern, ?string $referer): bool
{
    return (new RequestRestrictionsEvaluator)->allows(
        new RequestRestrictions(referrers: [$pattern]),
        new KeyContext(ip: null, referer: $referer),
    );
}

function evaluatesOrigin(string $pattern, ?string $origin): bool
{
    return (new RequestRestrictionsEvaluator)->allows(
        new RequestRestrictions(origins: [$pattern]),
        new KeyContext(ip: null, origin: $origin),
    );
}

it('refuses on construction the unparseable referrer patterns that used to match any unparseable referer', function (string $pattern): void {
    // Before RequestRestrictions validated itself, 'not a url' against the referer
    // '/relative/path' canonicalised both to null and the evaluator allowed it.
    expect(fn () => new RequestRestrictions(referrers: [$pattern]))
        ->toThrow(InvalidArgumentException::class);
})->with([
    'garbage' => ['not a url'],
    'userinfo' => ['https://user@app.example.com/'],
]);

it('allows everything when no dimension is restricted', function (): void {
    expect((new RequestRestrictionsEvaluator)->allows(new RequestRestrictions, new KeyContext(ip: null)))->toBeTrue();
});

it('matches methods case-insensitively and denies a missing method', function (?string $method, bool $isAllowed): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(methods: ['get', 'POST']),
        new KeyContext(ip: null, method: $method),
    ))->toBe($isAllowed);
})->with([
    'listed, other case' => ['GET', true],
    'second entry' => ['post', true],
    'not listed' => ['DELETE', false],
    'empty' => ['', false],
    'missing' => [null, false],
]);

it('matches route names exactly or by trailing-star prefix', function (string $pattern, ?string $routeName, bool $isAllowed): void {
    expect((new RequestRestrictionsEvaluator)->allows(
        new RequestRestrictions(routeNames: ['other.route', $pattern]),
        new KeyContext(ip: null, routeName: $routeName),
    ))->toBe($isAllowed);
})->with([
    'exact' => ['api.items.index', 'api.items.index', true],
    'exact is not a prefix' => ['api.items', 'api.items.index', false],
    'prefix' => ['api.items.*', 'api.items.show', true],
    'prefix keeps the dot' => ['api.items.*', 'api.itemsx', false],
    'prefix anchors at the start' => ['api.*', 'v2.api.items', false],
    'catch-all star' => ['*', 'anything', true],
    'empty name never matches the catch-all' => ['*', '', false],
    'missing name' => ['*', null, false],
]);

it('matches exact origins on scheme, host and port', function (string $pattern, ?string $origin, bool $isAllowed): void {
    expect(evaluatesOrigin($pattern, $origin))->toBe($isAllowed);
})->with([
    'same origin' => ['https://app.example.com', 'https://app.example.com', true],
    'trailing slash on either side' => ['https://app.example.com/', 'https://app.example.com', true],
    'case-insensitive scheme and host' => ['https://app.example.com', 'HTTPS://APP.Example.COM', true],
    'other scheme' => ['https://app.example.com', 'http://app.example.com', false],
    'other host' => ['https://app.example.com', 'https://api.example.com', false],
    'explicit port vs none' => ['https://app.example.com:8443', 'https://app.example.com', false],
    'same port' => ['https://app.example.com:8443', 'https://app.example.com:8443', true],
    'other port' => ['https://app.example.com:8443', 'https://app.example.com:9443', false],
    'request origin with a path' => ['https://app.example.com', 'https://app.example.com/admin', false],
    'request origin with a query' => ['https://app.example.com', 'https://app.example.com?x=1', false],
    'request origin with a fragment' => ['https://app.example.com', 'https://app.example.com#x', false],
    'request origin with userinfo' => ['https://app.example.com', 'https://app.example.com@app.example.com', false],
    'request origin without scheme' => ['https://app.example.com', '//app.example.com', false],
    'request origin unparseable' => ['https://app.example.com', 'https://', false],
    'opaque null origin' => ['https://app.example.com', 'null', false],
    'empty origin' => ['https://app.example.com', '', false],
    'missing origin' => ['https://app.example.com', null, false],
]);

it('matches host-label origin wildcards only on a subdomain boundary', function (?string $origin, bool $isAllowed): void {
    expect(evaluatesOrigin('https://*.example.com', $origin))->toBe($isAllowed);
})->with([
    'one label' => ['https://api.example.com', true],
    'several labels' => ['https://a.b.example.com', true],
    'mixed case' => ['https://API.Example.com', true],
    'the apex itself' => ['https://example.com', false],
    'suffix without a dot' => ['https://evilexample.com', false],
    'suffix elsewhere in the host' => ['https://example.com.evil.net', false],
    'empty label' => ['https://.example.com', false],
    'double dot before the boundary' => ['https://a..example.com', false],
    'double dot inside the subdomain' => ['https://a..b.example.com', false],
    'leading dot' => ['https://.a.example.com', false],
    'other scheme' => ['http://api.example.com', false],
    'with port' => ['https://api.example.com:8443', false],
]);

it('matches exact referrers on canonical origin plus case-sensitive path and query', function (string $pattern, ?string $referer, bool $isAllowed): void {
    expect(evaluatesReferer($pattern, $referer))->toBe($isAllowed);
})->with([
    'same URL' => ['https://app.example.com/page', 'https://app.example.com/page', true],
    'host case ignored' => ['https://app.example.com/page', 'HTTPS://App.Example.com/page', true],
    'path case kept' => ['https://app.example.com/Page', 'https://app.example.com/page', false],
    'fragment ignored' => ['https://app.example.com/page', 'https://app.example.com/page#top', true],
    'query must match' => ['https://app.example.com/page', 'https://app.example.com/page?x=1', false],
    'no path vs slash' => ['https://app.example.com', 'https://app.example.com/', false],
    'no path on both sides' => ['https://app.example.com', 'https://app.example.com', true],
    'port must match' => ['https://app.example.com:8443/page', 'https://app.example.com/page', false],
    'same port' => ['https://app.example.com:8443/page', 'https://app.example.com:8443/page', true],
    'other host' => ['https://app.example.com/page', 'https://evil.example.com/page', false],
    'relative referer' => ['https://app.example.com/page', '/page', false],
    'referer with userinfo' => ['https://app.example.com/page', 'https://app.example.com@evil.example/page', false],
    'empty referer' => ['https://app.example.com/page', '', false],
    'missing referer' => ['https://app.example.com/page', null, false],
]);

it('matches referrer path prefixes after an exact origin', function (?string $referer, bool $isAllowed): void {
    expect(evaluatesReferer('https://app.example.com/admin/*', $referer))->toBe($isAllowed);
})->with([
    'the prefix itself' => ['https://app.example.com/admin/', true],
    'below the prefix' => ['https://app.example.com/admin/users?page=2', true],
    'host case ignored' => ['HTTPS://APP.EXAMPLE.COM/admin/users', true],
    'path case kept' => ['https://app.example.com/Admin/users', false],
    'prefix only at the start of the path' => ['https://app.example.com/x/admin/users', false],
    'sibling path' => ['https://app.example.com/administrator', false],
    'other origin with the same path' => ['https://evil.example.com/admin/users', false],
    'origin as a subdomain of the attacker' => ['https://app.example.com.evil.net/admin/users', false],
    'port changes the origin' => ['https://app.example.com:8443/admin/users', false],
    'userinfo' => ['https://app.example.com@evil.net/admin/users', false],
    'relative' => ['/admin/users', false],
    'missing' => [null, false],
]);

it('lets any listed pattern in a dimension match, and requires every restricted dimension', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;
    $restrictions = new RequestRestrictions(
        methods: ['GET'],
        routeNames: ['api.*'],
        origins: ['https://one.example.com', 'https://two.example.com'],
        referrers: ['https://one.example.com/*', 'https://two.example.com/*'],
    );
    $matching = new KeyContext(
        ip: null,
        method: 'GET',
        routeName: 'api.items.index',
        origin: 'https://two.example.com',
        referer: 'https://two.example.com/dashboard',
    );

    expect($evaluator->allows($restrictions, $matching))->toBeTrue()
        ->and($evaluator->allows($restrictions, new KeyContext(ip: null, method: 'POST', routeName: 'api.items.index', origin: 'https://two.example.com', referer: 'https://two.example.com/dashboard')))->toBeFalse()
        ->and($evaluator->allows($restrictions, new KeyContext(ip: null, method: 'GET', routeName: 'web.home', origin: 'https://two.example.com', referer: 'https://two.example.com/dashboard')))->toBeFalse()
        ->and($evaluator->allows($restrictions, new KeyContext(ip: null, method: 'GET', routeName: 'api.items.index', origin: 'https://three.example.com', referer: 'https://two.example.com/dashboard')))->toBeFalse()
        ->and($evaluator->allows($restrictions, new KeyContext(ip: null, method: 'GET', routeName: 'api.items.index', origin: 'https://two.example.com', referer: 'https://three.example.com/dashboard')))->toBeFalse();
});
