<?php

declare(strict_types=1);

use Qiick\ApiKeys\RequestRestrictions;

mutates(RequestRestrictions::class);

/**
 * RequestRestrictions is public API and can be built by hand, not only by
 * KeyRestrictions::parse(). It validates its own lists so the evaluator never
 * sees a pattern it would have to guess about.
 */
it('refuses a pattern list that the parser would deny', function (array $arguments): void {
    expect(fn () => new RequestRestrictions(...$arguments))
        ->toThrow(InvalidArgumentException::class);
})->with([
    'methods not a list' => [['methods' => ['get' => 'GET']]],
    'empty method' => [['methods' => ['']]],
    'non-string method' => [['methods' => [1]]],
    'empty route name' => [['routeNames' => ['']]],
    'non-string route name' => [['routeNames' => [null]]],
    'origins not a list' => [['origins' => [1 => 'https://app.example.com']]],
    'empty origin' => [['origins' => ['']]],
    'non-string origin' => [['origins' => [true]]],
    'origin not a url' => [['origins' => ['not-a-url']]],
    'origin without scheme' => [['origins' => ['//app.example.com']]],
    'origin with path' => [['origins' => ['https://app.example.com/admin']]],
    'origin with query' => [['origins' => ['https://app.example.com?x=1']]],
    'origin with fragment' => [['origins' => ['https://app.example.com#x']]],
    'origin with user' => [['origins' => ['https://user@app.example.com']]],
    'origin with password only' => [['origins' => ['https://:secret@app.example.com']]],
    'two stars in origin' => [['origins' => ['https://*.*.example.com']]],
    'mid-host star' => [['origins' => ['https://app.*.com']]],
    'star after the host' => [['origins' => ['https://app.example.com:*']]],
    'empty subdomain suffix' => [['origins' => ['https://*.']]],
    'bare star origin' => [['origins' => ['*']]],
    'empty referrer' => [['referrers' => ['']]],
    'non-string referrer' => [['referrers' => [1.5]]],
    'referrer not a url' => [['referrers' => ['not a url']]],
    'relative referrer' => [['referrers' => ['/admin']]],
    'referrer with user' => [['referrers' => ['https://user@app.example.com/']]],
    'referrer with query' => [['referrers' => ['https://app.example.com/?q=1']]],
    'referrer with fragment' => [['referrers' => ['https://app.example.com/#top']]],
    'referrer mid star' => [['referrers' => ['https://app.example.com/*/x']]],
    'referrer two stars' => [['referrers' => ['https://app.example.com/a**']]],
    'referrer subdomain wild path' => [['referrers' => ['https://*.example.com/*']]],
    'referrer star in host' => [['referrers' => ['https://foo*bar.example.com/x*']]],
    'referrer prefix without path' => [['referrers' => ['https://app.example.com*']]],
    'referrer prefix relative' => [['referrers' => ['/admin/*']]],
    'referrer prefix with user' => [['referrers' => ['https://user@app.example.com/admin*']]],
    'referrer prefix with query' => [['referrers' => ['https://app.example.com/path?q=1*']]],
    'referrer prefix with fragment' => [['referrers' => ['https://app.example.com/path#x*']]],
    'referrer prefix with padded port' => [['referrers' => ['https://app.example.com:0443/x*']]],
]);

it('accepts the patterns the evaluator understands', function (): void {
    $restrictions = new RequestRestrictions(
        methods: ['GET', 'post'],
        routeNames: ['api.*', 'api.items.index'],
        origins: ['https://app.example.com', 'https://app.example.com/', 'https://*.example.com', 'https://*.x', 'http://localhost:8080'],
        referrers: [
            'https://app.example.com',
            'https://app.example.com/exact/page',
            'https://app.example.com/*',
            'https://app.example.com:8443/admin/*',
        ],
    );

    expect($restrictions->isUnrestricted())->toBeFalse()
        ->and($restrictions->origins)->toHaveCount(5)
        ->and((new RequestRestrictions)->isUnrestricted())->toBeTrue();
});

it('is restricted as soon as any single dimension is set', function (array $arguments): void {
    expect((new RequestRestrictions(...$arguments))->isUnrestricted())->toBeFalse();
})->with([
    'methods' => [['methods' => ['GET']]],
    'route names' => [['routeNames' => ['api.*']]],
    'origins' => [['origins' => ['https://app.example.com']]],
    'referrers' => [['referrers' => ['https://app.example.com/*']]],
]);
