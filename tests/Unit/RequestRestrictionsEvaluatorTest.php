<?php

declare(strict_types=1);

use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\RequestRestrictions;
use Qiick\ApiKeys\RequestRestrictionsEvaluator;

mutates(RequestRestrictionsEvaluator::class);

/**
 * The evaluator is public API: a product may build RequestRestrictions by hand
 * instead of through KeyRestrictions::parse(), so it must fail closed on its
 * own for patterns the parser would have rejected.
 */
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

it('denies an unparseable exact referrer pattern instead of matching any unparseable referer', function (string $pattern, string $referer): void {
    expect(evaluatesReferer($pattern, $referer))->toBeFalse();
})->with([
    'garbage pattern, relative referer' => ['not a url', '/relative/path'],
    'userinfo pattern, garbage referer' => ['https://user@app.example.com/', 'garbage'],
    'garbage pattern, same garbage referer' => ['not a url', 'not a url'],
]);
