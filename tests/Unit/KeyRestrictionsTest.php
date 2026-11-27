<?php

declare(strict_types=1);

use Qiick\ApiKeys\KeyContext;
use Qiick\ApiKeys\KeyRestrictions;
use Qiick\ApiKeys\RequestRestrictions;
use Qiick\ApiKeys\RequestRestrictionsEvaluator;
use Qiick\ApiKeys\ResourceRestriction;
use Qiick\ApiKeys\ResourceRestrictions;

mutates(KeyRestrictions::class);
mutates(RequestRestrictionsEvaluator::class);
mutates(RequestRestrictions::class);
mutates(ResourceRestrictions::class);
mutates(ResourceRestriction::class);

it('treats only null as unrestricted', function (): void {
    expect(KeyRestrictions::parse(null)->isDenied)->toBeFalse()
        ->and(KeyRestrictions::parse(null)->request->isUnrestricted())->toBeTrue()
        ->and(KeyRestrictions::parse(null)->resources->isEmpty())->toBeTrue()
        ->and(KeyRestrictions::unrestricted()->isDenied)->toBeFalse()
        ->and(KeyRestrictions::denied()->isDenied)->toBeTrue();
});

it('denies a document without version 1, empty ones included', function (mixed $raw): void {
    expect(KeyRestrictions::parse($raw)->isDenied)->toBeTrue();
})->with([
    'empty array' => [[]],
    'empty string' => [''],
    'empty JSON object' => ['{}'],
    'empty JSON list' => ['[]'],
    'request without v' => ['{"request":{}}'],
    'request without v, as array' => [['request' => []]],
]);

it('parses a valid version-1 document from array and JSON string', function (): void {
    $document = [
        'v' => 1,
        'request' => [
            'methods' => ['GET', 'POST'],
            'route_names' => ['api.v1.posts.*'],
            'origins' => ['https://app.example.com'],
            'referrers' => ['https://app.example.com/*'],
        ],
        'resources' => [
            ['type' => 'collection', 'values' => ['news'], 'mode' => 'allow'],
        ],
    ];

    $fromArray = KeyRestrictions::parse($document);
    $fromJson = KeyRestrictions::parse(json_encode($document, JSON_THROW_ON_ERROR));

    expect($fromArray->isDenied)->toBeFalse()
        ->and($fromArray->request->methods)->toBe(['GET', 'POST'])
        ->and($fromArray->request->routeNames)->toBe(['api.v1.posts.*'])
        ->and($fromArray->request->origins)->toBe(['https://app.example.com'])
        ->and($fromArray->request->referrers)->toBe(['https://app.example.com/*'])
        ->and($fromArray->resources->isEmpty())->toBeFalse()
        ->and($fromArray->resources->entries)->toHaveCount(1)
        ->and($fromArray->resources->entries[0]->type)->toBe('collection')
        ->and($fromArray->resources->entries[0]->values)->toBe(['news'])
        ->and($fromArray->resources->entries[0]->mode)->toBe('allow')
        ->and($fromJson->isDenied)->toBeFalse()
        ->and($fromJson->request->methods)->toBe(['GET', 'POST']);
});

it('denies malformed top-level shapes', function (mixed $raw): void {
    expect(KeyRestrictions::parse($raw)->isDenied)->toBeTrue();
})->with([
    'integer' => [1],
    'boolean' => [true],
    'object-ish string' => ['not-json'],
    'json non-array' => ['"hello"'],
    'json number' => ['12'],
    'missing v' => [['request' => ['methods' => ['GET']]]],
    'wrong v' => [['v' => 2]],
    'v zero' => [['v' => 0]],
    'unknown key' => [['v' => 1, 'extra' => true]],
    'numeric key' => [[0 => 'x', 'v' => 1]],
]);

it('denies malformed request sections', function (mixed $request): void {
    expect(KeyRestrictions::parse(['v' => 1, 'request' => $request])->isDenied)->toBeTrue();
})->with([
    'string' => ['GET'],
    'unknown field' => [['methods' => ['GET'], 'headers' => ['X']]],
    'methods not list' => [['methods' => ['GET' => 'yes']]],
    'empty method string' => [['methods' => ['']]],
    'non-string method' => [['methods' => [1]]],
    'route empty string' => [['route_names' => ['']]],
    'origin empty string' => [['origins' => ['']]],
    'referrer empty string' => [['referrers' => ['']]],
    'methods null entry' => [['methods' => [null]]],
    'methods not an array' => [['methods' => 'GET']],
    'route names not an array' => [['route_names' => 'api.*']],
    'origins not an array' => [['origins' => 'https://app.example.com']],
    'referrers not an array' => [['referrers' => 'https://app.example.com/*']],
    'numeric key' => [[0 => ['GET']]],
]);

it('denies malformed resources sections', function (mixed $resources): void {
    expect(KeyRestrictions::parse(['v' => 1, 'resources' => $resources])->isDenied)->toBeTrue();
})->with([
    'associative with valid entries' => [[
        'named' => ['type' => 'collection', 'values' => ['a'], 'mode' => 'allow'],
    ]],
    'string' => ['news'],
    'entry not array' => [['news']],
    'unknown entry key' => [[['type' => 'collection', 'values' => ['a'], 'extra' => 1]]],
    'missing type' => [[['values' => ['a']]]],
    'missing values' => [[['type' => 'collection']]],
    'empty type' => [[['type' => '', 'values' => ['a']]]],
    'non-string type' => [[['type' => 1, 'values' => ['a']]]],
    'deny mode' => [[['type' => 'collection', 'values' => ['a'], 'mode' => 'deny']]],
    'null mode' => [[['type' => 'collection', 'values' => ['a'], 'mode' => null]]],
    'empty value string' => [[['type' => 'collection', 'values' => ['']]]],
    'values not list' => [[['type' => 'collection', 'values' => ['a' => 'b']]]],
    'values not array' => [[['type' => 'collection', 'values' => 'a']]],
]);

it('defaults resource mode to allow when omitted', function (): void {
    $parsed = KeyRestrictions::parse([
        'v' => 1,
        'resources' => [
            ['type' => 'area', 'values' => ['ops']],
        ],
    ]);

    expect($parsed->isDenied)->toBeFalse()
        ->and($parsed->resources->entries[0]->mode)->toBe('allow')
        ->and($parsed->resources->entries[0]->type)->toBe('area');
});

it('accepts request-only and resources-only documents', function (): void {
    $requestOnly = KeyRestrictions::parse([
        'v' => 1,
        'request' => ['methods' => ['HEAD']],
    ]);
    $resourcesOnly = KeyRestrictions::parse([
        'v' => 1,
        'resources' => [
            ['type' => 'path', 'values' => ['/admin'], 'mode' => 'allow'],
        ],
    ]);

    expect($requestOnly->isDenied)->toBeFalse()
        ->and($requestOnly->request->methods)->toBe(['HEAD'])
        ->and($requestOnly->resources->isEmpty())->toBeTrue()
        ->and($resourcesOnly->isDenied)->toBeFalse()
        ->and($resourcesOnly->request->isUnrestricted())->toBeTrue()
        ->and($resourcesOnly->resources->entries)->toHaveCount(1);
});

it('evaluates request restrictions fail-closed on missing context', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;
    $restricted = new RequestRestrictions(
        methods: ['POST'],
        routeNames: ['api.posts.store'],
        origins: ['https://app.example.com'],
        referrers: ['https://app.example.com/*'],
    );

    expect($evaluator->allows(new RequestRestrictions, new KeyContext(ip: null)))->toBeTrue()
        ->and($evaluator->allows($restricted, new KeyContext(ip: null)))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(ip: null, method: 'GET')))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(ip: null, method: '')))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            method: 'POST',
            routeName: 'api.posts.store',
            origin: 'https://app.example.com',
            referer: 'https://app.example.com/edit',
        )))->toBeTrue()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            method: 'post',
            routeName: 'api.posts.store',
            origin: 'https://app.example.com',
            referer: 'https://app.example.com/edit',
        )))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(methods: ['get']),
            new KeyContext(ip: null, method: 'GET'),
        ))->toBeTrue();
});

it('matches route trailing wildcards and structured origins/referrers', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;
    $restricted = new RequestRestrictions(
        routeNames: ['api.v1.*'],
        origins: ['https://app.example.com'],
        referrers: ['https://app.example.com/*'],
    );

    expect($evaluator->allows($restricted, new KeyContext(
        ip: null,
        routeName: 'api.v1.posts.index',
        origin: 'https://app.example.com',
        referer: 'https://app.example.com/posts',
    )))->toBeTrue()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            routeName: 'api.v2.posts.index',
            origin: 'https://app.example.com',
            referer: 'https://app.example.com/posts',
        )))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            routeName: 'api.v1.posts.index',
            origin: 'https://other.example.com',
            referer: 'https://app.example.com/posts',
        )))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            routeName: 'api.v1.posts.index',
            origin: 'https://app.example.com',
            referer: 'https://evil.example.com/posts',
        )))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            routeName: '',
            origin: 'https://app.example.com',
            referer: 'https://app.example.com/posts',
        )))->toBeFalse()
        ->and($evaluator->allows($restricted, new KeyContext(
            ip: null,
            routeName: null,
            origin: 'https://app.example.com',
            referer: 'https://app.example.com/posts',
        )))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://app.example.com']),
            new KeyContext(ip: null, origin: ''),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://app.example.com']),
            new KeyContext(ip: null, origin: null),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com/*']),
            new KeyContext(ip: null, referer: ''),
        ))->toBeFalse();
});

it('N4: rejects evil-suffix origin patterns and does not allow suffix hosts', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect(KeyRestrictions::parse([
        'v' => 1,
        'request' => ['origins' => ['https://app.example.com*']],
    ])->isDenied)->toBeTrue()
        ->and(KeyRestrictions::parse([
            'v' => 1,
            'request' => ['referrers' => ['https://app.example.com*']],
        ])->isDenied)->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://app.example.com']),
            new KeyContext(ip: null, origin: 'https://app.example.com.evil.com'),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://*.example.com']),
            new KeyContext(ip: null, origin: 'https://app.example.com'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://*.example.com']),
            new KeyContext(ip: null, origin: 'https://app.example.com.evil.com'),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://*.example.com']),
            new KeyContext(ip: null, origin: 'https://example.com'),
        ))->toBeFalse()
        ->and(KeyRestrictions::parse([
            'v' => 1,
            'request' => ['origins' => ['https://*.example.com']],
        ])->isDenied)->toBeFalse()
        ->and(KeyRestrictions::parse([
            'v' => 1,
            'request' => ['origins' => ['*']],
        ])->isDenied)->toBeTrue();
});

it('N4: rejects malformed origin and referrer patterns at parse time', function (array $request): void {
    expect(KeyRestrictions::parse(['v' => 1, 'request' => $request])->isDenied)->toBeTrue();
})->with([
    'two stars in origin' => [['origins' => ['https://*.*.example.com']]],
    'origin with path' => [['origins' => ['https://app.example.com/admin']]],
    'origin with query' => [['origins' => ['https://app.example.com?x=1']]],
    'origin with fragment' => [['origins' => ['https://app.example.com#x']]],
    'origin with userinfo' => [['origins' => ['https://user:pass@app.example.com']]],
    'mid-host star' => [['origins' => ['https://app.*.com']]],
    'empty subdomain suffix' => [['origins' => ['https://*.']]],
    'bare star origin' => [['origins' => ['*']]],
    'not a url' => [['origins' => ['not-a-url']]],
    'referrer mid star' => [['referrers' => ['https://app.example.com/*/x']]],
    'referrer subdomain wild path' => [['referrers' => ['https://*.example.com/*']]],
    'referrer with query' => [['referrers' => ['https://app.example.com?q=1']]],
    'referrer with userinfo' => [['referrers' => ['https://u@app.example.com/path']]],
]);

it('normalizes origin and referrer host and scheme case', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(origins: ['https://app.example.com']),
        new KeyContext(ip: null, origin: 'HTTPS://APP.EXAMPLE.COM'),
    ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['HTTPS://*.Example.COM']),
            new KeyContext(ip: null, origin: 'https://Api.Example.Com'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com/admin/*']),
            new KeyContext(ip: null, referer: 'HTTPS://APP.EXAMPLE.COM/admin/users'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com/Exact']),
            new KeyContext(ip: null, referer: 'https://APP.example.com/Exact'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com/Exact']),
            new KeyContext(ip: null, referer: 'https://app.example.com/exact'),
        ))->toBeFalse();
});

it('covers KeyRestrictions referrer-prefix denials for star host, userinfo and authority mismatch', function (): void {
    expect(KeyRestrictions::parse([
        'v' => 1,
        'request' => ['referrers' => ['https://foo*bar.example.com/x*']],
    ])->isDenied)->toBeTrue()
        ->and(KeyRestrictions::parse([
            'v' => 1,
            'request' => ['referrers' => ['https://user@app.example.com/admin*']],
        ])->isDenied)->toBeTrue()
        ->and(KeyRestrictions::parse([
            'v' => 1,
            'request' => ['referrers' => ['https://app.example.com/path?q=1*']],
        ])->isDenied)->toBeTrue();
});

it('N4: accepts exact referers, path prefixes, and ported origins', function (): void {
    expect(KeyRestrictions::parse([
        'v' => 1,
        'request' => [
            'origins' => ['https://app.example.com:8443', 'https://*.example.com'],
            'referrers' => [
                'https://app.example.com/exact',
                'https://app.example.com/*',
                'https://app.example.com:8443/admin/*',
            ],
        ],
    ])->isDenied)->toBeFalse();

    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(origins: ['https://app.example.com:8443']),
        new KeyContext(ip: null, origin: 'https://app.example.com:8443'),
    ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://app.example.com:8443']),
            new KeyContext(ip: null, origin: 'https://app.example.com'),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com:8443/admin/*']),
            new KeyContext(ip: null, referer: 'https://app.example.com:8443/admin/users'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com:8443/admin/*']),
            new KeyContext(ip: null, referer: 'https://app.example.com/admin/users'),
        ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(referrers: ['https://app.example.com/exact']),
            new KeyContext(ip: null, referer: 'https://app.example.com/exact'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://*.example.com']),
            new KeyContext(ip: null, origin: 'https://a.b.example.com'),
        ))->toBeTrue();
});

it('denies empty route names even when a star pattern would otherwise match', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(routeNames: ['*']),
        new KeyContext(ip: null, routeName: ''),
    ))->toBeFalse();
});

it('keeps route wildcard prefix length exact (substr -1, not -2)', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(routeNames: ['ab*']),
        new KeyContext(ip: null, routeName: 'a'),
    ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(routeNames: ['ab*']),
            new KeyContext(ip: null, routeName: 'ab'),
        ))->toBeTrue()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['https://app.example.com']),
            new KeyContext(ip: null, origin: 'https://app.example.com'),
        ))->toBeTrue();
});

it('pins KeyRestrictions::VERSION to 1', function (): void {
    expect(KeyRestrictions::VERSION)->toBe(1)
        ->and(KeyRestrictions::parse(['v' => KeyRestrictions::VERSION])->isDenied)->toBeFalse();
});

it('denies every nested shape it does not recognise', function (string $document): void {
    expect(KeyRestrictions::parse($document)->isDenied)->toBeTrue();
})->with([
    'request as a list' => ['{"v":1,"request":[]}'],
    'request as a string' => ['{"v":1,"request":"GET"}'],
    'methods as an object' => ['{"v":1,"request":{"methods":{}}}'],
    'methods as a numbered object' => ['{"v":1,"request":{"methods":{"0":"GET"}}}'],
    'origins as an object' => ['{"v":1,"request":{"origins":{"0":"https://app.example.com"}}}'],
    'resources as an object' => ['{"v":1,"resources":{}}'],
    'resources as a numbered object' => ['{"v":1,"resources":{"0":{"type":"collection","values":["news"]}}}'],
    'resource entry as a list' => ['{"v":1,"resources":[["collection",["news"]]]}'],
    'values as an object' => ['{"v":1,"resources":[{"type":"collection","values":{}}]}'],
    'values as a numbered object' => ['{"v":1,"resources":[{"type":"collection","values":{"0":"news"}}]}'],
    'v as a string' => ['{"v":"1"}'],
    'v as a float' => ['{"v":1.0}'],
]);

it('accepts the recognised shapes, empty sections included', function (string $document): void {
    expect(KeyRestrictions::parse($document)->isDenied)->toBeFalse();
})->with([
    'version only' => ['{"v":1}'],
    'empty request object' => ['{"v":1,"request":{}}'],
    'null sections' => ['{"v":1,"request":null,"resources":null}'],
    'empty resource list' => ['{"v":1,"resources":[]}'],
    'full document' => ['{"v":1,"request":{"methods":["GET"]},"resources":[{"type":"collection","values":["news"]}]}'],
]);

it('reads a decoded array a product passes by the same shape rules', function (): void {
    expect(KeyRestrictions::parse(['v' => 1, 'request' => ['methods' => ['GET']]])->isDenied)->toBeFalse()
        ->and(KeyRestrictions::parse(['v' => 1, 'request' => ['methods' => ['0' => 'GET', '2' => 'POST']]])->isDenied)->toBeTrue()
        // An array cannot tell {} from []: an empty section read from an array is a list, so it denies.
        ->and(KeyRestrictions::parse(['v' => 1, 'request' => []])->isDenied)->toBeTrue();
});

it('denies a JSON null string, and reads only a PHP null as unrestricted', function (): void {
    expect(KeyRestrictions::parse('null')->isDenied)->toBeTrue()
        ->and(KeyRestrictions::parse(null)->isDenied)->toBeFalse();
});

it('denies a request list field holding JSON null instead of a list', function (string $field): void {
    expect(KeyRestrictions::parse('{"v":1,"request":{"'.$field.'":null}}')->isDenied)->toBeTrue()
        // Absent, the field is unrestricted.
        ->and(KeyRestrictions::parse('{"v":1,"request":{}}')->isDenied)->toBeFalse();
})->with(['methods', 'route_names', 'origins', 'referrers']);
