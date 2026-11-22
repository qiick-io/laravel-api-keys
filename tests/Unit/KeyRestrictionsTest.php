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

it('treats null and empty JSON as unrestricted', function (): void {
    expect(KeyRestrictions::parse(null)->isDenied)->toBeFalse()
        ->and(KeyRestrictions::parse(null)->request->isUnrestricted())->toBeTrue()
        ->and(KeyRestrictions::parse(null)->resources->isEmpty())->toBeTrue()
        ->and(KeyRestrictions::parse('')->isDenied)->toBeFalse()
        ->and(KeyRestrictions::parse([])->isDenied)->toBeFalse()
        ->and(KeyRestrictions::unrestricted()->isDenied)->toBeFalse()
        ->and(KeyRestrictions::denied()->isDenied)->toBeTrue();
});

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

it('matches trailing wildcards on routes, origins and referrers', function (): void {
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

it('denies empty route names even when a star pattern would otherwise match', function (): void {
    $evaluator = new RequestRestrictionsEvaluator;

    expect($evaluator->allows(
        new RequestRestrictions(routeNames: ['*']),
        new KeyContext(ip: null, routeName: ''),
    ))->toBeFalse()
        ->and($evaluator->allows(
            new RequestRestrictions(origins: ['*']),
            new KeyContext(ip: null, origin: ''),
        ))->toBeFalse();
});

it('keeps wildcard prefix length exact (substr -1, not -2)', function (): void {
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
