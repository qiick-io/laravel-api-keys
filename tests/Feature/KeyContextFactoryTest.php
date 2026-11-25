<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Qiick\ApiKeys\Http\KeyContextFactory;

mutates(KeyContextFactory::class);

it('reads the request fields the restrictions need', function (): void {
    $request = Request::create('https://api.example.com/items', 'POST', server: [
        'REMOTE_ADDR' => '203.0.113.10',
        'HTTP_USER_AGENT' => 'sdk/1.0',
        'HTTP_ORIGIN' => 'https://app.example.com',
        'HTTP_REFERER' => 'https://app.example.com/page',
    ]);
    $route = (new Route('POST', 'items', fn () => null))->name('api.items.store');
    $request->setRouteResolver(fn () => $route);

    $context = KeyContextFactory::fromRequest($request);

    expect($context->ip)->toBe('203.0.113.10')
        ->and($context->userAgent)->toBe('sdk/1.0')
        ->and($context->method)->toBe('POST')
        ->and($context->routeName)->toBe('api.items.store')
        ->and($context->origin)->toBe('https://app.example.com')
        ->and($context->referer)->toBe('https://app.example.com/page');
});

it('treats missing or empty request fields as absent', function (): void {
    $request = Request::create('https://api.example.com/items', 'GET', server: [
        'HTTP_ORIGIN' => '',
        'HTTP_REFERER' => '',
    ]);
    $request->headers->remove('User-Agent');

    $context = KeyContextFactory::fromRequest($request);

    expect($context->userAgent)->toBeNull()
        ->and($context->routeName)->toBeNull()
        ->and($context->origin)->toBeNull()
        ->and($context->referer)->toBeNull();
});

it('reads a route without a name as no route name', function (): void {
    $request = Request::create('https://api.example.com/items');
    $request->setRouteResolver(fn () => new Route('GET', 'items', fn () => null));

    expect(KeyContextFactory::fromRequest($request)->routeName)->toBeNull();
});
