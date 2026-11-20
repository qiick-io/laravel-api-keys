<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\ApiKeys\Http\BearerTokenExtractor;

mutates(BearerTokenExtractor::class);

function extractor(): BearerTokenExtractor
{
    return new BearerTokenExtractor;
}

it('extracts the Bearer token without trimming whitespace', function (): void {
    $request = Request::create('/', 'GET', server: [
        'HTTP_AUTHORIZATION' => "Bearer secret-token\n",
    ]);

    expect(extractor()->fromRequest($request))->toBe("secret-token\n");
});

it('accepts the Bearer scheme case-insensitively (RFC 7235)', function (): void {
    expect(extractor()->fromRequest(Request::create('/', 'GET', server: [
        'HTTP_AUTHORIZATION' => 'bearer lowercase-token',
    ])))->toBe('lowercase-token')
        ->and(extractor()->fromRequest(Request::create('/', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'BEARER UPPER',
        ])))->toBe('UPPER');
});

it('returns null when Authorization is missing, empty Bearer, or not Bearer', function (): void {
    expect(extractor()->fromRequest(Request::create('/', 'GET')))->toBeNull()
        ->and(extractor()->fromRequest(Request::create('/', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ',
        ])))->toBeNull()
        ->and(extractor()->fromRequest(Request::create('/', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Basic abc',
        ])))->toBeNull();
});
