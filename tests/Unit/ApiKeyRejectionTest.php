<?php

declare(strict_types=1);

use Qiick\ApiKeys\Exceptions\ApiKeyRejection;
use Qiick\ApiKeys\KeyRejectionCode;

mutates(ApiKeyRejection::class);
mutates(KeyRejectionCode::class);

it('renders invalid_token as 401 with RFC 6750 WWW-Authenticate (A11)', function (): void {
    $rejection = ApiKeyRejection::invalidToken();
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(401)
        ->and($rejection->errorCode())->toBe('invalid_token')
        ->and($response->headers->get('WWW-Authenticate'))->toBe('Bearer error="invalid_token"')
        ->and($response->getData(true))->toBe([
            'message' => 'The API key is not valid.',
            'error' => 'invalid_token',
        ]);
});

it('renders insufficient_scope with scope in body and challenge (A11)', function (): void {
    $rejection = ApiKeyRejection::insufficientScope('items:write');
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe('insufficient_scope')
        ->and($response->headers->get('WWW-Authenticate'))
        ->toBe('Bearer error="insufficient_scope", scope="items:write"')
        ->and($response->getData(true))->toBe([
            'message' => 'The API key lacks the items:write scope.',
            'error' => 'insufficient_scope',
            'scope' => 'items:write',
        ]);
});

it('renders noUsableScopes as insufficient_scope without a scope field', function (): void {
    $rejection = ApiKeyRejection::noUsableScopes();
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe('insufficient_scope')
        ->and($response->headers->get('WWW-Authenticate'))->toBe('Bearer error="insufficient_scope"')
        ->and($response->getData(true))->toBe([
            'message' => 'The API key holds no scopes.',
            'error' => 'insufficient_scope',
        ]);
});

it('renders ip_not_allowed without WWW-Authenticate (A10)', function (): void {
    $rejection = ApiKeyRejection::ipNotAllowed();
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe('ip_not_allowed')
        ->and($response->headers->get('WWW-Authenticate'))->toBeNull()
        ->and($response->getData(true))->toBe([
            'message' => 'API key is not allowed from this IP address.',
            'error' => 'ip_not_allowed',
        ]);
});

it('renders request_not_allowed without WWW-Authenticate (Q3)', function (): void {
    $rejection = ApiKeyRejection::requestNotAllowed();
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(403)
        ->and($rejection->errorCode())->toBe('request_not_allowed')
        ->and($response->headers->get('WWW-Authenticate'))->toBeNull()
        ->and($response->getData(true))->toBe([
            'message' => 'API key is not allowed for this request.',
            'error' => 'request_not_allowed',
        ]);
});

it('renders rateLimited as 429 with Retry-After and optional X-RateLimit headers', function (): void {
    $rejection = ApiKeyRejection::rateLimited(42, 60, 0, 42);
    $response = $rejection->render();

    expect($rejection->getStatusCode())->toBe(429)
        ->and($rejection->errorCode())->toBe('rate_limit_exceeded')
        ->and($response->headers->get('Retry-After'))->toBe('42')
        ->and($response->headers->get('X-RateLimit-Limit'))->toBe('60')
        ->and($response->headers->get('X-RateLimit-Remaining'))->toBe('0')
        ->and($response->headers->get('X-RateLimit-Reset'))->toBe('42')
        // Products that copy getHeaders() onto their own response (PSR-7, Octane) get strings.
        ->and($rejection->getHeaders())->toBe([
            'Retry-After' => '42',
            'X-RateLimit-Limit' => '60',
            'X-RateLimit-Remaining' => '0',
            'X-RateLimit-Reset' => '42',
        ])
        ->and($response->getData(true))->toBe([
            'message' => 'Too many requests.',
            'error' => 'rate_limit_exceeded',
        ]);
});

it('never embeds a presented token in messages, render, or debug info (A14)', function (): void {
    $secret = 'tst_live_abcdefghABCDEFGHIJKLMNOPQRSTUVWX123456';

    $paths = [
        ApiKeyRejection::invalidToken(),
        ApiKeyRejection::invalidToken('The API key has been revoked.'),
        ApiKeyRejection::insufficientScope('items:read'),
        ApiKeyRejection::noUsableScopes(),
        ApiKeyRejection::ipNotAllowed(),
        ApiKeyRejection::rateLimited(1),
    ];

    foreach ($paths as $rejection) {
        $rendered = json_encode($rejection->render()->getData(true), JSON_THROW_ON_ERROR);
        $debug = json_encode($rejection->__debugInfo(), JSON_THROW_ON_ERROR);

        expect($rejection->getMessage())->not->toContain($secret)
            ->and($rendered)->not->toContain($secret)
            ->and($debug)->not->toContain($secret)
            ->and($debug)->not->toContain('Authorization');
    }
});

it('exposes KeyRejectionCode values used by the fleet contract', function (): void {
    expect(KeyRejectionCode::InvalidToken->value)->toBe('invalid_token')
        ->and(KeyRejectionCode::InsufficientScope->value)->toBe('insufficient_scope')
        ->and(KeyRejectionCode::IpNotAllowed->value)->toBe('ip_not_allowed')
        ->and(KeyRejectionCode::RateLimitExceeded->value)->toBe('rate_limit_exceeded');
});

it('redacts debug info to status, error, message and scope only', function (): void {
    $withScope = ApiKeyRejection::insufficientScope('items:read')->__debugInfo();
    $without = ApiKeyRejection::ipNotAllowed()->__debugInfo();

    expect($withScope)->toBe([
        'status' => 403,
        'error' => 'insufficient_scope',
        'message' => 'The API key lacks the items:read scope.',
        'scope' => 'items:read',
    ])->and($without)->toBe([
        'status' => 403,
        'error' => 'ip_not_allowed',
        'message' => 'API key is not allowed from this IP address.',
        'scope' => null,
    ]);
});

it('translates messages via the translator hook but never the error code', function (): void {
    ApiKeyRejection::setTranslator(static function (string $key, array $replace): string {
        return match ($key) {
            'api_keys.invalid_token' => 'Chiave non valida.',
            'api_keys.insufficient_scope' => 'Manca lo scope :scope.',
            default => $key,
        };
    });

    try {
        $invalid = ApiKeyRejection::invalidToken();
        $scope = ApiKeyRejection::insufficientScope('items:read');

        expect($invalid->getMessage())->toBe('Chiave non valida.')
            ->and($invalid->errorCode())->toBe('invalid_token')
            ->and($scope->getMessage())->toBe('Manca lo scope items:read.')
            ->and($scope->errorCode())->toBe('insufficient_scope')
            ->and($scope->render()->getData(true)['error'])->toBe('insufficient_scope');
    } finally {
        ApiKeyRejection::setTranslator(null);
    }
});

afterEach(function (): void {
    ApiKeyRejection::setResourceMetadataUrl(null);
});

it('names the required scope when the key holds no usable scopes', function (): void {
    $response = ApiKeyRejection::noUsableScopes('items:read')->render();

    expect($response->getStatusCode())->toBe(403)
        ->and($response->headers->get('WWW-Authenticate'))->toBe('Bearer error="insufficient_scope", scope="items:read"')
        ->and($response->getData(true))->toBe([
            'message' => 'The API key holds no scopes.',
            'error' => 'insufficient_scope',
            'scope' => 'items:read',
        ]);
});

it('adds resource_metadata to the invalid_token and insufficient_scope challenges once configured', function (): void {
    $url = 'https://api.example.com/.well-known/oauth-protected-resource';
    ApiKeyRejection::setResourceMetadataUrl($url);

    expect(ApiKeyRejection::invalidToken()->render()->headers->get('WWW-Authenticate'))
        ->toBe('Bearer error="invalid_token", resource_metadata="'.$url.'"')
        ->and(ApiKeyRejection::insufficientScope('items:write')->render()->headers->get('WWW-Authenticate'))
        ->toBe('Bearer error="insufficient_scope", scope="items:write", resource_metadata="'.$url.'"')
        ->and(ApiKeyRejection::noUsableScopes('items:read')->render()->headers->get('WWW-Authenticate'))
        ->toBe('Bearer error="insufficient_scope", scope="items:read", resource_metadata="'.$url.'"')
        ->and(ApiKeyRejection::noUsableScopes()->render()->headers->get('WWW-Authenticate'))
        ->toBe('Bearer error="insufficient_scope", resource_metadata="'.$url.'"')
        ->and(ApiKeyRejection::ipNotAllowed()->render()->headers->get('WWW-Authenticate'))->toBeNull();

    ApiKeyRejection::setResourceMetadataUrl(null);

    expect(ApiKeyRejection::invalidToken()->render()->headers->get('WWW-Authenticate'))->toBe('Bearer error="invalid_token"');
});

it('refuses a resource metadata URL that is not an absolute https URL safe in a header', function (string $url): void {
    expect(fn () => ApiKeyRejection::setResourceMetadataUrl($url))
        ->toThrow(InvalidArgumentException::class, 'The resource metadata URL must be an absolute https URL.');
})->with([
    'http' => ['http://api.example.com/.well-known/oauth-protected-resource'],
    'relative' => ['/.well-known/oauth-protected-resource'],
    'quote' => ['https://api.example.com/"x'],
    'backslash' => ['https://api.example.com/\\x'],
    'new line' => ["https://api.example.com/\nx"],
    'empty' => [''],
]);

it('refuses a scope that could break out of the WWW-Authenticate header', function (string $scope): void {
    expect(fn () => ApiKeyRejection::insufficientScope($scope))
        ->toThrow(InvalidArgumentException::class, 'The required scope must be a scope atom such as items:read.');
})->with([
    'quote' => ['items:read", error="invalid_token'],
    'CRLF' => ["items:read\r\nSet-Cookie: session=x"],
    'backslash' => ['items:read\\'],
    'empty' => [''],
    'not a scope atom' => ['Items:Read'],
]);
