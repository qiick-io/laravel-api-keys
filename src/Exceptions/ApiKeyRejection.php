<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Exceptions;

use Illuminate\Http\JsonResponse;
use Qiick\ApiKeys\KeyRejectionCode;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * @api Fleet RFC 6750 refusals as `{message, error[, scope]}`.
 *
 * HARD RULE: constructors and factories MUST NOT accept or embed the presented
 * token, Authorization header, or key hash. Messages are fixed / translated only;
 * error codes are never translated.
 */
final class ApiKeyRejection extends HttpException
{
    /**
     * Optional message translator. Receives a stable message key and replace map;
     * must return the translated string (error codes stay English machine values).
     *
     * @var (callable(string, array<string, string>): string)|null
     */
    private static $translator = null;

    /**
     * RFC 9728 protected-resource metadata URL, added to the `invalid_token` and
     * `insufficient_scope` challenges so OAuth / MCP clients can discover how to
     * get a token with the right scopes. Null leaves it out.
     */
    private static ?string $resourceMetadataUrl = null;

    /**
     * @param  (callable(string, array<string, string>): string)|null  $translator
     */
    public static function setTranslator(?callable $translator): void
    {
        self::$translator = $translator;
    }

    /**
     * @param  array<string, string|list<string>>  $headers
     */
    private function __construct(
        int $statusCode,
        string $message,
        private readonly KeyRejectionCode $rejectionCode,
        private readonly ?string $requiredScope = null,
        array $headers = [],
    ) {
        parent::__construct($statusCode, $message, null, $headers);
    }

    /**
     * @throws \InvalidArgumentException when the URL is not an absolute https URL that
     *                                   is safe inside a quoted header parameter
     */
    public static function setResourceMetadataUrl(?string $url): void
    {
        $isSafe = $url === null || (
            str_starts_with($url, 'https://')
            && filter_var($url, FILTER_VALIDATE_URL) !== false
            && strpbrk($url, "\"\\\r\n") === false
        );

        if (! $isSafe) {
            throw new \InvalidArgumentException('The resource metadata URL must be an absolute https URL.');
        }

        self::$resourceMetadataUrl = $url;
    }

    public static function invalidToken(?string $message = null): self
    {
        return new self(
            401,
            $message ?? self::translate('api_keys.invalid_token', 'The API key is not valid.'),
            KeyRejectionCode::InvalidToken,
            null,
            ['WWW-Authenticate' => self::challenge('invalid_token')],
        );
    }

    public static function insufficientScope(string $scope): self
    {
        return new self(
            403,
            self::translate(
                'api_keys.insufficient_scope',
                'The API key lacks the :scope scope.',
                ['scope' => $scope],
            ),
            KeyRejectionCode::InsufficientScope,
            $scope,
            ['WWW-Authenticate' => self::challenge('insufficient_scope', $scope)],
        );
    }

    /**
     * The key holds no usable scope. When the request required one, it is named
     * like in {@see insufficientScope()}, so the client knows what to ask for.
     */
    public static function noUsableScopes(?string $requiredScope = null): self
    {
        return new self(
            403,
            self::translate('api_keys.no_usable_scopes', 'The API key holds no scopes.'),
            KeyRejectionCode::InsufficientScope,
            $requiredScope,
            ['WWW-Authenticate' => self::challenge('insufficient_scope', $requiredScope)],
        );
    }

    public static function ipNotAllowed(): self
    {
        // No WWW-Authenticate: fleet contract for ip_not_allowed.
        return new self(
            403,
            self::translate(
                'api_keys.ip_not_allowed',
                'API key is not allowed from this IP address.',
            ),
            KeyRejectionCode::IpNotAllowed,
        );
    }

    public static function requestNotAllowed(): self
    {
        // No WWW-Authenticate: same shape as ip_not_allowed (Luca, 2026-11-22).
        return new self(
            403,
            self::translate(
                'api_keys.request_not_allowed',
                'API key is not allowed for this request.',
            ),
            KeyRejectionCode::RequestNotAllowed,
        );
    }

    /**
     * 503 when the attempt store behind the rate limits is down: the request
     * fails closed, and the client may retry.
     */
    public static function serviceUnavailable(): self
    {
        return new self(
            503,
            self::translate('api_keys.service_unavailable', 'API key verification is temporarily unavailable.'),
            KeyRejectionCode::ServiceUnavailable,
        );
    }

    /**
     * 429 with Retry-After and optional X-RateLimit-* headers.
     *
     * `$resetAfterSeconds` populates `X-RateLimit-Reset` when provided (L8).
     */
    public static function rateLimited(
        int $retryAfterSeconds,
        ?int $limit = null,
        ?int $remaining = null,
        ?int $resetAfterSeconds = null,
    ): self {
        $headers = ['Retry-After' => (string) $retryAfterSeconds];

        if ($limit !== null) {
            $headers['X-RateLimit-Limit'] = (string) $limit;
        }

        if ($remaining !== null) {
            $headers['X-RateLimit-Remaining'] = (string) $remaining;
        }

        if ($resetAfterSeconds !== null) {
            $headers['X-RateLimit-Reset'] = (string) $resetAfterSeconds;
        }

        return new self(
            429,
            self::translate('api_keys.rate_limit_exceeded', 'Too many requests.'),
            KeyRejectionCode::RateLimitExceeded,
            null,
            $headers,
        );
    }

    public function errorCode(): string
    {
        return $this->rejectionCode->value;
    }

    public function render(): JsonResponse
    {
        $payload = [
            'message' => $this->getMessage(),
            'error' => $this->rejectionCode->value,
        ];

        if ($this->requiredScope !== null) {
            $payload['scope'] = $this->requiredScope;
        }

        return new JsonResponse($payload, $this->getStatusCode(), $this->getHeaders());
    }

    /**
     * @return array{status: int, error: string, message: string, scope: ?string}
     */
    public function __debugInfo(): array
    {
        return [
            'status' => $this->getStatusCode(),
            'error' => $this->rejectionCode->value,
            'message' => $this->getMessage(),
            'scope' => $this->requiredScope,
        ];
    }

    /**
     * RFC 6750 §3 challenge: `Bearer error="…"[, scope="…"][, resource_metadata="…"]`.
     * Scopes are validated scope strings and the URL is checked on the way in,
     * so neither can break out of its quotes.
     */
    private static function challenge(string $error, ?string $scope = null): string
    {
        $challenge = 'Bearer error="'.$error.'"';

        if ($scope !== null) {
            $challenge .= ', scope="'.$scope.'"';
        }

        if (self::$resourceMetadataUrl !== null) {
            $challenge .= ', resource_metadata="'.self::$resourceMetadataUrl.'"';
        }

        return $challenge;
    }

    /**
     * @param  array<string, string>  $replace
     */
    private static function translate(string $key, string $fallback, array $replace = []): string
    {
        $message = $fallback;

        if (self::$translator !== null) {
            $message = (self::$translator)($key, $replace);
        }

        foreach ($replace as $search => $value) {
            $message = str_replace(':'.$search, $value, $message);
        }

        return $message;
    }
}
