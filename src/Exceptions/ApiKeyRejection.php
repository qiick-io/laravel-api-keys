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
 * token, Authorization header, or key hash. Messages are fixed / translated only.
 */
final class ApiKeyRejection extends HttpException
{
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

    public static function invalidToken(string $message = 'The API key is not valid.'): self
    {
        return new self(
            401,
            $message,
            KeyRejectionCode::InvalidToken,
            null,
            ['WWW-Authenticate' => 'Bearer error="invalid_token"'],
        );
    }

    public static function insufficientScope(string $scope): self
    {
        return new self(
            403,
            'The API key lacks the '.$scope.' scope.',
            KeyRejectionCode::InsufficientScope,
            $scope,
            ['WWW-Authenticate' => 'Bearer error="insufficient_scope", scope="'.$scope.'"'],
        );
    }

    public static function noUsableScopes(): self
    {
        return new self(
            403,
            'The API key holds no scopes.',
            KeyRejectionCode::InsufficientScope,
            null,
            ['WWW-Authenticate' => 'Bearer error="insufficient_scope"'],
        );
    }

    public static function ipNotAllowed(): self
    {
        // No WWW-Authenticate: fleet contract for ip_not_allowed.
        return new self(
            403,
            'API key is not allowed from this IP address.',
            KeyRejectionCode::IpNotAllowed,
        );
    }

    /**
     * 429 with Retry-After and optional X-RateLimit-* headers.
     */
    public static function rateLimited(int $retryAfterSeconds, ?int $limit = null, ?int $remaining = null): self
    {
        $headers = ['Retry-After' => (string) $retryAfterSeconds]; // @pest-mutate-ignore RemoveStringCast

        if ($limit !== null) {
            $headers['X-RateLimit-Limit'] = (string) $limit; // @pest-mutate-ignore RemoveStringCast
        }

        if ($remaining !== null) {
            $headers['X-RateLimit-Remaining'] = (string) $remaining; // @pest-mutate-ignore RemoveStringCast
        }

        return new self(
            429,
            'Too many requests.',
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
}
