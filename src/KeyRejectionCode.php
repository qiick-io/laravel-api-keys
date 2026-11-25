<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Fleet RFC 6750 / rate-limit error codes for {@see Exceptions\ApiKeyRejection}.
 */
enum KeyRejectionCode: string
{
    case InvalidToken = 'invalid_token';
    case InsufficientScope = 'insufficient_scope';
    case IpNotAllowed = 'ip_not_allowed';
    case RequestNotAllowed = 'request_not_allowed';
    case RateLimitExceeded = 'rate_limit_exceeded';
    case ServiceUnavailable = 'service_unavailable';
}
