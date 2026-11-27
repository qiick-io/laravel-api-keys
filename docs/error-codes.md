# API key error codes

The `error` property of `ApiKeyRejection` responses uses the
[fleet registry](https://github.com/qiick-io/app-ui/blob/v0.15.0/standards/error-codes.json).

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `invalid_token` | 401 | The bearer credential is absent or unusable. |
| `insufficient_scope` | 403 | The key has no usable scopes or lacks the required scope. |
| `ip_not_allowed` | 403 | The client IP is outside the key's allowlist. |
| `request_not_allowed` | 403 | The key's request restrictions deny the request. |
| `too_many_requests` | 429 | The key quota or failed-attempt brake refused the request. |
| `service_unavailable` | 503 | An authentication dependency is unavailable. |
