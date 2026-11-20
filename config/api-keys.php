<?php

declare(strict_types=1);

/*
 * qiick/laravel-api-keys configuration.
 *
 * Products own models, migrations, scope enums and HTTP middleware. This file
 * only tunes the contract-only mechanics (codec, grace, usage, rate brakes).
 */
return [

    /*
     * Three-letter product prefix embedded in issued tokens (e.g. "exc", "sig").
     * Required before issue() can run; leave null until the app sets it.
     */
    'product_prefix' => env('API_KEYS_PRODUCT_PREFIX'),

    /*
     * Force live/test for issuance. Null → EnvironmentResolver (app environment).
     */
    'environment' => env('API_KEYS_ENVIRONMENT'),

    /*
     * Hours the previous secret stays valid after rotation. Invalid, negative,
     * or above rotation_max_grace_hours → 0 (no grace).
     */
    'rotation_grace_hours' => (int) env('API_KEYS_ROTATION_GRACE_HOURS', 24),

    /*
     * Ceiling for rotation_grace_hours (default one week). Larger values are
     * treated as invalid → 0 by RotationService::normalizeGraceHours.
     */
    'rotation_max_grace_hours' => (int) env('API_KEYS_ROTATION_MAX_GRACE_HOURS', 168),

    'usage_throttle_seconds' => (int) env('API_KEYS_USAGE_THROTTLE_SECONDS', 60),

    'usage_bypass_throttle_on_ip_change' => (bool) env('API_KEYS_USAGE_BYPASS_ON_IP_CHANGE', true),

    /*
     * Default per-key rate limit (attempts per minute). 0 disables.
     */
    'default_rate_limit_per_minute' => (int) env('API_KEYS_DEFAULT_RATE_LIMIT_PER_MINUTE', 60),

    /*
     * Pre-auth per-IP brake for unknown/invalid tokens. 0 disables.
     * Recipes should leave this on (20/min).
     */
    'failed_attempts_per_minute' => (int) env('API_KEYS_FAILED_ATTEMPTS_PER_MINUTE', 20),

    /*
     * Legacy matchers (class names). Boot fails when non-empty without accept_until.
     *
     * @var list<class-string>
     */
    'legacy_matchers' => [],

    'legacy' => [
        /*
         * ISO-8601 / Carbon-parseable cut-off. Required when legacy_matchers is non-empty.
         */
        'accept_until' => env('API_KEYS_LEGACY_ACCEPT_UNTIL'),
    ],

];
