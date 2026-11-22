<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (Laravel namespace, Fake test doubles, @api surface) are in
 * `PackageArchitectureTest.php`.
 *
 * Public API names follow the binding design (not the shared Contract/Enum suffix
 * table): those design-mandated types are listed under ignoring with reasons.
 */
return [
    'namespace' => 'Qiick\ApiKeys',

    'ignoring' => [
        'Contracts' => [
            // Design §3.1: public contract names without Contract suffix.
            'Qiick\ApiKeys\Contracts\Clock',
            'Qiick\ApiKeys\Contracts\EnvironmentResolver',
            'Qiick\ApiKeys\Contracts\RandomSource',
            'Qiick\ApiKeys\Contracts\ScopeVocabulary',
            'Qiick\ApiKeys\Contracts\ApiKeyRecord',
            'Qiick\ApiKeys\Contracts\ApiKeyRepository',
            'Qiick\ApiKeys\Contracts\KeyAuthorizer',
            'Qiick\ApiKeys\Contracts\UsageSideEffect',
            'Qiick\ApiKeys\Contracts\AttemptLimiter',
            'Qiick\ApiKeys\Contracts\ExpiryRecipientResolver',
            'Qiick\ApiKeys\Contracts\LifetimePolicy',
            'Qiick\ApiKeys\Contracts\CompromisedKeyRevoker',
            'Qiick\ApiKeys\Contracts\LegacyFormatWarningGate',
        ],
        'Exceptions' => [
            // Design §3.3: ApiKeyRejection (not *Exception).
            'Qiick\ApiKeys\Exceptions\ApiKeyRejection',
        ],
        'Events' => [
            // Design §3.4: event names without Event suffix.
            'Qiick\ApiKeys\Events\LegacyTokenUsed',
            'Qiick\ApiKeys\Events\ApiKeyAuthenticated',
            'Qiick\ApiKeys\Events\ApiKeyExpiryNoticeSent',
            'Qiick\ApiKeys\Events\ApiKeyExposed',
            'Qiick\ApiKeys\Events\ApiKeyLegacyFormatWarningSent',
        ],
        'Notifications' => [
            // Fleet notification names match config keys / externa command.
            'Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification',
            'Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification',
        ],
    ],

    'suffixes' => [
        'Laravel' => 'ServiceProvider',
    ],
];
