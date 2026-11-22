<?php

declare(strict_types=1);

use Qiick\ApiKeys\Testing\FakeApiKeyRepository;
use Qiick\ApiKeys\Testing\FakeAttemptLimiter;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;

it('N5: fakes refuse to construct outside the testing environment', function (): void {
    $previous = getenv('QIICK_API_KEYS_ALLOW_FAKES');
    putenv('QIICK_API_KEYS_ALLOW_FAKES');
    $_ENV['QIICK_API_KEYS_ALLOW_FAKES'] = false;
    unset($_ENV['QIICK_API_KEYS_ALLOW_FAKES'], $_SERVER['QIICK_API_KEYS_ALLOW_FAKES']);

    $this->app['env'] = 'production';

    expect(fn () => new FakeApiKeyRepository)
        ->toThrow(RuntimeException::class, 'testing environment')
        ->and(fn () => new FakeAttemptLimiter)
        ->toThrow(RuntimeException::class, 'testing environment')
        ->and(fn () => new InMemoryApiKeyRecord)
        ->toThrow(RuntimeException::class, 'testing environment');

    putenv('QIICK_API_KEYS_ALLOW_FAKES=1');
    $_ENV['QIICK_API_KEYS_ALLOW_FAKES'] = '1';

    expect(new FakeApiKeyRepository)->toBeInstanceOf(FakeApiKeyRepository::class);

    putenv('QIICK_API_KEYS_ALLOW_FAKES');
    unset($_ENV['QIICK_API_KEYS_ALLOW_FAKES'], $_SERVER['QIICK_API_KEYS_ALLOW_FAKES']);

    if ($previous === false) {
        putenv('QIICK_API_KEYS_ALLOW_FAKES');
    } else {
        putenv('QIICK_API_KEYS_ALLOW_FAKES='.$previous);
    }

    $this->app['env'] = 'testing';

    expect(new FakeApiKeyRepository)->toBeInstanceOf(FakeApiKeyRepository::class);
});
