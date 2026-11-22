<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;

/**
 * Test double: throws from via() so Notification::send fails before delivery.
 */
final class ThrowingExpiryNotification extends ApiKeyExpiringNotification
{
    public function via(object $notifiable): array
    {
        throw new \RuntimeException('delivery failed');
    }
}
