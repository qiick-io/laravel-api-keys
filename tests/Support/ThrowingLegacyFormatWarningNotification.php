<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;

/**
 * Test double: throws from via() so the legacy-format warning send fails
 * before delivery, like a broken mail transport.
 */
final class ThrowingLegacyFormatWarningNotification extends ApiKeyLegacyFormatWarningNotification
{
    public function via(object $notifiable): array
    {
        throw new \RuntimeException('delivery failed');
    }
}
