<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Tests\Support;

use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;

/**
 * Test double: delivery fails only for the key whose public id is `FAILING_PUBLIC_ID`.
 */
final class FailingForKeyLegacyWarningNotification extends ApiKeyLegacyFormatWarningNotification
{
    public const string FAILING_PUBLIC_ID = '018f0000-0000-7000-8000-0000000000f0';

    public function via(object $notifiable): array
    {
        if ($this->record->publicId() === self::FAILING_PUBLIC_ID) {
            throw new \RuntimeException('mail transport down');
        }

        return parent::via($notifiable);
    }
}
