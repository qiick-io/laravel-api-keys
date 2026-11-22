<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;

/**
 * @api Warns that a legacy-format key should be rotated before accept_until (N2).
 *
 * Never includes the plaintext secret. Products may replace the class via
 * `api-keys.legacy.warning_notification`.
 */
class ApiKeyLegacyFormatWarningNotification extends Notification
{
    public function __construct(
        public ApiKeyRecord $record,
        public \DateTimeImmutable $acceptUntil,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Legacy API key format ends soon')
            ->line('An API key still uses a legacy token format.')
            ->line('Prefix: '.$this->record->keyPrefix())
            ->line('Legacy acceptance ends at: '.$this->acceptUntil->format(\DateTimeInterface::ATOM))
            ->line('Rotate the key before that instant so the grace window covers clients.');
    }

    /**
     * @return array{api_key_id: string, key_prefix: string, accept_until: string, token_version: int}
     */
    public function toArray(object $notifiable): array
    {
        return [
            'api_key_id' => $this->record->publicId(),
            'key_prefix' => $this->record->keyPrefix(),
            'accept_until' => $this->acceptUntil->format(\DateTimeInterface::ATOM),
            'token_version' => $this->record->tokenVersion(),
        ];
    }
}
