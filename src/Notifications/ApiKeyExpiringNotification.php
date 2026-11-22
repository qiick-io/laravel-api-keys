<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Qiick\ApiKeys\Contracts\ApiKeyRecord;

/**
 * @api Default mail + database notice that an API key will expire soon.
 *
 * Products replace the class via `api-keys.expiry.notification`. Never includes
 * the plaintext secret.
 */
class ApiKeyExpiringNotification extends Notification
{
    public function __construct(
        public ApiKeyRecord $record,
        public \DateTimeImmutable $expiresAt,
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
            ->subject('API key expiring soon')
            ->line('An API key is approaching its expiry.')
            ->line('Name: '.$this->record->keyPrefix())
            ->line('Expires at: '.$this->expiresAt->format(\DateTimeInterface::ATOM));
    }

    /**
     * @return array{api_key_id: string, key_prefix: string, expires_at: string}
     */
    public function toArray(object $notifiable): array
    {
        return [
            'api_key_id' => $this->record->publicId(),
            'key_prefix' => $this->record->keyPrefix(),
            'expires_at' => $this->expiresAt->format(\DateTimeInterface::ATOM),
        ];
    }
}
