<?php

declare(strict_types=1);

use Illuminate\Notifications\Messages\MailMessage;
use Qiick\ApiKeys\Notifications\ApiKeyExpiringNotification;
use Qiick\ApiKeys\Notifications\ApiKeyLegacyFormatWarningNotification;
use Qiick\ApiKeys\Testing\InMemoryApiKeyRecord;

mutates(ApiKeyExpiringNotification::class);
mutates(ApiKeyLegacyFormatWarningNotification::class);

function notifiedRecord(): InMemoryApiKeyRecord
{
    return (new InMemoryApiKeyRecord(
        publicId: '018f0000-0000-7000-8000-0000000000a1',
        keyPrefix: 'tst_live_ABCDEFGH',
        keyHash: 'hash',
        scopes: ['items:read'],
    ))->withTokenVersion(0);
}

it('sends the expiry notice by mail and to the database, naming the key and the instant', function (): void {
    $notification = new ApiKeyExpiringNotification(notifiedRecord(), new DateTimeImmutable('2027-01-01T00:00:00+00:00'));
    $mail = $notification->toMail(new stdClass);

    expect($notification->via(new stdClass))->toBe(['mail', 'database'])
        ->and($mail)->toBeInstanceOf(MailMessage::class)
        ->and($mail->subject)->toBe('API key expiring soon')
        ->and($mail->introLines)->toBe([
            'An API key is approaching its expiry.',
            'Name: tst_live_ABCDEFGH',
            'Expires at: 2027-01-01T00:00:00+00:00',
        ])
        ->and($notification->toArray(new stdClass))->toBe([
            'api_key_id' => '018f0000-0000-7000-8000-0000000000a1',
            'key_prefix' => 'tst_live_ABCDEFGH',
            'expires_at' => '2027-01-01T00:00:00+00:00',
        ]);
});

it('sends the legacy-format warning by mail and to the database, with the cut-off and the version', function (): void {
    $notification = new ApiKeyLegacyFormatWarningNotification(notifiedRecord(), new DateTimeImmutable('2027-01-01T00:00:00+00:00'));
    $mail = $notification->toMail(new stdClass);

    expect($notification->via(new stdClass))->toBe(['mail', 'database'])
        ->and($mail->subject)->toBe('Legacy API key format ends soon')
        ->and($mail->introLines)->toBe([
            'An API key still uses a legacy token format.',
            'Prefix: tst_live_ABCDEFGH',
            'Legacy acceptance ends at: 2027-01-01T00:00:00+00:00',
            'Rotate the key before that instant so the grace window covers clients.',
        ])
        ->and($notification->toArray(new stdClass))->toBe([
            'api_key_id' => '018f0000-0000-7000-8000-0000000000a1',
            'key_prefix' => 'tst_live_ABCDEFGH',
            'accept_until' => '2027-01-01T00:00:00+00:00',
            'token_version' => 0,
        ]);
});
