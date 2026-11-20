<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\ApiKeys\Http\ClientIp;

mutates(ClientIp::class);

it('returns Request::ip() and nothing else', function (): void {
    $request = Request::create('http://localhost/api', 'GET', server: [
        'REMOTE_ADDR' => '203.0.113.50',
        'HTTP_X_FORWARDED_FOR' => '198.51.100.1',
    ]);

    expect(ClientIp::from($request))->toBe('203.0.113.50');
});
