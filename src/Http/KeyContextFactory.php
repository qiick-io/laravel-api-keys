<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Http;

use Illuminate\Http\Request;
use Qiick\ApiKeys\KeyContext;

/**
 * @api Builds a {@see KeyContext} from an Illuminate request (not middleware).
 *
 * Products call this from their own middleware or controller. Origin and Referer
 * are taken as client-supplied headers for defence-in-depth restrictions only.
 */
final class KeyContextFactory
{
    public static function fromRequest(Request $request): KeyContext
    {
        $origin = $request->headers->get('Origin');
        $referer = $request->headers->get('Referer');
        $userAgent = $request->userAgent();
        $route = $request->route();
        $routeName = is_object($route) && method_exists($route, 'getName')
            ? $route->getName()
            : null;

        return new KeyContext(
            ip: ClientIp::from($request),
            userAgent: is_string($userAgent) ? $userAgent : null,
            method: $request->getMethod(),
            routeName: is_string($routeName) ? $routeName : null,
            origin: is_string($origin) && $origin !== '' ? $origin : null,
            referer: is_string($referer) && $referer !== '' ? $referer : null,
        );
    }
}
