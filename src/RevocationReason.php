<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Why a key (or grant row) was revoked.
 *
 * Superset of `qiick/laravel-mcp-oauth` reasons so one row can carry either
 * package's value. Products must not invent reasons without a package release.
 */
enum RevocationReason: string
{
    case User = 'user';
    case Admin = 'admin';
    case Owner = 'owner';
    case Exposure = 'exposure';
    case Policy = 'policy';
    case Reuse = 'reuse';
    case Reconsent = 'reconsent';
    case System = 'system';
}
