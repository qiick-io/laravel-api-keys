<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api How the row is used: issued API key vs OAuth grant bridge row.
 *
 * Grant rows share the `api_keys` table but have no usable bearer secret.
 * Values are fixed; products must not invent kinds without a package release.
 */
enum CredentialKind: string
{
    case ApiKey = 'api_key';
    case OauthGrant = 'oauth_grant';
}
