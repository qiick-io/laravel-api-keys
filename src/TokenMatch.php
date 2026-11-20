<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @api Result of comparing a presented token to stored hashes (current / grace previous).
 */
enum TokenMatch: string
{
    case None = 'none';
    case Current = 'current';
    case Previous = 'previous';
}
