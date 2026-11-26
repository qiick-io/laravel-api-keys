<?php

declare(strict_types=1);

namespace Qiick\ApiKeys\Erasure;

use LogicException;

/** @api The product's reference API key schema cannot filter by organisation. */
final class OrganisationScopeUnsupportedException extends LogicException {}
