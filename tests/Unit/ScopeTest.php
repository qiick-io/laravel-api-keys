<?php

declare(strict_types=1);

use Qiick\ApiKeys\Contracts\ScopeVocabulary;
use Qiick\ApiKeys\Scope;
use Qiick\ApiKeys\ScopeSet;
use Qiick\ApiKeys\Testing\ArrayScopeVocabulary;

mutates(Scope::class);
mutates(ScopeSet::class);

function vocabulary(array $scopes = ['users:read', 'users:write', 'keys:read', 'keys:write']): ArrayScopeVocabulary
{
    return new ArrayScopeVocabulary($scopes);
}

it('parses well-formed scope atoms and rejects whitespace, case and junk', function (): void {
    expect(Scope::tryFromString('users:read'))->toEqual(new Scope('users', 'read'))
        ->and(Scope::tryFromString('users:write')?->value())->toBe('users:write')
        ->and(Scope::tryFromString(' users:read '))->toBeNull()
        ->and(Scope::tryFromString('Users:Read'))->toBeNull()
        ->and(Scope::tryFromString('users:READ'))->toBeNull()
        ->and(Scope::tryFromString("users:read\n"))->toBeNull()
        ->and(Scope::tryFromString('users:admin'))->toBeNull()
        ->and(Scope::tryFromString(''))->toBeNull();
});

it('rejects crafted constructor atoms that would inject into WWW-Authenticate', function (): void {
    expect(fn () => new Scope('users', 'read", scope="evil'))
        ->toThrow(InvalidArgumentException::class);
});

it('lets write satisfy read on the same resource only', function (): void {
    $read = Scope::tryFromString('users:read');
    $write = Scope::tryFromString('users:write');
    $keysRead = Scope::tryFromString('keys:read');

    expect($write->satisfies($read))->toBeTrue()
        ->and($read->satisfies($write))->toBeFalse()
        ->and($read->satisfies($read))->toBeTrue()
        ->and($write->satisfies($write))->toBeTrue()
        ->and($write->satisfies($keysRead))->toBeFalse()
        ->and($keysRead->satisfies($read))->toBeFalse();
});

it('fail-closes parseStored on empty, non-list, unknown, whitespace, case and duplicates', function (): void {
    $vocab = vocabulary();

    expect(ScopeSet::parseStored(null, $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored([], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['users:read' => true], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['users:read', 1], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['users:read', 'unknown:read'], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored([' users:read '], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['Users:Read'], $vocab)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['users:read', 'users:read'], $vocab)->isEmpty())->toBeTrue();
});

it('fail-closes when a malformed element is still claimed by the vocabulary', function (): void {
    // Ensures the tryFromString null branch returns empty even if contains() is true.
    $acceptAll = new class implements ScopeVocabulary
    {
        public function all(): array
        {
            return [];
        }

        public function contains(string $value): bool
        {
            return true;
        }
    };

    expect(ScopeSet::parseStored([' users:read '], $acceptAll)->isEmpty())->toBeTrue()
        ->and(ScopeSet::parseStored(['Users:Read'], $acceptAll)->isEmpty())->toBeTrue();
});

it('keeps highest-per-resource after a successful parse', function (): void {
    $set = ScopeSet::parseStored(['users:read', 'users:write', 'keys:read'], vocabulary());

    expect($set->isEmpty())->toBeFalse()
        ->and($set->values())->toBe(['users:write', 'keys:read'])
        ->and($set->allows(Scope::tryFromString('users:read')))->toBeTrue()
        ->and($set->allows(Scope::tryFromString('users:write')))->toBeTrue()
        ->and($set->allows(Scope::tryFromString('keys:read')))->toBeTrue()
        ->and($set->allows(Scope::tryFromString('keys:write')))->toBeFalse();
});

it('does not allow anything from an empty set', function (): void {
    $set = new ScopeSet([]);

    expect($set->isEmpty())->toBeTrue()
        ->and($set->values())->toBe([])
        ->and($set->allows(Scope::tryFromString('users:read')))->toBeFalse();
});

it('offers implied reads to the authorizer and demotes write when ceiling is read-only', function (): void {
    $expanded = ScopeSet::parseStoredExpanded(['users:write', 'keys:read'], vocabulary());

    expect($expanded->values())->toBe(['users:write', 'keys:read'])
        ->and($expanded->valuesOfferedToAuthorizer())->toBe(['users:write', 'keys:read', 'users:read']);

    // Read-before-write: ContinueToBreak must not stop the loop before the write.
    $readFirst = ScopeSet::parseStoredExpanded(['keys:read', 'users:write'], vocabulary());
    expect($readFirst->valuesOfferedToAuthorizer())->toBe(['keys:read', 'users:write', 'users:read']);

    $narrowed = $expanded->narrowedTo(['users:read', 'keys:read'])->collapsed();

    expect($narrowed->values())->toBe(['users:read', 'keys:read'])
        ->and($narrowed->allows(Scope::tryFromString('users:read')))->toBeTrue()
        ->and($narrowed->allows(Scope::tryFromString('users:write')))->toBeFalse();
});

it('keeps write when the ceiling still allows write', function (): void {
    $expanded = ScopeSet::parseStoredExpanded(['users:write'], vocabulary());
    $narrowed = $expanded->narrowedTo(['users:write', 'users:read'])->collapsed();

    expect($narrowed->values())->toBe(['users:write'])
        ->and($narrowed->allows(Scope::tryFromString('users:read')))->toBeTrue();
});

it('dedupes granted scopes when write demotes onto an already-kept read', function (): void {
    $expanded = ScopeSet::parseStoredExpanded(['users:read', 'users:write'], vocabulary());
    $narrowed = $expanded->narrowedTo(['users:read']);

    expect($narrowed->values())->toBe(['users:read'])
        ->and($narrowed->collapsed()->values())->toBe(['users:read']);
});
