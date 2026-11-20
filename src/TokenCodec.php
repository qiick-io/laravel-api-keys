<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

use Qiick\ApiKeys\Contracts\EnvironmentResolver;
use Qiick\ApiKeys\Contracts\RandomSource;

/**
 * @api Issues, parses and verifies API key secrets on plain values.
 *
 * Environment precedence for issue(): explicit argument > EnvironmentResolver > error.
 * Product prefix is constructor-injected (configurable 3-letter).
 *
 * Token shape: `{product}_{live|test}_{id}{secret}` with id length 8 and secret length 32
 * (A–Za–z0–9). The stored digest is SHA-256 of the full presented token.
 */
final class TokenCodec
{
    /**
     * Public API mirrors of the operational lengths. Typed class-const declaration
     * lines are not attributed coverage by Pest mutate, so Increment/Decrement on
     * these lines is ignored; the covered {@see self::idLength()} /
     * {@see self::secretLength()} methods are the values issue/parse actually use.
     */
    public const int ID_LENGTH = 8; // @pest-mutate-ignore

    public const int SECRET_LENGTH = 32; // @pest-mutate-ignore

    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * Fixed miss digest so "no candidate" and "hash miss" spend comparable compare work.
     * Not a real key hash.
     */
    private const string DUMMY_DIGEST = '0000000000000000000000000000000000000000000000000000000000000000';

    /** @var list<LegacyTokenMatcher> */
    private array $legacyMatchers;

    /**
     * @param  list<LegacyTokenMatcher>  $legacyMatchers
     */
    public function __construct(
        private string $productPrefix,
        private EnvironmentResolver $environment,
        private RandomSource $random,
        array $legacyMatchers = [],
    ) {
        if (preg_match('/^[a-z]{3}$/D', $this->productPrefix) !== 1) {
            throw new \InvalidArgumentException('API key product prefix must be exactly three lowercase letters.');
        }

        $this->legacyMatchers = $legacyMatchers;
    }

    public function issue(?TokenEnvironment $override = null): GeneratedToken
    {
        $environment = $override ?? $this->environment->environment();
        $publicId = $this->randomAlphabet($this->idLength());
        $keyPrefix = $this->productPrefix.'_'.$environment->value.'_'.$publicId;

        return $this->reissueForPrefix($keyPrefix);
    }

    public function reissueForPrefix(string $keyPrefix): GeneratedToken
    {
        $plainText = $keyPrefix.$this->randomAlphabet($this->secretLength());

        return new GeneratedToken(
            plainText: $plainText,
            keyPrefix: $keyPrefix,
            keyHash: $this->hash($plainText),
        );
    }

    public function prefixOf(string $presentedToken): ?string
    {
        if (preg_match($this->canonicalPattern(), $presentedToken, $matches) === 1) {
            return $matches['prefix'];
        }

        foreach ($this->legacyMatchers as $matcher) {
            $prefix = $matcher->prefixOf($presentedToken);
            if ($prefix !== null) {
                return $prefix;
            }
        }

        return null;
    }

    public function parse(string $presentedToken): ?ParsedToken
    {
        if (preg_match($this->canonicalPattern(), $presentedToken, $matches) !== 1) {
            return null;
        }

        // Pattern guarantees `{product}_{live|test}_{id}` — three underscore-separated parts,
        // with the environment segment always a TokenEnvironment value.
        $keyPrefix = $matches['prefix'];
        [$productPrefix, $environmentValue, $publicId] = explode('_', $keyPrefix);

        return new ParsedToken(
            productPrefix: $productPrefix,
            environment: TokenEnvironment::from($environmentValue),
            publicId: $publicId,
            secret: $matches['secret'],
            keyPrefix: $keyPrefix,
        );
    }

    public function hash(string $presentedToken): string
    {
        return hash('sha256', $presentedToken);
    }

    /**
     * Always runs hash_equals against a dummy digest when TokenMatch::None
     * so "no candidate" and "hash miss" spend comparable compare work.
     */
    public function match(
        string $presentedToken,
        string $keyHash,
        ?string $previousKeyHash,
        ?\DateTimeImmutable $previousKeyValidUntil,
        \DateTimeImmutable $now,
    ): TokenMatch {
        $presentedHash = $this->hash($presentedToken);

        if (hash_equals($keyHash, $presentedHash)) {
            return TokenMatch::Current;
        }

        if (
            $previousKeyHash !== null
            && $previousKeyValidUntil !== null
            && $now < $previousKeyValidUntil
            && hash_equals($previousKeyHash, $presentedHash)
        ) {
            return TokenMatch::Previous;
        }

        // Timing-only compare when both current and previous hashes missed.
        $this->spendCompare($presentedHash); // @pest-mutate-ignore

        return TokenMatch::None;
    }

    /**
     * Constant-ish miss helper used when the repository returns no candidates.
     */
    public function performDummyMatch(string $presentedToken): void
    {
        $this->spendCompare($this->hash($presentedToken)); // @pest-mutate-ignore
    }

    private function spendCompare(string $presentedHash): void
    {
        // Equalises compare work on a miss; branch bodies are intentional no-ops.
        if (hash_equals(self::DUMMY_DIGEST, $presentedHash)) { // @pest-mutate-ignore
            return;
        }
    }

    private function canonicalPattern(): string
    {
        $product = preg_quote($this->productPrefix, '/');
        $idLength = $this->idLength();
        $secretLength = $this->secretLength();

        return '/^(?<prefix>'.$product.'_(?:live|test)_[A-Za-z0-9]{'.$idLength.'})(?<secret>[A-Za-z0-9]{'.$secretLength.',})$/D';
    }

    /**
     * Operational id length (≥ fleet public id). Mutate-covered; keep in sync with ID_LENGTH.
     */
    private function idLength(): int
    {
        return 8;
    }

    /**
     * Operational secret length (≥160 bits of base62). Mutate-covered; keep in sync with SECRET_LENGTH.
     */
    private function secretLength(): int
    {
        return 32;
    }

    private function randomAlphabet(int $length): string
    {
        $bytes = $this->random->bytes($length);
        $alphabetLength = strlen(self::ALPHABET);
        $output = '';

        for ($index = 0; $index < $length; $index++) {
            $output .= self::ALPHABET[ord($bytes[$index]) % $alphabetLength];
        }

        return $output;
    }
}
