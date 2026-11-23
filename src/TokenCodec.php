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
 * Token shapes:
 * - version 1: `{product}_{live|test}_{id}{secret}` (id 8, secret 32, A–Za–z0–9)
 * - version 2 (default): same plus a 6-character base62 CRC32 checksum (GitHub construction)
 *
 * The stored digest is SHA-256 of the full presented token (including checksum).
 * Parsing is shape-based; the row's `token_version` is known only after prefix lookup.
 */
final class TokenCodec
{
    /**
     * Public API mirrors of the operational lengths. Typed class-const declaration
     * lines are not attributed coverage by Pest mutate, so Increment/Decrement on
     * these lines is ignored; the covered {@see self::idLength()} /
     * {@see self::secretLength()} methods are the values issue/parse actually use.
     */
    public const int ID_LENGTH = 8;

    public const int SECRET_LENGTH = 32;

    public const int CHECKSUM_LENGTH = 6;

    public const int DEFAULT_TOKEN_VERSION = 2;

    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    private const string KNOWN_HASH_ALGORITHM = 'sha256';

    /**
     * Fixed miss digest so "no candidate" and "hash miss" spend comparable compare work.
     * Not a real key hash.
     */
    private const string DUMMY_DIGEST = '0000000000000000000000000000000000000000000000000000000000000000';

    /** @var list<LegacyTokenMatcher> */
    private array $legacyMatchers;

    /**
     * @param  list<LegacyTokenMatcher>  $legacyMatchers
     * @param  null|callable(): void  $onDummyMatch  test seam only
     * @param  \DateTimeImmutable|null  $legacyAcceptUntil  Package cut-off from
     *                                                      `api-keys.legacy.accept_until`. When set, a matcher is rejected at
     *                                                      `now >= min(config, matcher->acceptUntil())` regardless of
     *                                                      {@see LegacyTokenMatcher::isAccepting()}.
     */
    public function __construct(
        private string $productPrefix,
        private EnvironmentResolver $environment,
        private RandomSource $random,
        array $legacyMatchers = [],
        private mixed $onDummyMatch = null,
        private ?\DateTimeImmutable $legacyAcceptUntil = null,
        private int $defaultTokenVersion = self::DEFAULT_TOKEN_VERSION,
    ) {
        if (preg_match('/^[a-z]{3}$/D', $this->productPrefix) !== 1) {
            throw new \InvalidArgumentException('API key product prefix must be exactly three lowercase letters.');
        }

        if ($this->defaultTokenVersion !== 1 && $this->defaultTokenVersion !== 2) {
            throw new \InvalidArgumentException('API key default token version must be 1 or 2.');
        }

        $this->legacyMatchers = $legacyMatchers;
    }

    public function issue(?TokenEnvironment $override = null, ?int $tokenVersion = null): GeneratedToken
    {
        $environment = $override ?? $this->environment->environment();
        $publicId = $this->randomAlphabet($this->idLength());
        $keyPrefix = $this->productPrefix.'_'.$environment->value.'_'.$publicId;

        return $this->reissueForPrefix($keyPrefix, $tokenVersion);
    }

    public function reissueForPrefix(string $keyPrefix, ?int $tokenVersion = null): GeneratedToken
    {
        $version = $tokenVersion ?? $this->defaultTokenVersion;
        if ($version !== 1 && $version !== 2) {
            throw new \InvalidArgumentException('API key token version must be 1 or 2.');
        }

        $body = $keyPrefix.$this->randomAlphabet($this->secretLength());
        $plainText = $version === 2 ? $body.$this->checksumFor($body) : $body;

        return new GeneratedToken(
            plainText: $plainText,
            keyPrefix: $keyPrefix,
            keyHash: $this->hash($plainText),
            tokenVersion: $version,
        );
    }

    /**
     * Whether a stored key_prefix matches this codec’s canonical shape.
     */
    public function isCanonicalKeyPrefix(string $keyPrefix): bool
    {
        $product = preg_quote($this->productPrefix, '/');
        $idLength = $this->idLength();

        return preg_match('/^'.$product.'_(?:live|test)_[A-Za-z0-9]{'.$idLength.'}$/D', $keyPrefix) === 1;
    }

    /**
     * Whether a stored key_prefix is canonical, or recognised by an accepting
     * legacy matcher at `$now`. Matchers are asked with the prefix alone (no
     * secret-length probes): a matcher that only accepts a full token shape
     * will not recognise a stored prefix for rotation.
     */
    public function isValidKeyPrefix(string $keyPrefix, \DateTimeImmutable $now): bool
    {
        if ($this->isCanonicalKeyPrefix($keyPrefix)) {
            return true;
        }

        foreach ($this->legacyMatchers as $matcher) {
            if (! $this->legacyStillAccepted($matcher, $now)) {
                continue;
            }

            if ($matcher->prefixOf($keyPrefix) === $keyPrefix) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve the stored key_prefix for a presented token. `$now` is required so
     * the package cut-off is never skipped (A13).
     */
    public function prefixOf(
        #[\SensitiveParameter] string $presentedToken,
        \DateTimeImmutable $now,
    ): ?string {
        $canonical = $this->matchCanonicalShape($presentedToken);
        if ($canonical !== null) {
            return $canonical['prefix'];
        }

        foreach ($this->legacyMatchers as $matcher) {
            if (! $this->legacyStillAccepted($matcher, $now)) {
                continue;
            }

            $prefix = $matcher->prefixOf($presentedToken);
            if ($prefix !== null && $this->isUsableMatcherPrefix($presentedToken, $prefix, $matcher)) {
                return $prefix;
            }
        }

        return null;
    }

    /**
     * First legacy matcher still accepting that recognises the token (A13).
     * Returns null for canonical tokens — products dispatch
     * {@see Events\LegacyTokenUsed} only after successful authentication when
     * {@see AuthenticationResult::$legacyMatcherClass} is non-null.
     */
    public function legacyMatcherFor(
        #[\SensitiveParameter] string $presentedToken,
        \DateTimeImmutable $now,
    ): ?LegacyTokenMatcher {
        if ($this->matchCanonicalShape($presentedToken) !== null) {
            return null;
        }

        foreach ($this->legacyMatchers as $matcher) {
            if (! $this->legacyStillAccepted($matcher, $now)) {
                continue;
            }

            $prefix = $matcher->prefixOf($presentedToken);
            if ($prefix !== null && $this->isUsableMatcherPrefix($presentedToken, $prefix, $matcher)) {
                return $matcher;
            }
        }

        return null;
    }

    /**
     * Floor for matcher-declared secret remainders (blocks near-whole-token "prefixes").
     */
    private const int MIN_LEGACY_SECRET_REMAINDER = 20;

    /**
     * Accepted only when {@see LegacyTokenMatcher::isAccepting} is true **and**
     * `$now < min(config cut-off, matcher->acceptUntil())` (exactly-at = rejected).
     * Products can stop legacy early via `isAccepting`; config is a hard ceiling.
     */
    private function legacyStillAccepted(LegacyTokenMatcher $matcher, \DateTimeImmutable $now): bool
    {
        if (! $matcher->isAccepting($now)) {
            return false;
        }

        $matcherUntil = $matcher->acceptUntil();
        // min(config, matcher): equality is equivalent either side; ignore ≤ vs <.
        $until = $this->legacyAcceptUntil === null || $matcherUntil < $this->legacyAcceptUntil
            ? $matcherUntil
            : $this->legacyAcceptUntil;

        return $now < $until;
    }

    /**
     * Matcher output must be a strict prefix of the token, leaving at least
     * max(20, {@see LegacyTokenMatcher::secretLength()}) characters.
     */
    private function isUsableMatcherPrefix(
        string $token,
        string $prefix,
        LegacyTokenMatcher $matcher,
    ): bool {
        if ($prefix === '' || $prefix === $token || ! str_starts_with($token, $prefix)) {
            return false;
        }

        $minRemainder = max(self::MIN_LEGACY_SECRET_REMAINDER, $matcher->secretLength());

        return (strlen($token) - strlen($prefix)) >= $minRemainder;
    }

    public function parse(#[\SensitiveParameter] string $presentedToken): ?ParsedToken
    {
        $matches = $this->matchCanonicalShape($presentedToken);
        if ($matches === null) {
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

    public function hash(#[\SensitiveParameter] string $presentedToken): string
    {
        return hash('sha256', $presentedToken);
    }

    /**
     * Always runs hash_equals against a dummy digest when TokenMatch::None
     * so "no candidate" and "hash miss" spend comparable compare work.
     *
     * Unknown `$hashAlgorithm` fails closed (TokenMatch::None) after a dummy compare.
     */
    public function match(
        #[\SensitiveParameter] string $presentedToken,
        string $keyHash,
        ?string $previousKeyHash,
        ?\DateTimeImmutable $previousKeyValidUntil,
        \DateTimeImmutable $now,
        string $hashAlgorithm = self::KNOWN_HASH_ALGORITHM,
    ): TokenMatch {
        if ($hashAlgorithm !== self::KNOWN_HASH_ALGORITHM) {
            $this->spendCompare($this->hash($presentedToken));

            return TokenMatch::None;
        }

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
        $this->spendCompare($presentedHash);

        return TokenMatch::None;
    }

    /**
     * Constant-ish miss helper used when the repository returns no candidates.
     */
    public function performDummyMatch(#[\SensitiveParameter] string $presentedToken): void
    {
        if (is_callable($this->onDummyMatch)) {
            ($this->onDummyMatch)();
        }

        $this->spendCompare($this->hash($presentedToken));
    }

    private function spendCompare(string $presentedHash): void
    {
        // Equalises compare work on a miss; branch bodies are intentional no-ops.
        if (hash_equals(self::DUMMY_DIGEST, $presentedHash)) {
            return;
        }
    }

    /**
     * Match version 1 or version 2 canonical shapes. Version 2 requires a valid CRC32.
     *
     * @return array{prefix: string, secret: string}|null
     */
    private function matchCanonicalShape(
        #[\SensitiveParameter] string $presentedToken,
    ): ?array {
        $product = preg_quote($this->productPrefix, '/');
        $idLength = $this->idLength();
        $secretLength = $this->secretLength();
        $checksumLength = $this->checksumLength();

        $version2 = '/^(?<prefix>'.$product.'_(?:live|test)_[A-Za-z0-9]{'.$idLength.'})(?<secret>[A-Za-z0-9]{'.$secretLength.'})(?<checksum>[A-Za-z0-9]{'.$checksumLength.'})$/D';
        if (preg_match($version2, $presentedToken, $version2Matches) === 1) {
            $body = $version2Matches['prefix'].$version2Matches['secret'];
            if (! hash_equals($this->checksumFor($body), $version2Matches['checksum'])) {
                return null;
            }

            return [
                'prefix' => $version2Matches['prefix'],
                'secret' => $version2Matches['secret'],
            ];
        }

        $version1 = '/^(?<prefix>'.$product.'_(?:live|test)_[A-Za-z0-9]{'.$idLength.'})(?<secret>[A-Za-z0-9]{'.$secretLength.'})$/D';
        if (preg_match($version1, $presentedToken, $version1Matches) === 1) {
            return [
                'prefix' => $version1Matches['prefix'],
                'secret' => $version1Matches['secret'],
            ];
        }

        return null;
    }

    /**
     * GitHub-style CRC32 of the token without the trailing checksum, as 6 base62 chars.
     */
    public function checksumFor(string $tokenWithoutChecksum): string
    {
        $crc = crc32($tokenWithoutChecksum) & 0xFFFFFFFF;
        $alphabet = self::ALPHABET;
        $alphabetLength = strlen($alphabet);
        $output = '';

        for ($index = 0; $index < $this->checksumLength(); $index++) {
            $output = $alphabet[$crc % $alphabetLength].$output;
            $crc = intdiv($crc, $alphabetLength);
        }

        return $output;
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

    /**
     * Operational checksum length. Mutate-covered; keep in sync with CHECKSUM_LENGTH.
     */
    private function checksumLength(): int
    {
        return 6;
    }

    /**
     * Maps CSPRNG bytes onto the base62 alphabet without modulo bias.
     *
     * Rejection sampling: only bytes in 0..(62*4 - 1) = 0..247 are kept
     * (248..255 discarded and refilled), so each alphabet index is equally likely.
     * Draws a fixed chunk each round so a mid-chunk `break` at the exact length
     * is load-bearing (surplus bytes in the chunk must not be consumed).
     */
    private function randomAlphabet(int $length): string
    {
        $alphabetLength = strlen(self::ALPHABET);
        // 62 * 4 = 248: largest multiple of the alphabet size that fits in a byte.
        $unbiasedLimit = 248;
        $output = '';

        while (strlen($output) < $length) {
            $bytes = $this->random->bytes(32);

            for ($index = 0, $count = strlen($bytes); $index < $count; $index++) {
                $value = ord($bytes[$index]);
                if ($value >= $unbiasedLimit) {
                    continue;
                }

                $output .= self::ALPHABET[$value % $alphabetLength];
                if (strlen($output) === $length) {
                    break;
                }
            }
        }

        return $output;
    }
}
