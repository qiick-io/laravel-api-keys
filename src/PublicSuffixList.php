<?php

declare(strict_types=1);

namespace Qiick\ApiKeys;

/**
 * @internal Answers "is this domain a public suffix?" from Mozilla's Public Suffix List.
 *
 * Used to refuse origin wildcards such as `*.co.uk` or `*.github.io`, where
 * anyone can register a sibling and inherit the key's origin restriction. The
 * PRIVATE section (hosting platforms like github.io, vercel.app) counts, as it
 * does for browser cookies.
 *
 * ponytail: a snapshot of the list ships in `resources/public_suffix_list.dat`
 * (MPL-2.0, fetched 2026-11-23), refreshed by hand before a release. Suffixes
 * added upstream after the snapshot are not refused until the next refresh;
 * the upgrade path is a periodic fetch or `jeremykendall/php-domain-parser`.
 */
final class PublicSuffixList
{
    private const string LIST_PATH = __DIR__.'/../resources/public_suffix_list.dat';

    /** @var array<string, true>|null normal rules, `*.parent` wildcards and `!exceptions`, as written in the list */
    private static ?array $rules = null;

    public static function isPublicSuffix(string $domain): bool
    {
        $domain = strtolower($domain);
        $rules = self::rules();

        if (isset($rules['!'.$domain])) {
            return false;
        }

        if (isset($rules[$domain])) {
            return true;
        }

        $labels = explode('.', $domain);

        // The list's implicit rule `*`: every top-level label is a public suffix.
        if (count($labels) === 1) {
            return true;
        }

        array_shift($labels);

        return isset($rules['*.'.implode('.', $labels)]);
    }

    /**
     * @return array<string, true>
     */
    private static function rules(): array
    {
        if (self::$rules !== null) {
            return self::$rules;
        }

        $rules = [];

        foreach (file(self::LIST_PATH, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            // A rule is the first whitespace-delimited token; comments start with `//`.
            $rule = strtok(trim($line), " \t");

            if ($rule === false || str_starts_with($rule, '//')) {
                continue;
            }

            $rules[self::toAscii($rule)] = true;
        }

        return self::$rules = $rules;
    }

    /**
     * Origins arrive in their ASCII (punycode) form; the list writes IDN rules in Unicode.
     */
    private static function toAscii(string $rule): string
    {
        if (! function_exists('idn_to_ascii')) {
            return $rule;
        }

        $prefix = str_starts_with($rule, '!') ? '!' : (str_starts_with($rule, '*.') ? '*.' : '');
        $ascii = idn_to_ascii(substr($rule, strlen($prefix)), IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

        return $prefix.strtolower($ascii === false ? substr($rule, strlen($prefix)) : $ascii);
    }
}
