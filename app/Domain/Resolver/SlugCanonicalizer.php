<?php

declare(strict_types=1);

namespace App\Domain\Resolver;

/**
 * ALG-001: Slug Canonicalization & Reserved Word Guard (SPEC-07, DES-013, #14).
 */
final class SlugCanonicalizer
{
    /**
     * @param list<string>|null $reservedSlugs
     * @return array{
     *   valid: bool,
     *   slug_normalized: ?string,
     *   display_slug: string,
     *   error_code: ?string,
     *   http_status: int
     * }
     */
    public static function canonicalize(string $rawSlug, ?array $reservedSlugs = null): array
    {
        $trimmed = trim($rawSlug, " \t\n\r\0\x0B/");
        if ($trimmed === '') {
            return self::invalid($rawSlug, 'SLUG_EMPTY');
        }

        // Single path segment only
        if (str_contains($trimmed, '/') || str_contains($trimmed, '\\')) {
            return self::invalid($rawSlug, 'SLUG_MULTI_SEGMENT');
        }

        // Reject non-ASCII / Unicode homographs (DES-013, TV-005)
        if (!preg_match('/^[\x20-\x7E]+$/', $trimmed)) {
            return self::invalid($rawSlug, 'SLUG_NON_ASCII');
        }

        $normalized = strtolower($trimmed);

        if ($reservedSlugs === null) {
            /** @var array<string, mixed> $cfg */
            $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';
            /** @var list<string> $reservedSlugs */
            $reservedSlugs = $cfg['reserved_slugs'] ?? [];
        }

        if (in_array($normalized, $reservedSlugs, true)) {
            return self::invalid($rawSlug, 'SLUG_RESERVED_SYSTEM');
        }

        $len = strlen($normalized);
        if ($len < 3 || $len > 64) {
            return self::invalid($rawSlug, 'SLUG_LENGTH_OUT_OF_RANGE');
        }

        if (str_contains($normalized, '--')) {
            return self::invalid($rawSlug, 'SLUG_CONSECUTIVE_HYPHENS');
        }

        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$/', $normalized)) {
            return self::invalid($rawSlug, 'SLUG_INVALID_FORMAT');
        }

        return [
            'valid' => true,
            'slug_normalized' => $normalized,
            'display_slug' => $trimmed,
            'error_code' => null,
            'http_status' => 200,
        ];
    }

    /**
     * @return array{valid: false, slug_normalized: null, display_slug: string, error_code: string, http_status: int}
     */
    private static function invalid(string $raw, string $code): array
    {
        return [
            'valid' => false,
            'slug_normalized' => null,
            'display_slug' => $raw,
            'error_code' => $code,
            'http_status' => 404,
        ];
    }
}

