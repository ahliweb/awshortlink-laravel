<?php

declare(strict_types=1);

namespace App\Domain\DestinationPolicy;

/**
 * ALG-002 (Part 1): Strict RFC 3986 / WHATWG URL Parser & Canonicalizer (SPEC-07, DES-008, #13).
 */
final class UrlCanonicalizer
{
    /**
     * @param list<string> $httpWaiverHosts
     * @return array{
     *   valid: bool,
     *   url_canonical: ?string,
     *   host_canonical: ?string,
     *   scheme: ?string,
     *   path: ?string,
     *   query: ?string,
     *   error_code: ?string,
     *   reasons: list<string>
     * }
     */
    public static function canonicalize(string $rawUrl, array $httpWaiverHosts = []): array
    {
        $trimmed = trim($rawUrl);
        if ($trimmed === '' || strlen($trimmed) > 2048) {
            return self::reject('URL_EMPTY_OR_TOO_LONG', ['URL must be between 1 and 2048 characters']);
        }

        // Reject control chars or whitespace inside URL
        if (preg_match('/[\x00-\x20\x7F]/', $trimmed)) {
            return self::reject('UNSAFE_CONTROL_CHARS', ['URL contains control characters or spaces']);
        }

        // Protocol-relative or missing scheme (TV-008)
        if (str_starts_with($trimmed, '//') || !preg_match('/^([a-zA-Z][a-zA-Z0-9+.-]*):/', $trimmed, $schemeMatch)) {
            return self::reject('UNSAFE_SCHEME_OR_RELATIVE', ['Relative URL or missing scheme is prohibited']);
        }

        $scheme = strtolower($schemeMatch[1]);
        if (in_array($scheme, ['javascript', 'data', 'vbscript', 'file', 'ftp', 'blob', 'about'], true)) {
            return self::reject('UNSAFE_SCHEME_OR_RELATIVE', [sprintf('Scheme "%s:" is strictly forbidden', $scheme)]);
        }

        if (!in_array($scheme, ['https', 'http'], true)) {
            return self::reject('UNSAFE_SCHEME_OR_RELATIVE', [sprintf('Unsupported scheme "%s"', $scheme)]);
        }

        // Check for embedded credentials before parse_url (TV-009)
        $afterScheme = substr($trimmed, strlen($scheme) + 3);
        $authorityEnd = strcspn($afterScheme, '/?#');
        $authority = substr($afterScheme, 0, $authorityEnd);
        if (str_contains($authority, '@')) {
            return self::reject('EMBEDDED_CREDENTIALS', ['Embedded userinfo (user:pass@host) is forbidden']);
        }

        $parts = parse_url($trimmed);
        if (!is_array($parts) || empty($parts['host'])) {
            return self::reject('MALFORMED_URL', ['Failed to parse URL authority/host']);
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            return self::reject('EMBEDDED_CREDENTIALS', ['Embedded credentials in URL are forbidden']);
        }

        $rawHost = strtolower(trim((string) $parts['host'], '.'));
        if ($rawHost === '') {
            return self::reject('MALFORMED_HOST', ['Empty hostname']);
        }

        // Reject IPv6 literal [::1] or IPv4 literal or integer/hex IP (TV-010)
        if (
            str_starts_with($rawHost, '[')
            || str_ends_with($rawHost, ']')
            || filter_var($rawHost, FILTER_VALIDATE_IP) !== false
            || preg_match('/^(?:\d+\.){3}\d+$/', $rawHost)
            || preg_match('/^0x[0-9a-f]+$/i', $rawHost)
            || ctype_digit($rawHost)
        ) {
            return self::reject('IP_LITERAL_FORBIDDEN', ['Direct IP literal destinations are forbidden (SSRF/phishing protection)']);
        }

        // IDNA UTS-46 ASCII conversion
        if (function_exists('idn_to_ascii')) {
            $asciiHost = idn_to_ascii($rawHost, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($asciiHost === false || $asciiHost === '') {
                return self::reject('INVALID_IDNA_HOST', ['IDNA domain normalization failed']);
            }
            $host = strtolower($asciiHost);
        } else {
            $host = $rawHost;
        }

        if (
            strlen($host) < 3
            || strlen($host) > 253
            || !str_contains($host, '.')
            || in_array($host, ['localhost', 'localhost.localdomain'], true)
            || str_ends_with($host, '.local')
            || str_ends_with($host, '.internal')
        ) {
            return self::reject('INVALID_HOST', ['Hostname must be a valid public FQDN']);
        }

        // Enforce HTTPS-only unless explicit waiver exists for host (DES-008, TV-007)
        if ($scheme === 'http' && !in_array($host, $httpWaiverHosts, true)) {
            return self::reject('SCHEME_NOT_HTTPS', ['Cleartext http:// is prohibited by DES-008 without active DPO/Security waiver']);
        }

        // Enforce standard port only (TV-011)
        if (isset($parts['port'])) {
            $port = (int) $parts['port'];
            $defaultPort = $scheme === 'https' ? 443 : 80;
            if ($port !== $defaultPort) {
                return self::reject('NON_STANDARD_PORT', [sprintf('Non-standard port %d is forbidden', $port)]);
            }
        }

        // Normalize path (resolve dot segments /./ and /../ and unreserved percent-encoding, TV-006 & TV-013)
        $rawPath = (string) ($parts['path'] ?? '/');
        $normalizedPath = self::normalizePath($rawPath);

        // Normalize query string (strip fragment # per TV-006)
        $query = isset($parts['query']) && $parts['query'] !== ''
            ? self::normalizeQuery((string) $parts['query'])
            : null;

        // Check prohibited PII / secret tokens in path or query (TV-012, THR-004)
        $piiCheck = self::detectProhibitedPiiOrTokens($normalizedPath, $query);
        if ($piiCheck !== null) {
            return self::reject('PROHIBITED_PII_OR_TOKEN_QUERY', [$piiCheck]);
        }

        $canonicalUrl = $scheme . '://' . $host . $normalizedPath . ($query !== null ? '?' . $query : '');

        return [
            'valid' => true,
            'url_canonical' => $canonicalUrl,
            'host_canonical' => $host,
            'scheme' => $scheme,
            'path' => $normalizedPath,
            'query' => $query,
            'error_code' => null,
            'reasons' => [],
        ];
    }

    private static function normalizePath(string $path): string
    {
        if ($path === '') {
            return '/';
        }
        $decodedUnreserved = self::normalizePercentEncoding($path);
        $segments = explode('/', $decodedUnreserved);
        $resolved = [];
        foreach ($segments as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($resolved);
                continue;
            }
            $resolved[] = $seg;
        }
        $TrailingSlash = str_ends_with($decodedUnreserved, '/') && $resolved !== [] ? '/' : '';
        return '/' . implode('/', $resolved) . $TrailingSlash;
    }

    private static function normalizeQuery(string $query): string
    {
        return self::normalizePercentEncoding($query);
    }

    /**
     * Decodes percent-encoded unreserved characters (ALPHA / DIGIT / "-" / "." / "_" / "~", RFC 3986 §2.3)
     * and uppercases remaining hex escapes (TV-013).
     */
    private static function normalizePercentEncoding(string $input): string
    {
        return (string) preg_replace_callback(
            '/%([0-9a-fA-F]{2})/',
            static function (array $m): string {
                $byte = hexdec($m[1]);
                $char = chr($byte);
                if (preg_match('/^[A-Za-z0-9\-._~]$/', $char)) {
                    return $char;
                }
                return '%' . strtoupper($m[1]);
            },
            $input
        );
    }

    private static function detectProhibitedPiiOrTokens(string $path, ?string $query): ?string
    {
        /** @var array<string, mixed> $cfg */
        $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';
        /** @var list<string> $sensitiveKeys */
        $sensitiveKeys = $cfg['sensitive_query_keys'] ?? [];

        $combined = rawurldecode($path . ($query !== null ? '?' . $query : ''));

        // 16-digit Indonesian NIK pattern in URL path or query (TV-012)
        if (preg_match('/(?<!\d)\d{16}(?!\d)/', $combined)) {
            return 'URL contains a 16-digit NIK identifier pattern (prohibited by THR-004)';
        }

        if ($query !== null) {
            parse_str($query, $params);
            foreach (array_keys($params) as $key) {
                $lowerKey = strtolower((string) $key);
                if (in_array($lowerKey, $sensitiveKeys, true)) {
                    return sprintf('Query parameter "%s" is prohibited (PII/credential leakage prevention)', $lowerKey);
                }
            }
        }

        return null;
    }

    /**
     * @param list<string> $reasons
     * @return array{
     *   valid: false,
     *   url_canonical: null,
     *   host_canonical: null,
     *   scheme: null,
     *   path: null,
     *   query: null,
     *   error_code: string,
     *   reasons: list<string>
     * }
     */
    private static function reject(string $code, array $reasons): array
    {
        return [
            'valid' => false,
            'url_canonical' => null,
            'host_canonical' => null,
            'scheme' => null,
            'path' => null,
            'query' => null,
            'error_code' => $code,
            'reasons' => $reasons,
        ];
    }
}

