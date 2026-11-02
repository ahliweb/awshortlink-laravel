<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Deployment identity (organisation name, public URL, logo) read from the environment so one codebase can
 * serve any organisation. Nothing about a specific deployment is embedded in the source.
 *
 * Templates carry @@PLACEHOLDER@@ tokens that {@see self::apply()} resolves, HTML-escaped, at the response
 * boundary (text/html and image/svg+xml only).
 */
final class Branding
{
    public static function orgName(): string
    {
        return self::env('BRAND_ORG_NAME', 'Your Organization');
    }

    public static function orgShort(): string
    {
        return self::env('BRAND_ORG_SHORT', 'Your Org');
    }

    public static function rootUnitCode(): string
    {
        $code = strtoupper(self::env('BRAND_ROOT_UNIT_CODE', 'ROOT'));

        return preg_match('/^[A-Z0-9_]{2,32}$/', $code) === 1 ? $code : 'ROOT';
    }

    /**
     * Absolute public base URL including the path prefix, no trailing slash (e.g. https://links.example.org/buka).
     * In production it must be an https URL; otherwise QR codes and canonical links would be wrong, so fail closed.
     */
    public static function publicBaseUrl(): string
    {
        $url = rtrim(self::env('APP_URL', 'http://localhost/buka'), '/');
        $parts = parse_url($url);
        $isProd = (getenv('APP_ENV') ?: '') === 'production';
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])
            || !in_array($parts['scheme'], ['http', 'https'], true)
            || ($isProd && $parts['scheme'] !== 'https')) {
            throw new \RuntimeException('APP_URL must be an absolute https URL in production (e.g. https://links.example.org/buka).');
        }

        return $url;
    }

    /**
     * Non-throwing variant for error paths (problem+json): falls back to 'about:blank' on a bad APP_URL.
     */
    public static function safePublicBaseUrl(): string
    {
        try {
            return self::publicBaseUrl();
        } catch (\RuntimeException) {
            return 'about:blank';
        }
    }

    public static function publicHost(): string
    {
        return (string) parse_url(self::publicBaseUrl(), PHP_URL_HOST);
    }

    public static function logoUrl(): string
    {
        return self::env('BRAND_LOGO_URL', self::publicBaseUrl() . '/assets/images/brand-logo.png');
    }

    /**
     * Local file used for the favicon and the QR centre logo; never a remote URL.
     */
    public static function logoPath(): ?string
    {
        $candidates = [];
        $configured = self::env('BRAND_LOGO_PATH', '');
        if ($configured !== '') {
            $candidates[] = $configured;
        }
        $root = dirname(__DIR__, 2);
        $candidates[] = $root . '/public/assets/images/brand-logo.png';
        $candidates[] = $root . '/assets/images/brand-logo.png';
        foreach ($candidates as $path) {
            if (is_file($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Resolve @@TOKEN@@ placeholders in a rendered template.
     */
    public static function apply(string $body): string
    {
        if (!str_contains($body, '@@')) {
            return $body;
        }
        $esc = static fn (string $v): string => htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return strtr($body, [
            '@@ORG_NAME@@' => $esc(self::orgName()),
            '@@ORG_SHORT@@' => $esc(self::orgShort()),
            '@@PUBLIC_HOST@@' => $esc(self::publicHost()),
            '@@PUBLIC_BASE_URL@@' => $esc(self::publicBaseUrl()),
            '@@LOGO_URL@@' => $esc(self::logoUrl()),
        ]);
    }

    private static function env(string $key, string $default): string
    {
        $value = getenv($key);

        return ($value === false || trim($value) === '') ? $default : trim($value);
    }
}
