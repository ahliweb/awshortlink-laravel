<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

/**
 * Lightweight, privacy-conscious User-Agent & Telemetry Parser for detailed per-link visitor analytics.
 * Extracts IP, OS, Browser, Device Type & Model, and Geo-Location (via Cloudflare headers or fallback).
 */
final class UserAgentParser
{
    /**
     * @param array<string, string> $headers
     * @return array{
     *   ip: string,
     *   country: string,
     *   city: string,
     *   region: string,
     *   latitude: ?float,
     *   longitude: ?float,
     *   os: string,
     *   browser: string,
     *   device_type: 'Mobile'|'Tablet'|'Desktop'|'Bot',
     *   device_model: string,
     *   user_agent: string,
     *   referer: string,
     *   is_bot: bool
     * }
     */
    public static function parse(array $headers): array
    {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[strtolower((string) $k)] = trim((string) $v);
        }

        // 1. IP Address Resolution
        $ip = self::resolveIp($h);

        // 2. User Agent
        $ua = $h['user-agent'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');

        // 3. Referer
        $referer = $h['referer'] ?? ($_SERVER['HTTP_REFERER'] ?? 'Langsung / Direct');
        if (trim($referer) === '') {
            $referer = 'Langsung / Direct';
        }

        // 4. Bot Classification
        $botClass = BotClassifier::classify($h);
        $isBot = ($botClass !== 0);

        // 5. Operating System (OS)
        $os = self::detectOs($ua);

        // 6. Browser
        $browser = self::detectBrowser($ua);

        // 7. Device Type & Model
        $device = self::detectDevice($ua, $isBot);

        // 8. Geo Location (Cloudflare headers or localized fallback)
        $geo = self::detectGeo($h, $ip);

        return [
            'ip' => $ip,
            'country' => $geo['country'],
            'city' => $geo['city'],
            'region' => $geo['region'],
            'latitude' => $geo['latitude'],
            'longitude' => $geo['longitude'],
            'os' => $os,
            'browser' => $browser,
            'device_type' => $device['type'],
            'device_model' => $device['model'],
            'user_agent' => $ua,
            'referer' => $referer,
            'is_bot' => $isBot,
        ];
    }

    /**
     * Resolves the client IP address.
     *
     * SECURITY: forwarding headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are client-controlled unless
     * the request really came through a proxy we operate. They are therefore honoured ONLY when the immediate
     * peer (REMOTE_ADDR) is listed in `trusted_proxies` (env TRUSTED_PROXIES). Otherwise REMOTE_ADDR is used, so
     * an attacker cannot rotate forged IPs to evade the login rate limiter or pollute analytics.
     *
     * @param array<string, string> $h lower-cased request headers
     */
    public static function resolveIp(array $h): string
    {
        $remote = self::remoteAddr();
        $trusted = self::trustedProxies();
        if ($trusted === [] || !self::ipInCidrs($remote, $trusted)) {
            return $remote;
        }

        $cf = trim((string) ($h['cf-connecting-ip'] ?? ''));
        if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) {
            return $cf;
        }

        // X-Forwarded-For: walk right-to-left, skipping our own proxies; the first foreign hop is the client.
        $xff = (string) ($h['x-forwarded-for'] ?? '');
        if ($xff !== '') {
            foreach (array_reverse(explode(',', $xff)) as $hop) {
                $hop = trim($hop);
                if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                    break;
                }
                if (!self::ipInCidrs($hop, $trusted)) {
                    return $hop;
                }
            }
        }

        $real = trim((string) ($h['x-real-ip'] ?? ''));
        if ($real !== '' && filter_var($real, FILTER_VALIDATE_IP)) {
            return $real;
        }

        return $remote;
    }

    /**
     * True when the immediate peer is a configured trusted proxy (so proxy-supplied geo headers can be believed).
     */
    private static function peerIsTrusted(): bool
    {
        $trusted = self::trustedProxies();

        return $trusted !== [] && self::ipInCidrs(self::remoteAddr(), $trusted);
    }

    private static function remoteAddr(): string
    {
        $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

        return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '127.0.0.1';
    }

    /**
     * @return list<string>
     */
    private static function trustedProxies(): array
    {
        $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';

        return array_values(array_filter((array) ($cfg['trusted_proxies'] ?? []), 'is_string'));
    }

    /**
     * @param list<string> $cidrs entries are "ip" or "ip/prefix" (IPv4 or IPv6)
     */
    public static function ipInCidrs(string $ip, array $cidrs): bool
    {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            [$net, $prefix] = array_pad(explode('/', $cidr, 2), 2, null);
            $netBin = @inet_pton((string) $net);
            if ($netBin === false || strlen($netBin) !== strlen($ipBin)) {
                continue;
            }
            $bits = strlen($netBin) * 8;
            $prefix = ($prefix === null || $prefix === '') ? $bits : (int) $prefix;
            if ($prefix < 0 || $prefix > $bits) {
                continue;
            }
            $fullBytes = intdiv($prefix, 8);
            if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($netBin, 0, $fullBytes)) {
                continue;
            }
            $rem = $prefix % 8;
            if ($rem === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rem)) & 0xFF;
            if ((ord($ipBin[$fullBytes]) & $mask) === (ord($netBin[$fullBytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Alias for resolveIp.
     *
     * @param array<string, string> $h
     */
    public static function clientIp(array $h): string
    {
        $lower = [];
        foreach ($h as $k => $v) {
            $lower[strtolower((string) $k)] = trim((string) $v);
        }

        return self::resolveIp($lower);
    }

    /**
     * Detects Operating System from User-Agent.
     */
    public static function detectOs(string $ua): string
    {
        if (preg_match('/Android\s*([0-9\.]+)?/i', $ua, $m)) {
            return !empty($m[1]) ? 'Android ' . $m[1] : 'Android';
        }
        if (preg_match('/iPhone OS\s*([0-9_]+)/i', $ua, $m)) {
            return 'iOS ' . str_replace('_', '.', $m[1]);
        }
        if (preg_match('/iPad.*OS\s*([0-9_]+)/i', $ua, $m)) {
            return 'iPadOS ' . str_replace('_', '.', $m[1]);
        }
        if (str_contains($ua, 'Windows NT 10.0')) {
            return 'Windows 10 / 11';
        }
        if (str_contains($ua, 'Windows NT 6.3')) {
            return 'Windows 8.1';
        }
        if (str_contains($ua, 'Windows NT 6.1')) {
            return 'Windows 7';
        }
        if (str_contains($ua, 'Windows NT')) {
            return 'Windows';
        }
        if (preg_match('/Mac OS X\s*([0-9_]+)/i', $ua, $m)) {
            return 'macOS ' . str_replace('_', '.', $m[1]);
        }
        if (str_contains($ua, 'CrOS')) {
            return 'ChromeOS';
        }
        if (str_contains($ua, 'Ubuntu')) {
            return 'Ubuntu Linux';
        }
        if (str_contains($ua, 'Linux')) {
            return 'Linux';
        }
        return 'Lainnya / OS Tidak Dikenal';
    }

    /**
     * Detects Browser from User-Agent.
     */
    public static function detectBrowser(string $ua): string
    {
        if (preg_match('/Edg[eA]?\/([0-9\.]+)/i', $ua, $m)) {
            return 'Microsoft Edge ' . explode('.', $m[1])[0];
        }
        if (preg_match('/SamsungBrowser\/([0-9\.]+)/i', $ua, $m)) {
            return 'Samsung Internet ' . explode('.', $m[1])[0];
        }
        if (preg_match('/UCBrowser\/([0-9\.]+)/i', $ua, $m)) {
            return 'UC Browser ' . explode('.', $m[1])[0];
        }
        if (preg_match('/OPR\/([0-9\.]+)/i', $ua, $m)) {
            return 'Opera ' . explode('.', $m[1])[0];
        }
        if (str_contains($ua, 'WhatsApp/')) {
            return 'WhatsApp In-App';
        }
        if (str_contains($ua, 'Instagram')) {
            return 'Instagram In-App';
        }
        if (str_contains($ua, 'FBAN') || str_contains($ua, 'FBAV')) {
            return 'Facebook In-App';
        }
        if (preg_match('/Chrome\/([0-9\.]+)/i', $ua, $m)) {
            return 'Google Chrome ' . explode('.', $m[1])[0];
        }
        if (preg_match('/Firefox\/([0-9\.]+)/i', $ua, $m)) {
            return 'Mozilla Firefox ' . explode('.', $m[1])[0];
        }
        if (preg_match('/Version\/([0-9\.]+).*Safari/i', $ua, $m)) {
            return 'Apple Safari ' . explode('.', $m[1])[0];
        }
        if (str_contains($ua, 'Safari') && !str_contains($ua, 'Chrome')) {
            return 'Safari Mobile';
        }
        if (str_contains($ua, 'curl/')) {
            return 'cURL CLI';
        }
        if (str_contains($ua, 'Googlebot')) {
            return 'Googlebot Crawler';
        }
        return 'Peramban Standar';
    }

    /**
     * Detects Device Type and Device Model.
     *
     * @return array{type: 'Mobile'|'Tablet'|'Desktop'|'Bot', model: string}
     */
    public static function detectDevice(string $ua, bool $isBot): array
    {
        if ($isBot) {
            return ['type' => 'Bot', 'model' => 'Mesin / Web Crawler'];
        }

        $type = 'Desktop';
        $model = 'PC / Laptop Desktop';

        if (preg_match('/iPad/i', $ua)) {
            $type = 'Tablet';
            $model = 'Apple iPad';
        } elseif (preg_match('/Tablet|SM-T/i', $ua)) {
            $type = 'Tablet';
            $model = 'Tablet Android';
        } elseif (preg_match('/iPhone/i', $ua)) {
            $type = 'Mobile';
            $model = 'Apple iPhone';
        } elseif (preg_match('/Android/i', $ua)) {
            $type = 'Mobile';
            if (preg_match('/SM-[A-Z0-9]+/i', $ua, $m)) {
                $model = 'Samsung ' . strtoupper($m[0]);
            } elseif (preg_match('/Redmi[^\s;)]+/i', $ua, $m)) {
                $model = 'Xiaomi ' . $m[0];
            } elseif (preg_match('/POCO[^\s;)]+/i', $ua, $m)) {
                $model = 'Xiaomi ' . $m[0];
            } elseif (preg_match('/CPH[0-9]+/i', $ua, $m)) {
                $model = 'OPPO Smartphone';
            } elseif (preg_match('/vivo/i', $ua)) {
                $model = 'Vivo Smartphone';
            } elseif (preg_match('/Pixel\s*[0-9]+/i', $ua, $m)) {
                $model = 'Google ' . $m[0];
            } elseif (preg_match('/Infinix/i', $ua)) {
                $model = 'Infinix Smartphone';
            } else {
                $model = 'Android Smartphone';
            }
        } elseif (preg_match('/Macintosh/i', $ua)) {
            $type = 'Desktop';
            $model = 'Apple Mac';
        } elseif (preg_match('/Windows/i', $ua)) {
            $type = 'Desktop';
            $model = 'Windows PC';
        }

        return ['type' => $type, 'model' => $model];
    }

    /**
     * Detects Geo Location (Country, City, Region, Coordinates) from Cloudflare geo headers, which are only
     * believed when the request came through a trusted proxy. Otherwise values are 'Unknown'/null: nothing is
     * fabricated.
     *
     * @param array<string, string> $h
     * @return array{country: string, city: string, region: string, latitude: ?float, longitude: ?float}
     */
    private static function detectGeo(array $h, string $ip): array
    {
        // Cloudflare IP headers
        $cfCountry = strtoupper(trim((string) ($h['cf-ipcountry'] ?? ($_SERVER['HTTP_CF_IPCOUNTRY'] ?? ''))));
        $cfCity = trim((string) ($h['cf-ipcity'] ?? ($_SERVER['HTTP_CF_IPCITY'] ?? '')));
        $cfRegion = trim((string) ($h['cf-region'] ?? ($_SERVER['HTTP_CF_REGION'] ?? '')));
        $cfLat = trim((string) ($h['cf-iplatitude'] ?? ($_SERVER['HTTP_CF_IPLATITUDE'] ?? '')));
        $cfLon = trim((string) ($h['cf-iplongitude'] ?? ($_SERVER['HTTP_CF_IPLONGITUDE'] ?? '')));
        if (!self::peerIsTrusted()) {
            $cfCountry = $cfCity = $cfRegion = $cfLat = $cfLon = '';
        }

        $countryMap = [
            'ID' => 'Indonesia',
            'SG' => 'Singapura',
            'MY' => 'Malaysia',
            'US' => 'Amerika Serikat',
            'JP' => 'Jepang',
            'AU' => 'Australia',
            'GB' => 'Inggris Raya',
            'DE' => 'Jerman',
            'NL' => 'Belanda',
        ];

        $country = $cfCountry !== '' ? ($countryMap[$cfCountry] ?? $cfCountry) : 'Unknown';
        $city = $cfCity !== '' ? urldecode($cfCity) : 'Unknown';
        $region = $cfRegion !== '' ? urldecode($cfRegion) : 'Unknown';
        $lat = ($cfLat !== '' && is_numeric($cfLat)) ? (float) $cfLat : null;
        $lon = ($cfLon !== '' && is_numeric($cfLon)) ? (float) $cfLon : null;

        return [
            'country' => $country,
            'city' => $city,
            'region' => $region,
            'latitude' => $lat,
            'longitude' => $lon,
        ];
    }
}
