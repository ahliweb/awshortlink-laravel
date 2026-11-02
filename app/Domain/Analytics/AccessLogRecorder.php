<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

use App\Support\PostgreSql;
use App\Support\UuidV7;
use PDO;
use Throwable;

/**
 * Optional per-visitor telemetry (ADR-0003: aggregate-only is the default).
 *
 * Disabled unless ANALYTICS_RAW_EVENTS_ENABLED=true. When enabled it stores timestamp, a truncated IP
 * (IPv4 /24, IPv6 /48 unless ANALYTICS_STORE_FULL_IP=true), OS, browser, device, coarse geo, the Referer
 * ORIGIN only (paths/queries can carry tokens or personal data) and bot status. Rows are purged by
 * `schedule:run` after ANALYTICS_ACCESS_LOG_RETENTION_DAYS.
 */
final class AccessLogRecorder
{
    /**
     * @param array<string, string> $headers
     */
    public static function record(
        string $linkId,
        array $headers,
        int $botClass = 0,
        ?PDO $pdo = null
    ): bool {
        // Privacy by default: no per-visitor storage unless the operator explicitly opted in.
        $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';
        if (empty($cfg['raw_click_events_enabled'])) {
            return false;
        }

        // Skip synthetic healthcheck probes
        if ($botClass === 3) {
            return false;
        }

        try {
            $telemetry = UserAgentParser::parse($headers);
            $ip = empty($cfg['store_full_ip']) ? self::truncateIp((string) $telemetry['ip']) : (string) $telemetry['ip'];
            $referer = self::refererOrigin((string) $telemetry['referer']);
            $db = $pdo ?? PostgreSql::connection();

            $logId = UuidV7::generate();
            $stmt = $db->prepare("
                INSERT INTO shortlink.link_access_logs (
                    id, link_id, occurred_at, ip_address, country, city, region,
                    latitude, longitude, os, browser, device_type, device_model,
                    user_agent, referer, is_bot
                ) VALUES (
                    :id, :link_id, now(), :ip, :country, :city, :region,
                    :lat, :lon, :os, :browser, :device_type, :device_model,
                    :ua, :referer, :is_bot
                )
            ");

            $stmt->execute([
                ':id' => $logId,
                ':link_id' => $linkId,
                ':ip' => $ip,
                ':country' => $telemetry['country'],
                ':city' => $telemetry['city'],
                ':region' => $telemetry['region'],
                ':lat' => $telemetry['latitude'],
                ':lon' => $telemetry['longitude'],
                ':os' => $telemetry['os'],
                ':browser' => $telemetry['browser'],
                ':device_type' => $telemetry['device_type'],
                ':device_model' => $telemetry['device_model'],
                ':ua' => $telemetry['user_agent'],
                ':referer' => $referer,
                ':is_bot' => ($botClass !== 0) ? 'true' : 'false',
            ]);

            return true;
        } catch (Throwable $e) {
            error_log('ACCESS_LOG_RECORDER_ERROR: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * IPv4 -> /24, IPv6 -> /48 (host bits zeroed).
     */
    public static function truncateIp(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return '';
        }
        if (strlen($bin) === 4) {
            return (string) inet_ntop(substr($bin, 0, 3) . "\0");
        }

        return (string) inet_ntop(substr($bin, 0, 6) . str_repeat("\0", 10));
    }

    /**
     * Reduce a Referer to scheme://host[:port]; anything unparseable becomes ''.
     */
    public static function refererOrigin(string $referer): string
    {
        $parts = parse_url($referer);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || !in_array($parts['scheme'], ['http', 'https'], true)) {
            return '';
        }

        return $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
}
