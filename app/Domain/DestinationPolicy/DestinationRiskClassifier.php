<?php

declare(strict_types=1);

namespace App\Domain\DestinationPolicy;

use PDO;

/**
 * ALG-002 (Part 2): Destination Risk Classifier & Institutional Domain Policy (SPEC-07, DES-014, #13).
 */
final class DestinationRiskClassifier
{
    /**
     * Evaluates a raw destination URL against `UrlCanonicalizer` and `destination_domain_rules` (plus config defaults).
     *
     * @return array{
     *   allowed: bool,
     *   requires_approval: bool,
     *   risk_class: 'low'|'medium'|'high'|'forbidden',
     *   url_canonical: ?string,
     *   host_canonical: ?string,
     *   error_code: ?string,
     *   reasons: list<string>
     * }
     */
    public static function evaluate(string $rawUrl, ?PDO $db = null): array
    {
        /** @var array<string, mixed> $cfg */
        $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';
        /** @var list<string> $allowHosts */
        $allowHosts = $cfg['institutional_allowlist_hosts'] ?? [];
        /** @var list<string> $mediumSuffixes */
        $mediumSuffixes = $cfg['medium_risk_suffixes'] ?? [];
        /** @var list<string> $shortenerHosts */
        $shortenerHosts = $cfg['known_shortener_hosts'] ?? [];
        $httpWaiverHosts = [];

        $dbRules = [];
        if ($db !== null) {
            $stmt = $db->query(
                'SELECT host_pattern, rule_type, reason
                 FROM shortlink.destination_domain_rules
                 WHERE expires_at IS NULL OR expires_at > now()'
            );
            /** @var list<array{host_pattern: string, rule_type: string, reason: string}> $dbRules */
            $dbRules = $stmt->fetchAll();
            foreach ($dbRules as $rule) {
                if ($rule['rule_type'] === 'http_waiver') {
                    $httpWaiverHosts[] = strtolower($rule['host_pattern']);
                }
            }
        }

        $canon = UrlCanonicalizer::canonicalize($rawUrl, $httpWaiverHosts);
        if (!$canon['valid'] || $canon['host_canonical'] === null || $canon['url_canonical'] === null) {
            return [
                'allowed' => false,
                'requires_approval' => false,
                'risk_class' => 'forbidden',
                'url_canonical' => null,
                'host_canonical' => null,
                'error_code' => $canon['error_code'] ?? 'INVALID_URL',
                'reasons' => $canon['reasons'],
            ];
        }

        $host = $canon['host_canonical'];

        // 1. Check chained URL shortener denylist (TV-014)
        foreach ($shortenerHosts as $shortener) {
            if ($host === $shortener || str_ends_with($host, '.' . $shortener)) {
                return [
                    'allowed' => false,
                    'requires_approval' => false,
                    'risk_class' => 'forbidden',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => 'CHAINED_SHORTENER_FORBIDDEN',
                    'reasons' => [sprintf('Host "%s" is a public URL shortener (redirect chains are forbidden)', $host)],
                ];
            }
        }

        // 2. Check DB denylist rules first
        foreach ($dbRules as $rule) {
            if ($rule['rule_type'] === 'denylist_forbidden' && self::matchesPattern($host, $rule['host_pattern'])) {
                return [
                    'allowed' => false,
                    'requires_approval' => false,
                    'risk_class' => 'forbidden',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => 'DOMAIN_DENYLISTED',
                    'reasons' => [$rule['reason']],
                ];
            }
        }

        // 3. Check institutional low-risk allowlist (DES-014: operator-configured SHORTLINK_ALLOWLIST_HOSTS)
        foreach ($allowHosts as $allowHost) {
            if ($host === $allowHost || str_ends_with($host, '.' . $allowHost)) {
                return [
                    'allowed' => true,
                    'requires_approval' => false,
                    'risk_class' => 'low',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => null,
                    'reasons' => ['Institutional allowlist match (DES-014 low risk)'],
                ];
            }
        }

        foreach ($dbRules as $rule) {
            if ($rule['rule_type'] === 'allowlist_low' && self::matchesPattern($host, $rule['host_pattern'])) {
                return [
                    'allowed' => true,
                    'requires_approval' => false,
                    'risk_class' => 'low',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => null,
                    'reasons' => [$rule['reason']],
                ];
            }
        }

        // 4. Check medium-risk government/academic domains (*.go.id, *.ac.id — TV-013)
        foreach ($mediumSuffixes as $suffix) {
            if (str_ends_with($host, $suffix)) {
                return [
                    'allowed' => true,
                    'requires_approval' => true,
                    'risk_class' => 'medium',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => null,
                    'reasons' => [sprintf('External government/academic domain (%s) requires independent approval', $suffix)],
                ];
            }
        }

        foreach ($dbRules as $rule) {
            if ($rule['rule_type'] === 'medium_review' && self::matchesPattern($host, $rule['host_pattern'])) {
                return [
                    'allowed' => true,
                    'requires_approval' => true,
                    'risk_class' => 'medium',
                    'url_canonical' => $canon['url_canonical'],
                    'host_canonical' => $host,
                    'error_code' => null,
                    'reasons' => [$rule['reason']],
                ];
            }
        }

        // 5. All other valid HTTPS public domains are high-risk and require independent approver + expiry
        return [
            'allowed' => true,
            'requires_approval' => true,
            'risk_class' => 'high',
            'url_canonical' => $canon['url_canonical'],
            'host_canonical' => $host,
            'error_code' => null,
            'reasons' => ['External non-governmental domain classified as high risk; requires independent approval and expiry'],
        ];
    }

    public static function matchesPattern(string $host, string $pattern): bool
    {
        $p = strtolower(trim($pattern));
        $h = strtolower(trim($host));
        if ($p === $h) {
            return true;
        }
        if (str_starts_with($p, '*.')) {
            $suffix = substr($p, 1); // .example.go.id
            return str_ends_with($h, $suffix);
        }
        return false;
    }
}

