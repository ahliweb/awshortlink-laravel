<?php

declare(strict_types=1);

/**
 * Comma-separated environment list -> normalised list of non-empty lowercase strings.
 *
 * @return list<string>
 */
$envList = static function (string $key, string $default = ''): array {
    $raw = getenv($key);
    $raw = ($raw === false) ? $default : $raw;

    return array_values(array_filter(
        array_map(static fn (string $v): string => strtolower(trim($v)), explode(',', $raw)),
        static fn (string $v): bool => $v !== ''
    ));
};

return [
    'app_version' => '1.1.0',
    'namespace' => 'buka',
    'base_path' => '/buka',
    'admin_path' => '/buka/admin',
    'api_base_path' => '/buka/api/v1',
    'livewire_update_path' => '/buka/livewire/update',
    'livewire_asset_url' => '/buka/livewire/livewire.js',

    // Slug policy (ALG-001, DES-013)
    'slug_min_length' => 3,
    'slug_max_length' => 64,
    'reserved_slugs' => [
        'admin', 'api', 'login', 'logout', 'livewire', 'qr', 'preview',
        'build', 'storage', 'assets', 'health', '.env', 'artisan', 'laporan',
    ],

    // Destination policy defaults (ALG-002, DES-008, DES-014).
    // The institutional allowlist is EMPTY by default; set SHORTLINK_ALLOWLIST_HOSTS to a comma-separated list of
    // hosts / wildcard patterns you own (e.g. "example.org,*.example.org"). Hosts where anyone can publish content
    // (file-sharing, form builders) must not be allowlisted as low risk.
    'institutional_allowlist_hosts' => $envList('SHORTLINK_ALLOWLIST_HOSTS'),
    'medium_risk_suffixes' => $envList('SHORTLINK_MEDIUM_RISK_SUFFIXES', '.go.id,.ac.id'),
    'known_shortener_hosts' => [
        'bit.ly', 'tinyurl.com', 't.co', 's.id', 'rebrand.ly', 'cutt.ly', 'is.gd', 'ow.ly',
    ],
    'sensitive_query_keys' => [
        'token', 'access_token', 'id_token', 'refresh_token', 'sig', 'signature',
        'password', 'passwd', 'secret', 'session', 'session_id', 'nik', 'no_rm', 'rm', 'rekam_medis',
    ],

    // Analytics & privacy policy (ADR-0003, DES-005, DES-007).
    // Per-visitor telemetry (link_access_logs) is OFF unless ANALYTICS_RAW_EVENTS_ENABLED=true. When on, IPs are
    // truncated unless ANALYTICS_STORE_FULL_IP=true, the Referer is reduced to its origin, and rows older than
    // ANALYTICS_ACCESS_LOG_RETENTION_DAYS are purged by `schedule:run`.
    'cohort_suppression_threshold' => 10,
    'raw_click_events_enabled' => filter_var(getenv('ANALYTICS_RAW_EVENTS_ENABLED') ?: 'false', FILTER_VALIDATE_BOOLEAN),
    'store_full_ip' => filter_var(getenv('ANALYTICS_STORE_FULL_IP') ?: 'false', FILTER_VALIDATE_BOOLEAN),
    'access_log_retention_days' => max(1, (int) (getenv('ANALYTICS_ACCESS_LOG_RETENTION_DAYS') ?: 90)),
    'retention_daily_months' => 13,

    // Reverse proxies whose forwarding headers may be trusted (comma-separated IPs/CIDRs). Empty = trust none and
    // use REMOTE_ADDR. Without this, anyone can forge their IP and defeat the login rate limiter.
    'trusted_proxies' => $envList('TRUSTED_PROXIES'),

    // Session & MFA policy (DES-006, DES-012)
    'session_idle_minutes' => 30,
    'session_absolute_minutes' => 480,
    'mfa_totp_required' => true,

    // Audit chain genesis constant (11.4). Must match database/sql/rls/0030_resolver_view_and_click_fn.sql.
    'audit_genesis_constant' => 'AWSHORTLINK-GENESIS-V1',
];
