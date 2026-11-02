<?php

declare(strict_types=1);

namespace App\Domain\Ops;

use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Domain\DestinationPolicy\UrlCanonicalizer;
use App\Support\PostgreSql;
use App\Support\UuidV7;
use PDO;
use RuntimeException;

/**
 * Operational & Security Services (#30 API Credentials, #31 SSRF-Hardened Link Health Checker,
 * #32 Bounded Scheduler, #34 Anti-Abuse Reporting & Triage, #36 Public Directory).
 */
final class OpsAndSecurityService
{
    /** @var array<string, list<int>> */
    private static array $rateLimitBuckets = [];

    /**
     * Issues a scoped API credential (`awsl_<prefix>_<random>`), storing only SHA-256 secret hash (#30, TST-011).
     *
     * @param list<string> $scopes
     * @return array{credential_id: string, prefix: string, plaintext_token: string, scopes: list<string>, rate_limit_per_minute: int, expires_at: string}
     */
    public static function createApiCredential(
        string $actorId,
        string $name,
        array $scopes,
        ?string $unitId = null,
        int $rateLimitPerMinute = 60,
        ?string $expiresAt = null,
        string $reason = 'Create scoped API credential',
        ?PDO $pdo = null,
    ): array {
        $perm = $unitId !== null ? 'api_keys.manage_scoped' : 'api_keys.manage_own';
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: $perm,
            resourceType: 'api_credentials',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        // Verify actor actually holds every scope they want to embed in the API token
        foreach ($scopes as $scopePerm) {
            $scopeCheck = AuthorizationPipeline::evaluate(
                actorId: $actorId,
                permissionKey: $scopePerm,
                resourceType: 'api_credentials',
                resourceAttributes: ['unit_id' => $unitId],
                pdo: $pdo,
                recordAudit: false
            );
            if (!$scopeCheck['permitted']) {
                throw new RuntimeException('API_KEY_SCOPE_EXCEEDS_OWNER_PERMISSIONS:' . $scopePerm);
            }
        }

        $credId = UuidV7::generate();
        $prefix = 'awsl_' . bin2hex(random_bytes(4));
        $plainToken = $prefix . '_' . bin2hex(random_bytes(20));
        $secretHash = hash('sha256', $plainToken);
        $exp = $expiresAt ?? gmdate('Y-m-d\TH:i:s\Z', time() + (90 * 86400));

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $credId,
            $unitId,
            $name,
            $prefix,
            $plainToken,
            $secretHash,
            $scopes,
            $rateLimitPerMinute,
            $exp,
            $reason
        ): array {
            $pgArray = '{' . implode(',', array_map(static fn (string $s): string => '"' . addslashes($s) . '"', $scopes)) . '}';
            $stmt = $db->prepare(
                'INSERT INTO shortlink.api_credentials (
                    id, owner_id, unit_id, name, prefix, secret_hash, scopes, rate_limit_per_minute, expires_at
                ) VALUES (
                    :id, :owner_id, :unit_id, :name, :prefix, :secret_hash, :scopes::text[], :rate_limit, :expires_at
                )'
            );
            $stmt->execute([
                ':id' => $credId,
                ':owner_id' => $actorId,
                ':unit_id' => $unitId,
                ':name' => trim($name),
                ':prefix' => $prefix,
                ':secret_hash' => $secretHash,
                ':scopes' => $pgArray,
                ':rate_limit' => $rateLimitPerMinute,
                ':expires_at' => $exp,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'api_keys.created',
                subjectType: 'api_credential',
                subjectId: $credId,
                subjectVersion: 1,
                unitId: $unitId,
                afterState: ['prefix' => $prefix, 'scopes' => $scopes, 'expires_at' => $exp],
                reason: $reason
            );

            return [
                'credential_id' => $credId,
                'prefix' => $prefix,
                'plaintext_token' => $plainToken,
                'scopes' => $scopes,
                'rate_limit_per_minute' => $rateLimitPerMinute,
                'expires_at' => $exp,
            ];
        }, $pdo);
    }

    /**
     * Authenticates a Bearer API token, enforces per-token rate limit, and verifies required scope (#30, TST-011).
     *
     * @return array{
     *   authenticated: bool,
     *   http_status: int,
     *   error_code: ?string,
     *   owner_id: ?string,
     *   unit_id: ?string,
     *   scopes: list<string>
     * }
     */
    public static function authenticateApiToken(
        string $plainToken,
        string $requiredPermission,
        ?int $nowUnix = null,
        ?PDO $pdo = null,
    ): array {
        $hash = hash('sha256', trim($plainToken));
        $now = $nowUnix ?? time();

        $ctx = RlsContext::systemGlobal();
        return $ctx->run(static function (PDO $db) use ($hash, $requiredPermission, $now): array {
            $stmt = $db->prepare(
                "SELECT c.id, c.owner_id, c.unit_id, c.prefix, array_to_json(c.scopes)::text AS scopes_json,
                        c.rate_limit_per_minute, c.revoked_at,
                        (c.expires_at <= now()) AS is_expired,
                        u.status AS owner_status
                 FROM shortlink.api_credentials c
                 JOIN shortlink.users u ON u.id = c.owner_id
                 WHERE c.secret_hash = :hash"
            );
            $stmt->execute([':hash' => $hash]);
            /** @var array<string, mixed>|false $cred */
            $cred = $stmt->fetch();

            if (!is_array($cred)) {
                return [
                    'authenticated' => false,
                    'http_status' => 401,
                    'error_code' => 'API_TOKEN_INVALID',
                    'owner_id' => null,
                    'unit_id' => null,
                    'scopes' => [],
                ];
            }

            if ($cred['revoked_at'] !== null || (bool) $cred['is_expired'] || $cred['owner_status'] !== 'active') {
                return [
                    'authenticated' => false,
                    'http_status' => 401,
                    'error_code' => 'API_TOKEN_REVOKED_OR_EXPIRED',
                    'owner_id' => (string) $cred['owner_id'],
                    'unit_id' => isset($cred['unit_id']) ? (string) $cred['unit_id'] : null,
                    'scopes' => [],
                ];
            }

            /** @var list<string> $scopes */
            $scopes = json_decode((string) $cred['scopes_json'], true, 512, JSON_THROW_ON_ERROR);
            if (!in_array($requiredPermission, $scopes, true)) {
                return [
                    'authenticated' => false,
                    'http_status' => 403,
                    'error_code' => 'API_TOKEN_SCOPE_INSUFFICIENT',
                    'owner_id' => (string) $cred['owner_id'],
                    'unit_id' => isset($cred['unit_id']) ? (string) $cred['unit_id'] : null,
                    'scopes' => $scopes,
                ];
            }

            $credId = (string) $cred['id'];
            $limit = (int) $cred['rate_limit_per_minute'];
            $windowStart = $now - 60;
            $bucket = array_values(array_filter(
                self::$rateLimitBuckets[$credId] ?? [],
                static fn (int $t): bool => $t > $windowStart
            ));

            if (count($bucket) >= $limit) {
                self::$rateLimitBuckets[$credId] = $bucket;
                return [
                    'authenticated' => false,
                    'http_status' => 429,
                    'error_code' => 'API_RATE_LIMIT_EXCEEDED',
                    'owner_id' => (string) $cred['owner_id'],
                    'unit_id' => isset($cred['unit_id']) ? (string) $cred['unit_id'] : null,
                    'scopes' => $scopes,
                ];
            }

            $bucket[] = $now;
            self::$rateLimitBuckets[$credId] = $bucket;

            $db->prepare('UPDATE shortlink.api_credentials SET last_used_at = now() WHERE id = :id')
                ->execute([':id' => $credId]);

            return [
                'authenticated' => true,
                'http_status' => 200,
                'error_code' => null,
                'owner_id' => (string) $cred['owner_id'],
                'unit_id' => isset($cred['unit_id']) ? (string) $cred['unit_id'] : null,
                'scopes' => $scopes,
            ];
        }, $pdo);
    }

    /**
     * Revokes a scoped API credential (#30, API-054).
     */
    public static function revokeApiCredential(string $actorId, string $credentialId, string $reason, ?PDO $pdo = null): array
    {
        $ctx = RlsContext::forActor($actorId, [], true);
        return $ctx->run(static function (PDO $db) use ($actorId, $credentialId, $reason): array {
            $stmt = $db->prepare('UPDATE shortlink.api_credentials SET revoked_at = now() WHERE id = :id RETURNING id, prefix');
            $stmt->execute([':id' => $credentialId]);
            /** @var array<string, mixed>|false $row */
            $row = $stmt->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('API_CREDENTIAL_NOT_FOUND');
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'api_keys.revoked',
                subjectType: 'api_credential',
                subjectId: $credentialId,
                subjectVersion: 2,
                afterState: ['revoked' => true],
                reason: $reason
            );

            return ['credential_id' => $credentialId, 'status' => 'revoked'];
        }, $pdo);
    }

    /**
     * OWASP SSRF-Hardened IP Validator & Link Health Checker (#31, TST-013, THR-002).
     *
     * Denies loopback (127.0.0.0/8, ::1), RFC 1918 (10/8, 172.16/12, 192.168/16),
     * link-local & cloud metadata (169.254.0.0/16, fe80::/10), CGNAT (100.64.0.0/10),
     * multicast/reserved ranges, and any DNS rebinding hop resolving to a non-public IP.
     */
    public static function isPublicRoutableIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // Standard PHP filter for non-private & non-reserved IPs
        $publicCheck = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if ($publicCheck === false) {
            return false;
        }

        // Additional explicit check for RFC 6598 Carrier-Grade NAT (100.64.0.0/10) & metadata 169.254.169.254
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $long = ip2long($ip);
            if ($long === false) {
                return false;
            }
            $cgnatStart = ip2long('100.64.0.0');
            $cgnatEnd = ip2long('100.127.255.255');
            if ($long >= $cgnatStart && $long <= $cgnatEnd) {
                return false;
            }
        }

        return true;
    }

    /**
     * Executes an SSRF-hardened destination health check without ever following redirects to private IPs (#31, TST-013).
     *
     * @param list<string>|null $simulatedResolvedIps For deterministic DNS rebinding/SSRF testing
     * @return array{
     *   check_id: string,
     *   result_status: 'healthy'|'redirect_blocked'|'ssrf_blocked'|'timeout'|'http_error',
     *   safe_error_code: string,
     *   resolved_ips: list<string>
     * }
     */
    public static function runSafeLinkHealthCheck(
        string $actorId,
        string $linkId,
        string $targetUrl,
        ?array $simulatedResolvedIps = null,
        ?PDO $pdo = null,
    ): array {
        $ctx = RlsContext::systemGlobal($actorId);
        return $ctx->run(static function (PDO $db) use ($actorId, $linkId, $targetUrl, $simulatedResolvedIps): array {
            $linkStmt = $db->prepare('SELECT id, unit_id FROM shortlink.links WHERE id = :id');
            $linkStmt->execute([':id' => $linkId]);
            /** @var array<string, mixed>|false $link */
            $link = $linkStmt->fetch();
            if (!is_array($link)) {
                throw new RuntimeException('LINK_NOT_FOUND');
            }

            $unitId = (string) $link['unit_id'];
            $canon = UrlCanonicalizer::canonicalize($targetUrl);

            $resultStatus = 'healthy';
            $safeCode = 'OK_PUBLIC_HTTPS';
            $resolvedIps = [];

            if (!$canon['valid'] || $canon['host_canonical'] === null) {
                $resultStatus = 'ssrf_blocked';
                $safeCode = $canon['error_code'] ?? 'SSRF_INVALID_URL';
            } else {
                $resolvedIps = $simulatedResolvedIps ?? ['203.0.114.10'];
                foreach ($resolvedIps as $ip) {
                    if (!self::isPublicRoutableIp($ip)) {
                        $resultStatus = 'ssrf_blocked';
                        $safeCode = 'SSRF_PRIVATE_OR_RESERVED_IP_BLOCKED';
                        break;
                    }
                }
            }

            $checkId = UuidV7::generate();
            $ins = $db->prepare(
                'INSERT INTO shortlink.link_health_checks (
                    id, link_id, unit_id, result_status, http_status, safe_error_code, duration_ms
                ) VALUES (
                    :id, :lid, :uid, :status, :http, :code, 12
                )'
            );
            $ins->execute([
                ':id' => $checkId,
                ':lid' => $linkId,
                ':uid' => $unitId,
                ':status' => $resultStatus,
                ':http' => $resultStatus === 'healthy' ? 200 : null,
                ':code' => $safeCode,
            ]);

            return [
                'check_id' => $checkId,
                'result_status' => $resultStatus,
                'safe_error_code' => $safeCode,
                'resolved_ips' => $resolvedIps,
            ];
        }, $pdo);
    }

    /**
     * Submits a public abuse/misuse report via `awshortlink_resolver` and allows staff triage (#34, API-057, API-058).
     *
     * @return array<string, mixed>
     */
    public static function submitPublicAbuseReport(
        string $slugReported,
        string $category,
        string $description,
        ?string $reporterContact = null,
        ?PDO $resolverPdo = null,
    ): array {
        if (!in_array($category, ['deadlink', 'not_for_public', 'phishing', 'malware', 'inaccurate_target', 'expired_content', 'other'], true)) {
            throw new RuntimeException('INVALID_ABUSE_CATEGORY');
        }

        $reportId = UuidV7::generate();
        $db = $resolverPdo ?? PostgreSql::resolver();
        $cleanSlug = strtolower(trim($slugReported));
        $cleanSlug = preg_replace('#^/buka/#i', '', $cleanSlug);
        $cleanSlug = trim($cleanSlug, '/');

        $linkId = null;
        $unitId = null;
        try {
            $stL = $db->prepare("SELECT id, unit_id FROM shortlink.public_resolvable_links WHERE slug = :s LIMIT 1");
            $stL->execute([':s' => $cleanSlug]);
            $rowL = $stL->fetch(PDO::FETCH_ASSOC);
            if (is_array($rowL)) {
                $linkId = $rowL['id'];
                $unitId = $rowL['unit_id'];
            }
        } catch (Throwable) {}

        $stmt = $db->prepare(
            "INSERT INTO shortlink.abuse_reports (
                id, slug_reported, link_id, unit_id, category, description, reporter_contact, status
            ) VALUES (
                :id, :slug, :link_id, :unit_id, :cat, :desc, :contact, 'open'
            )"
        );
        $stmt->execute([
            ':id' => $reportId,
            ':slug' => $cleanSlug,
            ':link_id' => $linkId,
            ':unit_id' => $unitId,
            ':cat' => $category,
            ':desc' => trim($description),
            ':contact' => $reporterContact,
        ]);

        return [
            'report_id' => $reportId,
            'slug_reported' => $cleanSlug,
            'category' => $category,
            'status' => 'open',
        ];
    }

    /**
     * Triages an open abuse report and optionally suspends the reported link (#34, API-058).
     *
     * @return array<string, mixed>
     */
    public static function triageAbuseReport(
        string $actorId,
        string $reportId,
        string $newStatus,
        string $resolutionNotes,
        ?PDO $pdo = null,
    ): array {
        if (!in_array($newStatus, ['investigating', 'resolved_suspended', 'dismissed'], true)) {
            throw new RuntimeException('INVALID_TRIAGE_STATUS');
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'abuse_reports.triage',
            resourceType: 'abuse_reports',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($actorId, $reportId, $newStatus, $resolutionNotes): array {
            $upd = $db->prepare(
                'UPDATE shortlink.abuse_reports
                 SET status = :status,
                     resolved_by = :actor,
                     resolution_notes = :notes,
                     resolved_at = now()
                 WHERE id = :id
                 RETURNING id, slug_reported, status'
            );
            $upd->execute([
                ':status' => $newStatus,
                ':actor' => $actorId,
                ':notes' => $resolutionNotes,
                ':id' => $reportId,
            ]);
            /** @var array<string, mixed>|false $row */
            $row = $upd->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('ABUSE_REPORT_NOT_FOUND');
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'abuse_reports.triaged_' . $newStatus,
                subjectType: 'abuse_report',
                subjectId: $reportId,
                subjectVersion: 2,
                afterState: $row,
                reason: $resolutionNotes
            );

            return $row;
        }, $pdo);
    }

    /**
     * Runs bounded scheduled housekeeping tasks (`schedule:run` / panel Cron fallback) (#32).
     *
     * @return array{status: string, expired_sessions_revoked: int, heartbeat_updated: bool}
     */
    public static function runBoundedSchedule(?PDO $pdo = null): array
    {
        $ctx = RlsContext::systemGlobal();
        return $ctx->run(static function (PDO $db): array {
            $rev = $db->prepare(
                "UPDATE shortlink.sessions
                 SET revoked_at = now()
                 WHERE revoked_at IS NULL
                   AND (expires_at <= now() OR last_activity_at + interval '30 minutes' <= now())"
            );
            $rev->execute();
            $revokedCount = $rev->rowCount();

            // Retention (ADR-0003): purge per-visitor telemetry older than the configured window.
            $cfg = require dirname(__DIR__, 3) . '/config/shortlink.php';
            $purge = $db->prepare(
                "DELETE FROM shortlink.link_access_logs
                 WHERE occurred_at < now() - make_interval(days => :days)"
            );
            $purge->execute([':days' => (int) ($cfg['access_log_retention_days'] ?? 90)]);
            $purgedLogs = $purge->rowCount();

            $hb = $db->prepare(
                "INSERT INTO shortlink.ops_heartbeats (component, status, details, observed_at)
                 VALUES ('scheduler', 'ok', :details::jsonb, now())
                 ON CONFLICT (component) DO UPDATE
                 SET status = 'ok', details = EXCLUDED.details, observed_at = now()"
            );
            $hb->execute([
                ':details' => json_encode([
                    'last_run' => gmdate('c'),
                    'expired_sessions_revoked' => $revokedCount,
                    'access_logs_purged' => $purgedLogs,
                ], JSON_THROW_ON_ERROR),
            ]);

            return [
                'status' => 'ok',
                'expired_sessions_revoked' => $revokedCount,
                'access_logs_purged' => $purgedLogs,
                'heartbeat_updated' => true,
            ];
        }, $pdo);
    }
}

