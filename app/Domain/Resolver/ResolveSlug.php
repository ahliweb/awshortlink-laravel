<?php

declare(strict_types=1);

namespace App\Domain\Resolver;

use App\Domain\Analytics\AccessLogRecorder;
use App\Domain\Analytics\BotClassifier;
use App\Domain\Analytics\RecordClick;
use App\Domain\DestinationPolicy\UrlCanonicalizer;
use App\Support\PostgreSql;
use PDO;
use Throwable;

/**
 * ALG-003: Fast Public Redirect Resolver (SPEC-07, DES-003, DES-008, DES-011, #14, #20).
 *
 * Uses restricted role `awshortlink_resolver` reading `shortlink.public_resolvable_links` only.
 * Never performs synchronous DNS/HTTP fetches, never forwards query parameters, never sets cookies,
 * and always emits `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
 */
final class ResolveSlug
{
    /**
     * @param array<string, string> $headers
     * @return array{
     *   http_status: int,
     *   headers: array<string, string>,
     *   location: ?string,
     *   link_id: ?string,
     *   view_state: 'redirect'|'missing_404'|'retired_410'|'method_405'|'error_503',
     *   error_code: ?string,
     *   click_recorded: bool
     * }
     */
    public static function resolve(
        string $method,
        string $rawSlug,
        array $headers = [],
        ?PDO $resolverPdo = null,
        string $namespace = 'buka'
    ): array {
        $baseHeaders = [
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-Robots-Tag' => 'noindex, nofollow',
        ];

        $upperMethod = strtoupper(trim($method));
        if (!in_array($upperMethod, ['GET', 'HEAD'], true)) {
            $baseHeaders['Allow'] = 'GET, HEAD';
            return [
                'http_status' => 405,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => null,
                'view_state' => 'method_405',
                'error_code' => 'METHOD_NOT_ALLOWED',
                'click_recorded' => false,
            ];
        }

        // Step 2: Canonicalize slug via ALG-001 before touching DB
        $canon = SlugCanonicalizer::canonicalize($rawSlug);
        if (!$canon['valid'] || $canon['slug_normalized'] === null) {
            return [
                'http_status' => 404,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => null,
                'view_state' => 'missing_404',
                'error_code' => $canon['error_code'],
                'click_recorded' => false,
            ];
        }

        $slug = $canon['slug_normalized'];

        // Step 3: Single bounded lookup on shortlink.public_resolvable_links via awshortlink_resolver
        try {
            $db = $resolverPdo ?? PostgreSql::resolver();
            $db->exec("SET statement_timeout = '1000ms'");
            $stmt = $db->prepare(
                'SELECT id, namespace, slug, title, status, target_url
                 FROM shortlink.public_resolvable_links
                 WHERE namespace = :ns AND slug = :slug
                 LIMIT 1'
            );
            $stmt->execute([':ns' => $namespace, ':slug' => $slug]);
            /** @var array{id: string, namespace: string, slug: string, title?: ?string, status: string, target_url: ?string}|false $row */
            $row = $stmt->fetch();
        } catch (Throwable) {
            $baseHeaders['Retry-After'] = '30';
            return [
                'http_status' => 503,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => null,
                'view_state' => 'error_503',
                'error_code' => 'RESOLVER_DB_UNAVAILABLE',
                'click_recorded' => false,
            ];
        }

        if (!is_array($row)) {
            return [
                'http_status' => 404,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => null,
                'view_state' => 'missing_404',
                'error_code' => 'SLUG_NOT_FOUND',
                'click_recorded' => false,
            ];
        }

        $viewStatus = (string) $row['status'];
        $linkId = (string) $row['id'];

        // DES-003: retired (archived or expired with retired_public_message=true) -> 410 Gone
        if ($viewStatus === 'retired') {
            return [
                'http_status' => 410,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => $linkId,
                'view_state' => 'retired_410',
                'error_code' => 'LINK_RETIRED_OR_EXPIRED',
                'click_recorded' => false,
            ];
        }

        // DES-003: unavailable (suspended, scheduled in future, or archived without public tombstone) -> 404 Not Found
        if ($viewStatus !== 'active' || empty($row['target_url'])) {
            return [
                'http_status' => 404,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => $linkId,
                'view_state' => 'missing_404',
                'error_code' => 'LINK_UNAVAILABLE',
                'click_recorded' => false,
            ];
        }

        $targetUrl = (string) $row['target_url'];

        // Step 5: Defensive stored URL invariant check (must be https://, no credentials, no IP literal)
        $defensiveCheck = UrlCanonicalizer::canonicalize($targetUrl);
        if (!$defensiveCheck['valid'] || $defensiveCheck['url_canonical'] === null) {
            $baseHeaders['Retry-After'] = '30';
            return [
                'http_status' => 503,
                'headers' => $baseHeaders,
                'location' => null,
                'link_id' => $linkId,
                'view_state' => 'error_503',
                'error_code' => 'STORED_DESTINATION_INVARIANT_FAILED',
                'click_recorded' => false,
            ];
        }

        $baseHeaders['Location'] = $targetUrl;

        // Step 7: Record aggregate click & detailed access telemetry for GET only
        $clickRecorded = false;
        if ($upperMethod === 'GET') {
            $botClass = BotClassifier::classify($headers);
            if ($botClass !== 3) {
                $clickRecorded = RecordClick::record($linkId, $botClass, '', $resolverPdo);
                AccessLogRecorder::record($linkId, $headers, $botClass, $resolverPdo);
            }
        }

        return [
            'http_status' => 302,
            'headers' => $baseHeaders,
            'location' => $targetUrl,
            'link_id' => $linkId,
            'slug' => (string) $row['slug'],
            'title' => (string) ($row['title'] ?? ''),
            'view_state' => 'redirect',
            'error_code' => null,
            'click_recorded' => $clickRecorded,
        ];
    }
}
