<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\Analytics\AnalyticsService;
use App\Domain\Analytics\RecordClick;
use App\Domain\Links\BulkCsvProcessor;
use App\Domain\Links\LinkLifecycleService;
use App\Domain\Ops\OpsAndSecurityService;
use App\Domain\Qr\RenderQr;
use App\Support\PostgreSql;
use Tests\TestAssert;

echo "==> [05] Running QR SVG/PNG, Analytics k=10 Suppression, Campaigns, Bulk CSV, Scoped API Keys, SSRF & Anti-Abuse Tests (TST-005..006, TST-011..014, #16, #17, #28..#34)...\n";

Migrator::resetAllData();

// 1. Dynamic QR SVG & PNG Generation (#16, TST-005)
$draftLink = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'qr-sample',
    title: 'Integrated guide',
    destinationUrl: 'https://www.example.org/programs/sample-2026'
);
$linkId = (string) $draftLink['id'];

$draftQrSvg = RenderQr::generate(Migrator::USER_PLATFORM_OWNER, $linkId, 'svg');
TestAssert::true($draftQrSvg['is_draft_watermarked'], 'Draft link QR SVG must have draft watermark');
TestAssert::contains('DRAFT PREVIEW', $draftQrSvg['content'], 'Draft SVG contains DRAFT PREVIEW watermark');
TestAssert::same('https://links.example.org/buka/qr-sample', $draftQrSvg['encoded_url'], 'QR encodes canonical shortlink URL, not mutable destination');
TestAssert::same(false, str_contains($draftQrSvg['content'], 'programs/sample-2026'), 'QR SVG must never embed mutable destination URL');

// Approve link -> QR SVG & PNG generated without draft watermark and deterministic checksum
LinkLifecycleService::approveAndPublish(Migrator::USER_SECURITY_APPROVER, $linkId);
$pubQrSvg1 = RenderQr::generate(Migrator::USER_PLATFORM_OWNER, $linkId, 'svg');
$pubQrSvg2 = RenderQr::generate(Migrator::USER_PLATFORM_OWNER, $linkId, 'svg');
TestAssert::same(false, $pubQrSvg1['is_draft_watermarked'], 'Published link QR has no draft watermark');
TestAssert::same($pubQrSvg1['checksum'], $pubQrSvg2['checksum'], 'Deterministic QR SVG checksum');
TestAssert::contains('brand-logo-center', $pubQrSvg1['content'], 'QR SVG embeds centered @@ORG_SHORT@@ logo');

$pubQrPng = RenderQr::generate(Migrator::USER_PLATFORM_OWNER, $linkId, 'png');
TestAssert::same('image/png', $pubQrPng['mime_type'], 'PNG mime_type');
TestAssert::same("\x89PNG\r\n\x1a\n", substr($pubQrPng['content'], 0, 8), 'PNG output starts with valid 8-byte PNG signature');

// Verify QR code scanner readability with centered logo
$scannedUrl = (string) (new \chillerlan\QRCode\QRCode)->readFromBlob($pubQrPng['content']);
TestAssert::same('https://links.example.org/buka/qr-sample', $scannedUrl, 'QR PNG with centered logo is 100% readable by QR scanners');

// 2. Analytics k=10 Small-Cohort Suppression & Campaigns (#17, #28, #33, TST-006)
$camp = AnalyticsService::createCampaign(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    code: 'CAMPAIGN_2026',
    name: 'Lifecycle campaign 2026'
);
TestAssert::same('CAMPAIGN_2026', $camp['code'], 'Campaign created');

// 0 clicks -> not suppressed (valid_clicks = 0)
$statsZero = AnalyticsService::queryDailyStats(Migrator::USER_PLATFORM_OWNER, $linkId);
TestAssert::same(false, $statsZero['totals']['suppressed'], '0 clicks is not suppressed');
TestAssert::same(0, $statsZero['totals']['valid_clicks'], '0 clicks returned as 0');

// 5 clicks (1..9 < k=10) -> suppressed!
for ($i = 0; $i < 5; $i++) {
    RecordClick::record($linkId, 0, 'poster');
}
$statsFive = AnalyticsService::queryDailyStats(Migrator::USER_PLATFORM_OWNER, $linkId);
TestAssert::true($statsFive['totals']['suppressed'], 'Cohort of 5 clicks (<10) must be suppressed');
TestAssert::same(null, $statsFive['totals']['valid_clicks'], 'Suppressed valid_clicks must be null');
TestAssert::same('<10', $statsFive['totals']['valid_clicks_display'], 'Suppressed display must be <10');

// Add 5 more clicks -> total 10 (>= k=10) -> unsuppressed exact count!
for ($i = 0; $i < 5; $i++) {
    RecordClick::record($linkId, 0, 'poster');
}
$statsTen = AnalyticsService::queryDailyStats(Migrator::USER_PLATFORM_OWNER, $linkId);
TestAssert::same(false, $statsTen['totals']['suppressed'], 'Cohort of 10 clicks (>=10) is not suppressed');
TestAssert::same(10, $statsTen['totals']['valid_clicks'], 'Cohort of 10 clicks returns exact integer 10');

// 13-month retention pruning (#33)
$pruned = AnalyticsService::pruneExpiredDailyStats(PostgreSql::migrator(), 13);
TestAssert::same(0, $pruned, 'Current day stats are retained (<13 months)');

// 3. Bulk CSV Import Dry-Run, Formula Injection Defense & Atomic Rollback (#29, TST-012)
$badCsvBatch = [
    [
        'slug' => 'csv-valid-1',
        'title' => 'Tautan CSV Valid Satu',
        'destination_url' => 'https://www.example.org/csv-1',
    ],
    [
        'slug' => 'csv-bad-formula',
        'title' => '=CMD|\' /C calc\'!A0',
        'destination_url' => 'http://127.0.0.1/ssrf',
    ],
];
$badImportRes = BulkCsvProcessor::importRows(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rows: $badCsvBatch,
    dryRun: false
);
TestAssert::same(false, $badImportRes['valid'], 'Batch with formula injection and invalid URL must fail');
TestAssert::same(0, $badImportRes['created_count'], 'Atomic batch rule: 0 rows created when any row fails');
TestAssert::contains('CSV_FORMULA_INJECTION_DETECTED', implode(',', $badImportRes['row_results'][1]['errors']), 'Detects CSV formula injection');

// Valid dry-run batch -> validates true, creates 0 rows
$goodCsvBatch = [
    [
        'slug' => 'csv-program-1',
        'title' => 'Pos Imunisasi Satu',
        'destination_url' => 'https://www.example.org/program-1',
    ],
    [
        'slug' => 'csv-program-2',
        'title' => 'Pos Imunisasi Dua',
        'destination_url' => 'https://www.example.org/program-2',
    ],
];
$dryRes = BulkCsvProcessor::importRows(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rows: $goodCsvBatch,
    dryRun: true
);
TestAssert::true($dryRes['valid'], 'Dry-run batch is valid');
TestAssert::same(0, $dryRes['created_count'], 'Dry-run persists 0 rows');

// Commit valid batch -> creates 2 draft links
$commitRes = BulkCsvProcessor::importRows(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rows: $goodCsvBatch,
    dryRun: false
);
TestAssert::true($commitRes['valid'], 'Committed batch is valid');
TestAssert::same(2, $commitRes['created_count'], 'Committed batch creates 2 links');

// Formula sanitization on export
TestAssert::same("'=SUM(A1:A2)", BulkCsvProcessor::sanitizeCellForExport('=SUM(A1:A2)'), 'Export cell starting with = is prefixed with single quote');
$exportedCsv = BulkCsvProcessor::exportScopedCsv(Migrator::USER_PLATFORM_OWNER, Migrator::UNIT_ROOT);
TestAssert::contains('csv-program-1', $exportedCsv, 'Exported CSV contains imported slug');

// 4. Scoped API Credentials, Rate Limit & Revocation (#30, TST-011)
$cred = OpsAndSecurityService::createApiCredential(
    actorId: Migrator::USER_PLATFORM_OWNER,
    name: 'Portal Integration',
    scopes: ['links.list_internal', 'analytics.view'],
    unitId: Migrator::UNIT_ROOT,
    rateLimitPerMinute: 3
);
$plainToken = $cred['plaintext_token'];

// Valid scope within rate limit (requests 1, 2, 3)
for ($i = 1; $i <= 3; $i++) {
    $authOk = OpsAndSecurityService::authenticateApiToken($plainToken, 'links.list_internal', 1700000000 + $i);
    TestAssert::true($authOk['authenticated'], 'API token request #' . $i . ' succeeds');
}

// 4th request within same 60-second window hits rate limit (429 API_RATE_LIMIT_EXCEEDED)
$rateLimited = OpsAndSecurityService::authenticateApiToken($plainToken, 'links.list_internal', 1700000005);
TestAssert::same(false, $rateLimited['authenticated'], '4th request in 1 minute must be rate limited');
TestAssert::same(429, $rateLimited['http_status'], 'Rate limit returns 429');

// Out-of-scope permission request -> 403 API_TOKEN_SCOPE_INSUFFICIENT
$outOfScope = OpsAndSecurityService::authenticateApiToken($plainToken, 'users.disable', 1700000100);
TestAssert::same(403, $outOfScope['http_status'], 'Out-of-scope permission returns 403');
TestAssert::same('API_TOKEN_SCOPE_INSUFFICIENT', $outOfScope['error_code'], 'API_TOKEN_SCOPE_INSUFFICIENT');

// Revoke token -> subsequent call returns 401 API_TOKEN_REVOKED_OR_EXPIRED
OpsAndSecurityService::revokeApiCredential(Migrator::USER_PLATFORM_OWNER, $cred['credential_id'], 'Rotate key');
$afterRevoke = OpsAndSecurityService::authenticateApiToken($plainToken, 'links.list_internal', 1700000200);
TestAssert::same(401, $afterRevoke['http_status'], 'Revoked token returns 401');

// 5. OWASP SSRF-Hardened Link Health Checker (#31, TST-013)
foreach ([
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.10',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '::1',
    'fe80::1',
] as $privateIp) {
    TestAssert::same(false, OpsAndSecurityService::isPublicRoutableIp($privateIp), 'Private/reserved IP ' . $privateIp . ' must be blocked');
}
TestAssert::true(OpsAndSecurityService::isPublicRoutableIp('203.0.114.10'), 'Public IPv4 is allowed');

$ssrfBlockedCheck = OpsAndSecurityService::runSafeLinkHealthCheck(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: $linkId,
    targetUrl: 'https://www.example.org/programs/sample-2026',
    simulatedResolvedIps: ['169.254.169.254']
);
TestAssert::same('ssrf_blocked', $ssrfBlockedCheck['result_status'], 'DNS rebinding to 169.254.169.254 must be blocked');

$healthyCheck = OpsAndSecurityService::runSafeLinkHealthCheck(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: $linkId,
    targetUrl: 'https://www.example.org/programs/sample-2026',
    simulatedResolvedIps: ['103.140.188.10']
);
TestAssert::same('healthy', $healthyCheck['result_status'], 'Public routable IP health check succeeds');

// 6. Anti-Abuse Reporting & Triage + Bounded Scheduler (#32, #34)
$abuse = OpsAndSecurityService::submitPublicAbuseReport(
    slugReported: 'qr-sample',
    category: 'inaccurate_target',
    description: 'Mohon periksa jadwal di halaman tujuan apakah sudah tahun 2026.'
);
TestAssert::same('open', $abuse['status'], 'Public abuse report created in open status');

$triaged = OpsAndSecurityService::triageAbuseReport(
    actorId: Migrator::USER_SECURITY_APPROVER,
    reportId: (string) $abuse['report_id'],
    newStatus: 'dismissed',
    resolutionNotes: 'Telah diverifikasi jadwal tujuan sudah benar.'
);
TestAssert::same('dismissed', $triaged['status'], 'Abuse report triaged');

$sched = OpsAndSecurityService::runBoundedSchedule();
TestAssert::same('ok', $sched['status'], 'Bounded scheduler updates heartbeat');

echo "    [PASS] 05_qr_analytics_csv_ssrf_smoke.php (" . TestAssert::$assertions . " assertions)\n";

