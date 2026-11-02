<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\Analytics\AnalyticsService;
use App\Domain\DestinationPolicy\DestinationRiskClassifier;
use App\Domain\Links\LinkLifecycleService;
use App\Domain\Resolver\ResolveSlug;
use App\Domain\Resolver\SlugCanonicalizer;
use App\Support\PostgreSql;
use Tests\TestAssert;

echo "==> [02] Running Deterministic Test Vectors TV-001..024 (ALG-001..005, TST-001..003, TST-009, #13, #14)...\n";

Migrator::resetAllData();
$appDb = PostgreSql::app();
$resolverDb = PostgreSql::resolver();

// Create & approve baseline active link /buka/event-62 and /buka/event62
$draftEventDash = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'event-62',
    title: 'Hari Kesehatan Nasional Ke-62',
    destinationUrl: 'https://www.example.org/info/event-62'
);
LinkLifecycleService::approveAndPublish(
    approverId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftEventDash['id'],
    reason: 'Approve TV-001 link'
);

$draftEvent62 = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'event62',
    title: 'Event 62 Portal',
    destinationUrl: 'https://www.example.org/event62'
);
LinkLifecycleService::approveAndPublish(
    approverId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftEvent62['id'],
    reason: 'Approve TV-015..024 link'
);

// TV-001: Uppercase ASCII slug normalized to lowercase -> 302 Found
$tv001 = ResolveSlug::resolve('GET', 'EVENT-62', ['User-Agent' => 'Mozilla/5.0 Chrome/130.0'], $resolverDb);
TestAssert::same(302, $tv001['http_status'], 'TV-001: GET /buka/EVENT-62 must return 302');
TestAssert::same('https://www.example.org/info/event-62', $tv001['location'], 'TV-001: Location must match canonical URL');
TestAssert::contains('no-store', $tv001['headers']['Cache-Control'], 'TV-001: Cache-Control must include no-store');
TestAssert::same('no-referrer', $tv001['headers']['Referrer-Policy'], 'TV-001: Referrer-Policy must be no-referrer');

// TV-002: Length < 3 rejected before DB query -> 404
$tv002 = ResolveSlug::resolve('GET', 'ab', [], $resolverDb);
TestAssert::same(404, $tv002['http_status'], 'TV-002: slug length 2 must return 404');
TestAssert::same('SLUG_LENGTH_OUT_OF_RANGE', $tv002['error_code'], 'TV-002: error code');

// TV-003: Leading, trailing, or double hyphen rejected -> 404
foreach (['-event62', 'event62-', 'event--62'] as $badSlug) {
    $res = ResolveSlug::resolve('GET', $badSlug, [], $resolverDb);
    TestAssert::same(404, $res['http_status'], 'TV-003: ' . $badSlug . ' must return 404');
}

// TV-004: Reserved system words rejected -> 404
foreach (['admin', 'api', 'livewire', '.env', 'artisan', 'laporan'] as $reserved) {
    $c = SlugCanonicalizer::canonicalize($reserved);
    TestAssert::same(false, $c['valid'], 'TV-004: reserved word ' . $reserved . ' must be invalid');
    TestAssert::same('SLUG_RESERVED_SYSTEM', $c['error_code'], 'TV-004: SLUG_RESERVED_SYSTEM');
}

// TV-005: Cyrillic/Unicode homograph rejected -> 404
$tv005 = ResolveSlug::resolve('GET', "kesehatan-\xD1\x96\xD1\x97", [], $resolverDb);
TestAssert::same(404, $tv005['http_status'], 'TV-005: non-ASCII slug must return 404');
TestAssert::same('SLUG_NON_ASCII', $tv005['error_code'], 'TV-005: SLUG_NON_ASCII');

// Run ALG-002 destination policy vectors inside global RLS context
$ctx = RlsContext::systemGlobal();
$ctx->run(static function (\PDO $db): void {
    // TV-006: Path dot-segment normalization, fragment stripping, institutional allowlist -> low risk
    $tv006 = DestinationRiskClassifier::evaluate('https://www.example.org/info/../jadwal?utm_source=ig#top', $db);
    TestAssert::true($tv006['allowed'], 'TV-006: institutional HTTPS URL must be allowed');
    TestAssert::same('https://www.example.org/jadwal?utm_source=ig', $tv006['url_canonical'], 'TV-006: dot-segments resolved and #fragment stripped');
    TestAssert::same('low', $tv006['risk_class'], 'TV-006: risk_class must be low');

    // TV-007: Cleartext http:// blocked (SCHEME_NOT_HTTPS)
    $tv007 = DestinationRiskClassifier::evaluate('http://www.example.org/info', $db);
    TestAssert::same(false, $tv007['allowed'], 'TV-007: http:// must be blocked');
    TestAssert::same('SCHEME_NOT_HTTPS', $tv007['error_code'], 'TV-007: SCHEME_NOT_HTTPS');

    // TV-008: Unsafe schemes & protocol-relative blocked
    foreach (['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', '//evil.example/phish'] as $unsafeUrl) {
        $v = DestinationRiskClassifier::evaluate($unsafeUrl, $db);
        TestAssert::same(false, $v['allowed'], 'TV-008: ' . $unsafeUrl . ' must be blocked');
        TestAssert::same('UNSAFE_SCHEME_OR_RELATIVE', $v['error_code'], 'TV-008: UNSAFE_SCHEME_OR_RELATIVE');
    }

    // TV-009: Embedded credentials blocked
    $tv009 = DestinationRiskClassifier::evaluate('https://admin:secret@example.org/', $db);
    TestAssert::same(false, $tv009['allowed'], 'TV-009: embedded userinfo must be blocked');
    TestAssert::same('EMBEDDED_CREDENTIALS', $tv009['error_code'], 'TV-009: EMBEDDED_CREDENTIALS');

    // TV-010: Direct IPv4 / metadata / IPv6 literal blocked
    foreach (['https://127.0.0.1/admin', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/'] as $ipUrl) {
        $v = DestinationRiskClassifier::evaluate($ipUrl, $db);
        TestAssert::same(false, $v['allowed'], 'TV-010: ' . $ipUrl . ' must be blocked');
        TestAssert::same('IP_LITERAL_FORBIDDEN', $v['error_code'], 'TV-010: IP_LITERAL_FORBIDDEN');
    }

    // TV-011: Non-standard port blocked
    $tv011 = DestinationRiskClassifier::evaluate('https://www.example.org:8443/panel', $db);
    TestAssert::same(false, $tv011['allowed'], 'TV-011: port 8443 must be blocked');
    TestAssert::same('NON_STANDARD_PORT', $tv011['error_code'], 'TV-011: NON_STANDARD_PORT');

    // TV-012: Prohibited patient/NIK/RME or credential query parameters blocked
    foreach ([
        'https://simrs.example.go.id/pasien?nik=6201011234560001',
        'https://simrs.example.go.id/pasien?no_rm=12345',
        'https://simrs.example.go.id/auth?access_token=eyJhbGci',
    ] as $piiUrl) {
        $v = DestinationRiskClassifier::evaluate($piiUrl, $db);
        TestAssert::same(false, $v['allowed'], 'TV-012: ' . $piiUrl . ' must be blocked');
        TestAssert::same('PROHIBITED_PII_OR_TOKEN_QUERY', $v['error_code'], 'TV-012: PROHIBITED_PII_OR_TOKEN_QUERY');
    }

    // TV-013: Unreserved percent-decoding (%7E -> ~) and *.go.id medium risk classification
    $tv013 = DestinationRiskClassifier::evaluate('https://portal.Example.GO.ID/Path%7E1', $db);
    TestAssert::true($tv013['allowed'], 'TV-013: external .go.id must be allowed with approval');
    TestAssert::same('https://portal.example.go.id/Path~1', $tv013['url_canonical'], 'TV-013: canonical URL');
    TestAssert::same('medium', $tv013['risk_class'], 'TV-013: risk_class must be medium');
    TestAssert::true($tv013['requires_approval'], 'TV-013: medium risk requires approval');

    // TV-014: Known URL shortener blocked
    $tv014 = DestinationRiskClassifier::evaluate('https://bit.ly/3xyz', $db);
    TestAssert::same(false, $tv014['allowed'], 'TV-014: bit.ly must be blocked');
    TestAssert::same('CHAINED_SHORTENER_FORBIDDEN', $tv014['error_code'], 'TV-014: CHAINED_SHORTENER_FORBIDDEN');
});

// TV-015: Incoming query string on /buka/event62?token=... is never forwarded to destination
$tv015 = ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'Mozilla/5.0 Firefox/132.0'], $resolverDb);
TestAssert::same(302, $tv015['http_status'], 'TV-015: 302');
TestAssert::same('https://www.example.org/event62', $tv015['location'], 'TV-015: Location never appends incoming query string');

// TV-016: HEAD /buka/event62 returns 302 + Location but does NOT increment click counter
$tv016 = ResolveSlug::resolve('HEAD', 'event62', ['User-Agent' => 'Mozilla/5.0 Firefox/132.0'], $resolverDb);
TestAssert::same(302, $tv016['http_status'], 'TV-016: HEAD returns 302');
TestAssert::same(false, $tv016['click_recorded'], 'TV-016: HEAD must not record click');

// TV-017: POST /buka/event62 rejected with 405 Method Not Allowed + Allow: GET, HEAD
$tv017 = ResolveSlug::resolve('POST', 'event62', [], $resolverDb);
TestAssert::same(405, $tv017['http_status'], 'TV-017: POST must return 405');
TestAssert::same('GET, HEAD', $tv017['headers']['Allow'], 'TV-017: Allow header must be GET, HEAD');

// TV-018: Suspended link returns generic safe 404 (DES-003) with no Location header
$draftSkm = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'survey-main',
    title: 'Survei Kepuasan Masyarakat',
    destinationUrl: 'https://www.example.org/skm'
);
LinkLifecycleService::approveAndPublish(Migrator::USER_SECURITY_APPROVER, (string) $draftSkm['id']);
LinkLifecycleService::suspendLink(Migrator::USER_PLATFORM_OWNER, (string) $draftSkm['id'], 'Emergency suspend test');

$tv018 = ResolveSlug::resolve('GET', 'survey-main', [], $resolverDb);
TestAssert::same(404, $tv018['http_status'], 'TV-018: suspended link must return 404 Not Found');
TestAssert::same(null, $tv018['location'], 'TV-018: suspended link must not emit Location');

// TV-019: Archived link with retired_public_message=true returns 410 Gone
$draftEvent61 = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'event61',
    title: 'Event 61 Arsip',
    destinationUrl: 'https://www.example.org/event61'
);
LinkLifecycleService::approveAndPublish(Migrator::USER_SECURITY_APPROVER, (string) $draftEvent61['id']);
LinkLifecycleService::archiveLink(Migrator::USER_PLATFORM_OWNER, (string) $draftEvent61['id'], 'End of campaign', true);

$tv019 = ResolveSlug::resolve('GET', 'event61', [], $resolverDb);
TestAssert::same(410, $tv019['http_status'], 'TV-019: archived link with retired_public_message=true must return 410 Gone');

// TV-020: Database unavailability / closed statement fails closed with 503 Service Unavailable + Retry-After: 30
$brokenPdo = new class('sqlite::memory:') extends \PDO {
    public function __construct(string $dsn)
    {
        // Intentionally uninitialized or throwing PDO stub to simulate DB timeout/failure
    }
    public function exec(string $statement): int|false
    {
        throw new \PDOException('Simulated PostgreSQL connection timeout');
    }
};
$tv020 = ResolveSlug::resolve('GET', 'event62', [], $brokenPdo);
TestAssert::same(503, $tv020['http_status'], 'TV-020: DB failure must fail closed with 503');
TestAssert::same('30', $tv020['headers']['Retry-After'], 'TV-020: Retry-After header must be 30');

// TV-021: Archived published slug is permanently reserved and cannot be reused (409 SLUG_PERMANENTLY_RESERVED)
TestAssert::throws(
    static fn () => LinkLifecycleService::createDraft(
        actorId: Migrator::USER_PLATFORM_OWNER,
        unitId: Migrator::UNIT_ROOT,
        rawSlug: 'event61',
        title: 'Attempt Reuse Archived Slug',
        destinationUrl: 'https://www.example.org/reuse'
    ),
    'SLUG_PERMANENTLY_RESERVED',
    'TV-021: Reusing archived slug event61 must throw SLUG_PERMANENTLY_RESERVED'
);

// TV-022: Proposing v2 destination on active link keeps public resolver on v1 until v2 is approved
$propV2 = LinkLifecycleService::proposeDestination(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: (string) $draftEvent62['id'],
    destinationUrl: 'https://www.example.org/event62-v2',
    reason: 'Update target page to v2'
);
$beforeApprove = ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'Mozilla/5.0 Safari/605.1'], $resolverDb);
TestAssert::same('https://www.example.org/event62', $beforeApprove['location'], 'TV-022: Before approval, resolver must still return v1');

LinkLifecycleService::approveAndPublish(
    approverId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftEvent62['id'],
    destinationId: (string) $propV2['id'],
    reason: 'Approve v2 destination'
);
$afterApprove = ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'Mozilla/5.0 Safari/605.1'], $resolverDb);
TestAssert::same('https://www.example.org/event62-v2', $afterApprove['location'], 'TV-022: After approval, resolver atomically returns v2');

// TV-023: Optimistic concurrency If-Match / expectedVersion check (STALE_VERSION)
$ctxGlobal = RlsContext::systemGlobal();
$curVer = (int) $ctxGlobal->run(
    static fn (\PDO $db) => $db->query("SELECT version FROM shortlink.links WHERE slug_normalized = 'event62'")->fetchColumn()
);
$updOk = LinkLifecycleService::updateLinkMetadata(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: (string) $draftEvent62['id'],
    expectedVersion: $curVer,
    changes: ['title' => 'Event 62 Updated Title'],
    reason: 'First concurrent update'
);
TestAssert::same($curVer + 1, (int) $updOk['version'], 'TV-023: First update increments version');
TestAssert::throws(
    static fn () => LinkLifecycleService::updateLinkMetadata(
        actorId: Migrator::USER_PLATFORM_OWNER,
        linkId: (string) $draftEvent62['id'],
        expectedVersion: $curVer,
        changes: ['title' => 'Stale Update'],
        reason: 'Second concurrent update with stale version'
    ),
    'STALE_VERSION',
    'TV-023: Stale version must throw STALE_VERSION'
);

// TV-024: Bot/prefetch User-Agent or Purpose: prefetch increments suspected_bot, not valid_clicks
$statsBefore = AnalyticsService::queryDailyStats(Migrator::USER_PLATFORM_OWNER, (string) $draftEvent62['id']);
$botBefore = (int) ($statsBefore['daily_series'][0]['suspected_bot'] ?? 0);

$tv024Wa = ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'WhatsApp/2.24.1 i'], $resolverDb);
$tv024Pre = ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'Mozilla/5.0 Chrome/130.0', 'Purpose' => 'prefetch'], $resolverDb);
TestAssert::same(302, $tv024Wa['http_status'], 'TV-024: WhatsApp preview still gets 302');
TestAssert::same(302, $tv024Pre['http_status'], 'TV-024: Prefetch still gets 302');

// Send 10 bot clicks so it exceeds k=10 suppression threshold for exact count check
for ($i = 0; $i < 10; $i++) {
    ResolveSlug::resolve('GET', 'event62', ['User-Agent' => 'WhatsApp/2.24.1 i'], $resolverDb);
}
$statsAfter = AnalyticsService::queryDailyStats(Migrator::USER_PLATFORM_OWNER, (string) $draftEvent62['id']);
$botAfter = (int) ($statsAfter['daily_series'][0]['suspected_bot'] ?? 0);
TestAssert::true($botAfter >= $botBefore + 12, 'TV-024: Bot & prefetch requests must increment suspected_bot');

echo "    [PASS] 02_algorithms_and_resolver_smoke.php (" . TestAssert::$assertions . " assertions)\n";

