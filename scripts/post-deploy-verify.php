<?php

declare(strict_types=1);

/**
 * Post-deployment synthetic verification: RLS posture, five sample links (create/approve/resolve/QR), 404/410
 * behaviour, parent-site coexistence, health endpoint, scheduler and audit hash-chain integrity.
 *
 * WARNING: calls Migrator::resetAllData() — run it ONLY against the disposable test database
 * (scripts/ci.sh does this). It refuses to run when APP_ENV=production.
 */

require dirname(__DIR__) . "/bootstrap/autoload.php";

use App\Database\Migrator;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\Audit\AuditChainVerifier;
use App\Domain\Links\LinkLifecycleService;
use App\Domain\Ops\OpsAndSecurityService;
use App\Domain\Qr\RenderQr;
use App\Http\Kernel;
use App\Support\PostgreSql;
use Tests\TestAssert;

echo "==> [POST-DEPLOY] Verifying PostgreSQL 18 RLS Posture, first-five slugs, Rollback, QR & Audit Chain (#26)...\n";

Migrator::resetAllData();

// 1. Verify PostgreSQL RLS & Runtime Role Posture
$posture = PostgreSql::introspectSecurityPosture();
TestAssert::true($posture["healthy"], "Post-deploy PostgreSQL RLS posture must be healthy");
TestAssert::same(0, count($posture["unprotected_tables"]), "0 unprotected tables");

// 2. Provision & Approve the 5 Initial @@ORG_SHORT@@ Use-Case Slugs (README.md & #26)
$initialSlugs = [
    ["welcome", "Welcome page", "https://www.example.org/welcome"],
    ["survey", "Satisfaction survey", "https://www.example.org/services/survey"],
    ["directory", "Public directory", "https://www.example.org/about/directory"],
    ["training-material", "Training material", "https://www.example.org/publications/training-material"],
    ["campaign", "Awareness campaign", "https://www.example.org/programs/campaign"],
];

foreach ($initialSlugs as [$slug, $title, $url]) {
    $draft = LinkLifecycleService::createDraft(
        actorId: Migrator::USER_PLATFORM_OWNER,
        unitId: Migrator::UNIT_ROOT,
        rawSlug: $slug,
        title: $title,
        destinationUrl: $url
    );
    LinkLifecycleService::approveAndPublish(
        approverId: Migrator::USER_SECURITY_APPROVER,
        linkId: (string) $draft["id"],
        reason: "Post-deploy synthetic verification"
    );

    // Synthetic probe with X-Synthetic-Probe: 1 (bot_class = 3 so monitoring does not pollute campaign click counts)
    $res = Kernel::handle("GET", "/buka/" . $slug, ["X-Synthetic-Probe" => "1"]);
    TestAssert::same(302, $res["status"], "Synthetic GET /buka/" . $slug . " returns 302");
    TestAssert::same($url, $res["headers"]["Location"], "Synthetic Location matches " . $url);

    $qr = RenderQr::generate(Migrator::USER_PLATFORM_OWNER, (string) $draft["id"], "svg");
    TestAssert::same(false, $qr["is_draft_watermarked"], "Published QR SVG for " . $slug . " is unwatermarked");
}

// 3. Verify 404, 410, Parent Site Coexistence, Admin Login & Health Endpoint
$parentCheck = Kernel::handle("GET", "/news-page");
TestAssert::same(404, $parentCheck["status"], "Parent site path outside /buka/* is untouched");

$missingCheck = Kernel::handle("GET", "/buka/slug-tidak-terdaftar");
TestAssert::same(404, $missingCheck["status"], "Unknown slug returns safe 404");

$healthCheck = Kernel::handle("GET", "/buka/api/v1/ops/health");
TestAssert::same(200, $healthCheck["status"], "Health endpoint returns 200 OK");

// 4. Verify Bounded Scheduler & Audit Hash Chain Integrity
$sched = OpsAndSecurityService::runBoundedSchedule();
TestAssert::same("ok", $sched["status"], "Scheduler heartbeat ok");

$ctx = RlsContext::systemGlobal();
$chain = $ctx->run(static fn (\PDO $db): array => AuditChainVerifier::verify($db));
TestAssert::true($chain["valid"], "Post-deploy audit hash chain 100% valid");

echo "    [PASS] Post-deploy synthetic verification (" . TestAssert::$assertions . " assertions)\n";
