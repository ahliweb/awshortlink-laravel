<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\Links\LinkLifecycleService;
use App\Filament\PanelRegistry;
use App\Http\Kernel;
use Tests\TestAssert;

echo "==> [06] Running HTTP /buka/* Coexistence, Livewire Prefix, Filament UI-001..018 WCAG 2.2 AA & API Contract Tests (TST-008..009, #20..#24, #36, #43)...\n";

Migrator::resetAllData();

// 1. Coexistence Routing (#22): Routes outside /buka/* are never hijacked
$outside = Kernel::handle('GET', '/profile-page');
TestAssert::same(404, $outside['status'], 'Route outside /buka/* returns 404 OUTSIDE_BUKA_PREFIX');
TestAssert::contains('OUTSIDE_BUKA_PREFIX', $outside['body'], 'RFC 9457 code OUTSIDE_BUKA_PREFIX');

// 2. Livewire Asset & Update Coexistence Prefix (/buka/livewire/*, #22)
$lwAsset = Kernel::handle('GET', '/buka/livewire/livewire.js');
TestAssert::same(200, $lwAsset['status'], '/buka/livewire/livewire.js returns 200');
TestAssert::contains('/buka/livewire', $lwAsset['body'], 'Livewire asset bound to /buka/livewire');

$lwUpdateUnauth = Kernel::handle('POST', '/buka/livewire/update');
TestAssert::same(401, $lwUpdateUnauth['status'], 'Unauthenticated POST /buka/livewire/update returns 401');

$lwUpdateAuth = Kernel::handle('POST', '/buka/livewire/update', ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]);
TestAssert::same(200, $lwUpdateAuth['status'], 'Authenticated POST /buka/livewire/update returns 200');

// 3. Public Landing & Directory (/buka/, UI-008, #20, #36) + WCAG 2.2 AA checks (#11, #23)
$draftPub = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_ROOT,
    rawSlug: 'info-campaign',
    title: 'Gerakan Masyarakat Hidup Sehat (GERMAS)',
    destinationUrl: 'https://www.example.org/campaign',
    visibility: 'public'
);
LinkLifecycleService::approveAndPublish(Migrator::USER_SECURITY_APPROVER, (string) $draftPub['id']);

$landing = Kernel::handle('GET', '/buka/', [], ['q' => 'campaign']);
TestAssert::same(200, $landing['status'], 'GET /buka/ returns 200');
TestAssert::contains('lang="id"', $landing['body'], 'WCAG 3.1.1: HTML has lang="id"');
TestAssert::contains('href="#main-content"', $landing['body'], 'WCAG 2.4.1: Skip link to #main-content present');
TestAssert::contains('role="main"', $landing['body'], 'WCAG 1.3.1: Main landmark present');
TestAssert::contains('<label for="search-slug">', $landing['body'], 'WCAG 3.3.2: Explicit form label present');
TestAssert::contains('/buka/info-campaign', $landing['body'], 'Public directory lists active public link');

// 4. Public Redirect & Safe Error Pages 302 / 404 / 410 (#14, #20, UI-009)
$redir = Kernel::handle('GET', '/buka/info-campaign');
TestAssert::same(302, $redir['status'], 'GET /buka/info-campaign returns 302');
TestAssert::same('https://www.example.org/campaign', $redir['headers']['Location'], 'Location header');

$missing404 = Kernel::handle('GET', '/buka/tautan-tidak-ada');
TestAssert::same(404, $missing404['status'], 'Unknown slug returns 404');
TestAssert::contains('data-screen-id="UI-009"', $missing404['body'], 'Renders UI-009 safe 404 page');

LinkLifecycleService::archiveLink(Migrator::USER_PLATFORM_OWNER, (string) $draftPub['id'], 'Archive GERMAS', true);
$gone410 = Kernel::handle('GET', '/buka/info-campaign');
TestAssert::same(410, $gone410['status'], 'Archived link returns 410 Gone');
TestAssert::contains('410 Gone', $gone410['body'], 'Renders 410 Gone message');

// 5. Public Abuse Reporting (/buka/laporan, UI-018, #34)
$abusePage = Kernel::handle('GET', '/buka/laporan');
TestAssert::same(200, $abusePage['status'], 'GET /buka/laporan returns 200');
$abusePost = Kernel::handle('POST', '/buka/laporan', [], [], [
    'slug_reported' => 'info-campaign',
    'category' => 'expired_content',
    'description' => 'Halaman tujuan kampanye GERMAS sudah selesai.',
]);
TestAssert::same(201, $abusePost['status'], 'POST /buka/laporan returns 201 Created');

// 6. Filament Admin Panel UI-001..018 Fail-Closed Authorization (#11, #19)
$allScreens = PanelRegistry::screens();
TestAssert::same(18, count($allScreens), 'All 18 canonical screens UI-001..018 registered');

$unauthAdmin = Kernel::handle('GET', '/buka/admin');
TestAssert::same(401, $unauthAdmin['status'], 'Unauthenticated GET /buka/admin returns 401');

$authAdmin = Kernel::handle('GET', '/buka/admin', ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]);
TestAssert::same(200, $authAdmin['status'], 'Authorized GET /buka/admin returns 200');
TestAssert::contains('data-screen-id="UI-002"', $authAdmin['body'], 'Renders UI-002 dashboard');

$navItems = PanelRegistry::authorizedNavigation(Migrator::USER_PLATFORM_OWNER);
TestAssert::true(count($navItems) >= 10, 'Platform owner sees all authorized navigation items');

// 7. REST API v1 Endpoints & Optimistic Concurrency ETag / If-Match (TST-008)
$healthApi = Kernel::handle('GET', '/buka/api/v1/ops/health');
TestAssert::same(200, $healthApi['status'], 'GET /buka/api/v1/ops/health returns 200');

$createApi = Kernel::handle(
    method: 'POST',
    path: '/buka/api/v1/links',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER],
    body: [
        'unit_id' => Migrator::UNIT_ROOT,
        'slug' => 'api-created-slug',
        'title' => 'Tautan Dibuat Lewat API',
        'destination_url' => 'https://www.example.org/api-target',
    ]
);
TestAssert::same(201, $createApi['status'], 'POST /buka/api/v1/links returns 201');
TestAssert::same('"v1"', $createApi['headers']['ETag'], 'Response includes ETag "v1"');
/** @var array<string, mixed> $createdData */
$createdData = json_decode($createApi['body'], true, 512, JSON_THROW_ON_ERROR);
$apiLinkId = (string) $createdData['id'];

// PATCH without If-Match returns 428 Precondition Required
$patchNoIfMatch = Kernel::handle(
    method: 'PATCH',
    path: '/buka/api/v1/links/' . $apiLinkId,
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER],
    body: ['title' => 'Judul Baru']
);
TestAssert::same(428, $patchNoIfMatch['status'], 'PATCH without If-Match returns 428');

// PATCH with matching If-Match: "v1" returns 200 + ETag: "v2"
$patchOk = Kernel::handle(
    method: 'PATCH',
    path: '/buka/api/v1/links/' . $apiLinkId,
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER, 'If-Match' => '"v1"'],
    body: ['title' => 'Judul Baru Terverifikasi']
);
TestAssert::same(200, $patchOk['status'], 'PATCH with If-Match: "v1" returns 200');
TestAssert::same('"v2"', $patchOk['headers']['ETag'], 'Updated ETag is "v2"');

// PATCH with stale If-Match: "v1" returns 409 Conflict
$patchStale = Kernel::handle(
    method: 'PATCH',
    path: '/buka/api/v1/links/' . $apiLinkId,
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER, 'If-Match' => '"v1"'],
    body: ['title' => 'Judul Basi']
);
TestAssert::same(409, $patchStale['status'], 'PATCH with stale If-Match returns 409 Conflict');

// Verify QR SVG endpoint & Audit Chain Verification endpoint via HTTP Kernel
$qrApi = Kernel::handle(
    method: 'GET',
    path: '/buka/api/v1/links/' . $apiLinkId . '/qr.svg',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]
);
TestAssert::same(200, $qrApi['status'], 'GET /buka/api/v1/links/{id}/qr.svg returns 200');
TestAssert::same('true', $qrApi['headers']['X-QR-Watermarked'], 'Draft QR via API has X-QR-Watermarked: true');

$verifyApi = Kernel::handle(
    method: 'POST',
    path: '/buka/api/v1/audit/verify-chain',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER]
);
TestAssert::same(200, $verifyApi['status'], 'POST /buka/api/v1/audit/verify-chain returns 200');

// Verify POST /buka/admin/links/edit works and saves changes
$adminEdit = Kernel::handle(
    method: 'POST',
    path: '/buka/admin/links/edit',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER],
    query: [],
    body: [
        'link_id' => $apiLinkId,
        'title' => 'Judul Tautan Telah Diedit Staf',
        'destination_url' => 'https://www.example.org/publik/diedit',
        'status' => 'active'
    ]
);
TestAssert::same(302, $adminEdit['status'], 'POST /buka/admin/links/edit returns 302 redirect');
TestAssert::same('/buka/admin/links?msg=updated', $adminEdit['headers']['Location'], 'Redirects to /buka/admin/links?msg=updated');

// Verify AJAX GET /buka/admin/links/check-slug and duplicate check on creation
$checkApi = Kernel::handle(
    method: 'GET',
    path: '/buka/admin/links/check-slug',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER],
    query: ['slug' => 'api-created-slug']
);
TestAssert::same(200, $checkApi['status'], 'GET /buka/admin/links/check-slug returns 200');
TestAssert::contains('"available":false', $checkApi['body'], 'Existing slug reports available: false');

$createDup = Kernel::handle(
    method: 'POST',
    path: '/buka/admin/links/create',
    headers: ['X-Actor-Id' => Migrator::USER_PLATFORM_OWNER],
    query: [],
    body: [
        'title' => 'Cegah Duplikat',
        'slug_mode' => 'manual',
        'manual_slug' => 'api-created-slug',
        'destination_url' => 'https://www.example.org/division-a/test',
        'publish_now' => '1'
    ]
);
TestAssert::same(302, $createDup['status'], 'Duplicate slug creation returns 302');
TestAssert::contains('msg=err_duplicate_slug', $createDup['headers']['Location'], 'Redirects to msg=err_duplicate_slug');

echo "    [PASS] 06_http_api_ui_artifact_ops_smoke.php (" . TestAssert::$assertions . " assertions)\n";

