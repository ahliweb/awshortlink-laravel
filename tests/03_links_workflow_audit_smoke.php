<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\Audit\AuditChainVerifier;
use App\Domain\Links\LinkLifecycleService;
use App\Domain\Resolver\ResolveSlug;
use App\Support\PostgreSql;
use Tests\TestAssert;

echo "==> [03] Running Link Approval SoD, Destination Rollback & Hash-Chained Audit Integrity Tests (TST-004, TST-007, TST-010, #15, #18, #27)...\n";

Migrator::resetAllData();

// 1. Propose medium-risk destination (.go.id outside example.org) and verify POL-LINK-SOD blocks self-approval
$draftMedium = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_DIVISION_A,
    rawSlug: 'guideline-portal',
    title: 'Pedoman Surveilans Kemenkes RI',
    destinationUrl: 'https://portal.example.go.id/id/guideline-2026'
);
TestAssert::same('medium', $draftMedium['risk_class'], 'portal.example.go.id must be classified as medium risk');
TestAssert::true($draftMedium['requires_approval'], 'medium risk requires independent approval');

$submitted = LinkLifecycleService::submitForApproval(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: (string) $draftMedium['id'],
    reason: 'Submit medium risk link for approval'
);
TestAssert::same('submitted', $submitted['status'], 'Link status must be submitted');

// Proposer (USER_PLATFORM_OWNER) attempts self-approval -> blocked by ABAC POL-LINK-SOD!
TestAssert::throws(
    static fn () => LinkLifecycleService::approveAndPublish(
        approverId: Migrator::USER_PLATFORM_OWNER,
        linkId: (string) $draftMedium['id'],
        reason: 'Attempt self-approval'
    ),
    'ABAC_DENY_SOD_SELF_APPROVAL',
    'POL-LINK-SOD must block proposer from self-approving medium/high-risk destination'
);

// Independent approver (USER_SECURITY_APPROVER) approves -> succeeds!
$approvedV1 = LinkLifecycleService::approveAndPublish(
    approverId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftMedium['id'],
    reason: 'Independent approver verified official Kemenkes URL'
);
TestAssert::same('active', $approvedV1['status'], 'Independent approval activates link');

// 2. Propose v2, approve v2, then rollback to v1 and verify public resolver immediately reflects v1
$destV2 = LinkLifecycleService::proposeDestination(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: (string) $draftMedium['id'],
    destinationUrl: 'https://portal.example.go.id/id/guideline-2026-revisi',
    reason: 'Propose revision v2'
);
LinkLifecycleService::approveAndPublish(
    approverId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftMedium['id'],
    destinationId: (string) $destV2['id'],
    reason: 'Approve revision v2'
);
$resV2 = ResolveSlug::resolve('GET', 'guideline-portal');
TestAssert::same('https://portal.example.go.id/id/guideline-2026-revisi', $resV2['location'], 'Resolver points to v2');

$rolledBack = LinkLifecycleService::rollbackDestination(
    actorId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftMedium['id'],
    targetDestinationVersion: 1,
    reason: 'Rollback to v1 after target page issue'
);
TestAssert::same(1, $rolledBack['destination_version'], 'Rollback restores destination version 1');
$resAfterRollback = ResolveSlug::resolve('GET', 'guideline-portal');
TestAssert::same('https://portal.example.go.id/id/guideline-2026', $resAfterRollback['location'], 'Resolver immediately reflects rolled-back v1 URL');

// 3. Emergency suspend & reinstate
$suspended = LinkLifecycleService::suspendLink(
    actorId: Migrator::USER_PLATFORM_OWNER,
    linkId: (string) $draftMedium['id'],
    reason: 'Emergency suspend drill',
    isEmergency: true
);
TestAssert::same('suspended', $suspended['status'], 'Link is suspended');
TestAssert::same(404, ResolveSlug::resolve('GET', 'guideline-portal')['http_status'], 'Suspended link returns 404');

$reinstated = LinkLifecycleService::reinstateLink(
    actorId: Migrator::USER_SECURITY_APPROVER,
    linkId: (string) $draftMedium['id'],
    reason: 'Reinstate after verification'
);
TestAssert::same('active', $reinstated['status'], 'Link is reinstated');
TestAssert::same(302, ResolveSlug::resolve('GET', 'guideline-portal')['http_status'], 'Reinstated link returns 302');

// 4. Verify append-only privileges on shortlink.link_audit_events & access_decision_audit (TST-007, #18)
$ctxGlobal = RlsContext::systemGlobal();
$ctxGlobal->run(static function (\PDO $db): void {
    TestAssert::throws(
        static fn () => $db->exec("UPDATE shortlink.link_audit_events SET reason = 'Tampered' WHERE id = 1"),
        'permission denied for table link_audit_events',
        'awshortlink_app must be denied UPDATE on link_audit_events'
    );
});
$ctxGlobal->run(static function (\PDO $db): void {
    TestAssert::throws(
        static fn () => $db->exec('DELETE FROM shortlink.link_audit_events WHERE id = 1'),
        'permission denied for table link_audit_events',
        'awshortlink_app must be denied DELETE on link_audit_events'
    );
});

// 5. Verify cryptographic SHA-256 hash chain integrity across all recorded mutations
$chainReport = $ctxGlobal->run(static fn (\PDO $db): array => AuditChainVerifier::verify($db));
TestAssert::true($chainReport['valid'], 'Audit hash chain must be 100% valid');
TestAssert::true($chainReport['checked_rows'] >= 7, 'At least 7 audit events recorded and verified');
TestAssert::same(null, $chainReport['first_broken_id'], 'No broken row in untampered audit chain');

// 6. Simulate out-of-band tamper on row #2 using migrator/owner role and verify AuditChainVerifier catches exact row!
$migrator = PostgreSql::migrator();
$migrator->exec('SET ROLE awshortlink_owner');
$migrator->exec("UPDATE shortlink.link_audit_events SET reason = 'TAMPERED_OUT_OF_BAND' WHERE id = 2");
$migrator->exec('RESET ROLE');

$tamperedReport = $ctxGlobal->run(static fn (\PDO $db): array => AuditChainVerifier::verify($db));
TestAssert::same(false, $tamperedReport['valid'], 'Tampered audit chain must fail verification');
TestAssert::same(2, $tamperedReport['first_broken_id'], 'AuditChainVerifier must pinpoint exact tampered row id = 2');

echo "    [PASS] 03_links_workflow_audit_smoke.php (" . TestAssert::$assertions . " assertions)\n";

