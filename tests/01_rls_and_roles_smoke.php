<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\Links\LinkLifecycleService;
use App\Support\PostgreSql;
use Tests\TestAssert;

echo "==> [01] Running PostgreSQL-Only Contract, Role Separation & Compulsory RLS Smoke Tests (TST-017, TST-018, #10, #12, #38)...\n";

// 1. Verify non-PostgreSQL drivers are strictly rejected (ADR-0005, #10)
foreach (['sqlite', 'mysql', 'mariadb', 'sqlsrv'] as $forbiddenDriver) {
    TestAssert::throws(
        static fn () => PostgreSql::assertDriverAllowed($forbiddenDriver),
        'SECURITY_VIOLATION',
        'Forbidden driver ' . $forbiddenDriver . ' must be rejected'
    );
}
PostgreSql::assertDriverAllowed('pgsql');

// 2. Reset & seed baseline catalog on PostgreSQL 18
Migrator::migrateAndSeed();
Migrator::resetAllData();

// 3. Introspect PostgreSQL RLS & runtime role security posture (TST-018, #38)
$posture = PostgreSql::introspectSecurityPosture();
TestAssert::true($posture['healthy'], 'PostgreSQL RLS security posture must be healthy');
TestAssert::same('awshortlink_app', $posture['current_user'], 'Runtime connection must use awshortlink_app');
TestAssert::same(false, (bool) $posture['app_role_posture']['rolsuper'], 'awshortlink_app must be NOSUPERUSER');
TestAssert::same(false, (bool) $posture['app_role_posture']['rolbypassrls'], 'awshortlink_app must be NOBYPASSRLS');
TestAssert::same(false, (bool) $posture['resolver_role_posture']['rolsuper'], 'awshortlink_resolver must be NOSUPERUSER');
TestAssert::same(false, (bool) $posture['resolver_role_posture']['rolbypassrls'], 'awshortlink_resolver must be NOBYPASSRLS');
TestAssert::same(0, $posture['tables_owned_by_app_role'], 'awshortlink_app must own 0 tables');
TestAssert::same([], $posture['unprotected_tables'], 'Every table in schema shortlink must have RLS and FORCE RLS enabled');
TestAssert::true($posture['tables_with_rls_and_force'] >= 27, 'At least 27 tables must have ENABLE + FORCE RLS');

// 4. Verify No-Context Default Deny on awshortlink_app (TST-017)
$rawAppDb = PostgreSql::connection('pgsql', true);
$noCtxLinks = (int) $rawAppDb->query('SELECT count(*) FROM shortlink.links')->fetchColumn();
$noCtxUsers = (int) $rawAppDb->query('SELECT count(*) FROM shortlink.users')->fetchColumn();
$noCtxUnits = (int) $rawAppDb->query('SELECT count(*) FROM shortlink.units')->fetchColumn();
TestAssert::same(0, $noCtxLinks, 'No-context SELECT on shortlink.links must return 0 rows');
TestAssert::same(0, $noCtxUsers, 'No-context SELECT on shortlink.users must return 0 rows');
TestAssert::same(0, $noCtxUnits, 'No-context SELECT on shortlink.units must return 0 rows');

TestAssert::throws(
    static fn () => $rawAppDb->exec("INSERT INTO shortlink.units (id, code, name) VALUES ('00000000-0000-7000-8000-000000000099', 'ROGUE', 'Rogue Unit')"),
    'new row violates row-level security policy',
    'No-context INSERT on shortlink.units must be blocked by RLS'
);

// 5. Cross-Unit Isolation & Transaction-Local Context Reset (TST-017, #38)
$draftP2p = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_DIVISION_A,
    rawSlug: 'program-division-a',
    title: 'Division A programme schedule',
    destinationUrl: 'https://www.example.org/division-a/program'
);
$draftPkm = LinkLifecycleService::createDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: Migrator::UNIT_BRANCH_A,
    rawSlug: 'jadwal-pkm-arsel',
    title: 'Branch A service schedule',
    destinationUrl: 'https://www.example.org/branch-a/schedule'
);

// Query under Unit P2P context -> must see P2P link only, NOT PKM_ARSEL link
$ctxP2p = RlsContext::forActor(Migrator::USER_PLATFORM_OWNER, [Migrator::UNIT_DIVISION_A], false);
$visibleSlugsP2p = $ctxP2p->run(static function (\PDO $db): array {
    return $db->query('SELECT slug_normalized FROM shortlink.links ORDER BY slug_normalized')->fetchAll(\PDO::FETCH_COLUMN);
});
TestAssert::same(['program-division-a'], $visibleSlugsP2p, 'Unit P2P context must only see P2P links');

// Verify Unit P2P context cannot UPDATE or SELECT PKM_ARSEL link
$updatedCrossUnit = $ctxP2p->run(static function (\PDO $db) use ($draftPkm): int {
    $stmt = $db->prepare("UPDATE shortlink.links SET title = 'Tampered' WHERE id = :id");
    $stmt->execute([':id' => $draftPkm['id']]);
    return $stmt->rowCount();
});
TestAssert::same(0, $updatedCrossUnit, 'Cross-unit UPDATE must affect 0 rows under PostgreSQL RLS');

// Verify connection pool safety: after $ctxP2p->run() commits, the same PDO connection has empty context again!
$afterCommitCount = (int) PostgreSql::app()->query('SELECT count(*) FROM shortlink.links')->fetchColumn();
TestAssert::same(0, $afterCommitCount, 'After transaction COMMIT, SET LOCAL context must reset to default-deny (0 rows)');

// Verify ROLLBACK also resets transaction-local context cleanly
try {
    $ctxP2p->run(static function (\PDO $db): void {
        $inTxCount = (int) $db->query('SELECT count(*) FROM shortlink.links')->fetchColumn();
        TestAssert::same(1, $inTxCount, 'Inside transaction, Unit P2P sees 1 link');
        throw new \RuntimeException('FORCE_ROLLBACK_TEST');
    });
} catch (\RuntimeException) {
    // Expected rollback
}
$afterRollbackCount = (int) PostgreSql::app()->query('SELECT count(*) FROM shortlink.links')->fetchColumn();
TestAssert::same(0, $afterRollbackCount, 'After transaction ROLLBACK, SET LOCAL context must reset to default-deny (0 rows)');

// 6. Verify awshortlink_resolver least privilege (cannot read users, roles, audit, or raw links table)
$resolverDb = PostgreSql::resolver();
foreach (['users', 'roles', 'permissions', 'link_audit_events', 'abac_policy_versions'] as $restrictedTable) {
    TestAssert::throws(
        static fn () => $resolverDb->query('SELECT count(*) FROM shortlink.' . $restrictedTable),
        'permission denied',
        'awshortlink_resolver must be denied SELECT on shortlink.' . $restrictedTable
    );
}

echo "    [PASS] 01_rls_and_roles_smoke.php (" . TestAssert::$assertions . " assertions)\n";

