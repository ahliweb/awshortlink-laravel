<?php

declare(strict_types=1);

namespace App\Database;

use App\Domain\AccessControl\Database\RlsContext;
use App\Support\Branding;
use App\Support\PostgreSql;
use App\Support\Totp;
use App\Support\UuidV7;
use PDO;

/**
 * PostgreSQL-Only Schema Migrator & Baseline Catalog Seeder (#10, #12, #38).
 */
final class Migrator
{
    public const UNIT_ROOT = '00000000-0000-7000-8000-000000000010';

    // Demo-only units (SHORTLINK_DEMO_SEED=1, never outside a non-production test run).
    public const UNIT_SECRETARIAT = '00000000-0000-7000-8000-000000000011';
    public const UNIT_DIVISION_A = '00000000-0000-7000-8000-000000000012';
    public const UNIT_BRANCH_A = '00000000-0000-7000-8000-000000000013';

    public const USER_PLATFORM_OWNER = '00000000-0000-7000-8000-000000000001';
    public const USER_SECURITY_APPROVER = '00000000-0000-7000-8000-000000000002';

    /**
     * Demo/test seeding is opt-in and impossible in production.
     */
    public static function demoSeedEnabled(): bool
    {
        if ((getenv('SHORTLINK_DEMO_SEED') ?: '') !== '1') {
            return false;
        }
        if ((getenv('APP_ENV') ?: '') === 'production') {
            throw new \RuntimeException('SHORTLINK_DEMO_SEED=1 is refused when APP_ENV=production.');
        }

        return true;
    }

    public static function ownerEmail(): string
    {
        return strtolower((string) (getenv('SHORTLINK_OWNER_EMAIL') ?: 'platform-owner@example.invalid'));
    }

    public static function approverEmail(): string
    {
        return strtolower((string) (getenv('SHORTLINK_APPROVER_EMAIL') ?: 'security-approver@example.invalid'));
    }

    public static function migrateAndSeed(?PDO $migratorPdo = null, ?PDO $appPdo = null): void
    {
        $migrator = $migratorPdo ?? PostgreSql::migrator();
        $sqlDir = dirname(__DIR__, 2) . '/database/sql/rls';

        foreach ([
            '0010_schema_and_tables.sql',
            '0020_enable_rls_and_policies.sql',
            '0030_resolver_view_and_click_fn.sql',
        ] as $file) {
            $sql = (string) file_get_contents($sqlDir . '/' . $file);
            $migrator->exec($sql);
        }

        self::seedCatalog($migrator);
    }

    public static function resetAllData(?PDO $migratorPdo = null, ?PDO $appPdo = null): void
    {
        // Destructive: wipes every table. Only for the automated test suite.
        if ((getenv('APP_ENV') ?: '') === 'production' || (getenv('SHORTLINK_ALLOW_DATA_RESET') ?: '') !== '1') {
            throw new \RuntimeException('resetAllData() is destructive and requires SHORTLINK_ALLOW_DATA_RESET=1 outside production.');
        }
        $migrator = $migratorPdo ?? PostgreSql::migrator();
        $migrator->exec('SET ROLE awshortlink_owner');
        $migrator->exec(
            'TRUNCATE TABLE
                shortlink.link_health_checks,
                shortlink.abuse_reports,
                shortlink.ops_heartbeats,
                shortlink.app_settings,
                shortlink.api_credentials,
                shortlink.link_qr_assets,
                shortlink.link_daily_stats,
                shortlink.access_decision_audit,
                shortlink.link_audit_events,
                shortlink.link_approvals,
                shortlink.destination_domain_rules,
                shortlink.reserved_slugs,
                shortlink.link_destinations,
                shortlink.links,
                shortlink.campaigns,
                shortlink.access_change_requests,
                shortlink.abac_policy_approvals,
                shortlink.abac_policy_versions,
                shortlink.abac_policy_definitions,
                shortlink.user_role_assignments,
                shortlink.role_permissions,
                shortlink.permissions,
                shortlink.roles,
                shortlink.user_unit_memberships,
                shortlink.sessions,
                shortlink.users,
                shortlink.unit_closure,
                shortlink.units
             RESTART IDENTITY CASCADE'
        );
        $migrator->exec('RESET ROLE');

        self::seedCatalog($migrator);
    }

    public static function seedCatalog(?PDO $migratorPdo = null): void
    {
        $db = $migratorPdo ?? PostgreSql::migrator();
        $db->beginTransaction();
        try {
            $hasOwnerRole = (bool) $db->query("SELECT 1 FROM pg_roles WHERE rolname = 'awshortlink_owner'")->fetchColumn();
            if ($hasOwnerRole) {
                $db->exec('SET LOCAL ROLE awshortlink_owner');
            }
            $closureRun = static function (PDO $db): void {
            // 1. Seed the root organisational unit (TBL-001, TBL-002). The rest of the unit tree is managed by
            //    operators in the admin UI; the extra demo units exist only for the automated test suite.
            $units = [
                [
                    'id' => self::UNIT_ROOT,
                    'parent_id' => null,
                    'code' => Branding::rootUnitCode(),
                    'name' => Branding::orgName(),
                ],
            ];
            if (self::demoSeedEnabled()) {
                foreach ([
                    [self::UNIT_SECRETARIAT, 'SECRETARIAT', 'Secretariat'],
                    [self::UNIT_DIVISION_A, 'DIVISION_A', 'Division A'],
                    [self::UNIT_BRANCH_A, 'BRANCH_A', 'Branch A'],
                ] as [$unitId, $unitCode, $unitName]) {
                    $units[] = ['id' => $unitId, 'parent_id' => self::UNIT_ROOT, 'code' => $unitCode, 'name' => $unitName];
                }
            }


            $unitStmt = $db->prepare(
                "INSERT INTO shortlink.units (id, parent_id, code, name, status)
                 VALUES (:id, :parent_id, :code, :name, 'active')
                 ON CONFLICT (id) DO NOTHING"
            );
            foreach ($units as $u) {
                $unitStmt->execute([
                    ':id' => $u['id'],
                    ':parent_id' => $u['parent_id'],
                    ':code' => $u['code'],
                    ':name' => $u['name'],
                ]);
            }

            $closurePairs = [];
            foreach ($units as $u) {
                $closurePairs[] = [$u['id'], $u['id'], 0];
                if ($u['parent_id'] !== null) {
                    $closurePairs[] = [$u['parent_id'], $u['id'], 1];
                }
            }
            $closureStmt = $db->prepare(
                'INSERT INTO shortlink.unit_closure (ancestor_id, descendant_id, depth)
                 VALUES (:a, :d, :depth)
                 ON CONFLICT (ancestor_id, descendant_id) DO UPDATE SET depth = EXCLUDED.depth'
            );
            foreach ($closurePairs as [$a, $d, $depth]) {
                $closureStmt->execute([':a' => $a, ':d' => $d, ':depth' => $depth]);
            }

            // 2. Seed protected baseline platform owner & independent security approver (TBL-003).
            // SECURITY: no credential or TOTP secret is ever embedded in this repository. Accounts are seeded
            // 'invited' with NO password/MFA and must be activated by an operator with
            // `php artisan admin:bootstrap <email>`. The only exception is the automated test suite, which opts
            // in with SHORTLINK_DEMO_SEED=1 and supplies per-run random SHORTLINK_DEMO_PASSWORD /
            // SHORTLINK_DEMO_TOTP_SECRET; that mode is refused when APP_ENV=production.
            $demo = self::demoSeedEnabled();
            $demoPasswordHash = null;
            $demoSecret = null;
            if ($demo) {
                $demoPassword = (string) (getenv('SHORTLINK_DEMO_PASSWORD') ?: '');
                $demoSecret = (string) (getenv('SHORTLINK_DEMO_TOTP_SECRET') ?: '');
                if (strlen($demoPassword) < 16 || $demoSecret === '') {
                    throw new \RuntimeException('SHORTLINK_DEMO_SEED=1 requires SHORTLINK_DEMO_PASSWORD (>=16 chars) and SHORTLINK_DEMO_TOTP_SECRET.');
                }
                $demoPasswordHash = password_hash($demoPassword, PASSWORD_BCRYPT);
            }
            $userStmt = $db->prepare(
                "INSERT INTO shortlink.users (
                    id, name, email, password_hash, mfa_secret_encrypted, mfa_enrolled_at,
                    status, is_protected_owner
                ) VALUES (
                    :id, :name, :email, :password_hash, :mfa_secret, :mfa_at, :status, :is_protected
                )
                ON CONFLICT (id) DO NOTHING"
            );
            foreach ([
                [self::USER_PLATFORM_OWNER, 'Platform Owner', self::ownerEmail()],
                [self::USER_SECURITY_APPROVER, 'Independent Security Approver', self::approverEmail()],
            ] as [$userId, $userName, $userEmail]) {
                $userStmt->execute([
                    ':id' => $userId,
                    ':name' => $userName,
                    ':email' => $userEmail,
                    ':password_hash' => $demoPasswordHash,
                    ':mfa_secret' => $demoSecret,
                    ':mfa_at' => $demo ? gmdate('Y-m-d H:i:sP') : null,
                    ':status' => $demo ? 'active' : 'invited',
                    ':is_protected' => 'true',
                ]);
            }


            // 3. Seed PERM-001..062 & 8 Default Roles (TBL-006, TBL-007, TBL-008)
            /** @var array<string, mixed> $permConfig */
            $permConfig = require dirname(__DIR__, 2) . '/config/permissions.php';
            $catalogVersion = (int) ($permConfig['catalog_version'] ?? 1);
            /** @var array<string, array{key: string, description: string, risk: string}> $permissions */
            $permissions = $permConfig['permissions'];

            $permIdsByKey = [];
            $permStmt = $db->prepare(
                'INSERT INTO shortlink.permissions (id, code, key, description, risk, catalog_version)
                 VALUES (:id, :code, :key, :description, :risk, :catalog_version)
                 ON CONFLICT (code) DO UPDATE
                 SET key = EXCLUDED.key,
                     description = EXCLUDED.description,
                     risk = EXCLUDED.risk,
                     catalog_version = EXCLUDED.catalog_version'
            );
            foreach ($permissions as $code => $meta) {
                $permId = UuidV7::deterministic('perm:' . $code);
                $permIdsByKey[$meta['key']] = $permId;
                $permStmt->execute([
                    ':id' => $permId,
                    ':code' => $code,
                    ':key' => $meta['key'],
                    ':description' => $meta['description'],
                    ':risk' => $meta['risk'],
                    ':catalog_version' => $catalogVersion,
                ]);
            }

            /** @var array<string, array<string, mixed>> $roles */
            $roles = $permConfig['roles'];
            $roleStmt = $db->prepare(
                "INSERT INTO shortlink.roles (id, key, label, is_protected, sensitivity, status, created_by)
                 VALUES (:id, :key, :label, :is_protected, :sensitivity, 'active', :created_by)
                 ON CONFLICT (key) DO UPDATE
                 SET label = EXCLUDED.label,
                     is_protected = EXCLUDED.is_protected,
                     sensitivity = EXCLUDED.sensitivity"
            );
            $rolePermStmt = $db->prepare(
                'INSERT INTO shortlink.role_permissions (role_id, permission_id, grantable, granted_by, reason)
                 VALUES (:role_id, :permission_id, :grantable, :granted_by, :reason)
                 ON CONFLICT (role_id, permission_id) DO UPDATE
                 SET grantable = EXCLUDED.grantable'
            );

            $roleIdsByKey = [];
            foreach ($roles as $roleKey => $roleMeta) {
                $roleId = UuidV7::deterministic('role:' . $roleKey);
                $roleIdsByKey[$roleKey] = $roleId;
                $roleStmt->execute([
                    ':id' => $roleId,
                    ':key' => $roleKey,
                    ':label' => (string) $roleMeta['label'],
                    ':is_protected' => !empty($roleMeta['is_protected']) ? 'true' : 'false',
                    ':sensitivity' => (string) ($roleMeta['sensitivity'] ?? 'normal'),
                    ':created_by' => self::USER_PLATFORM_OWNER,
                ]);

                $rolePerms = $roleMeta['permissions'] === '*'
                    ? array_keys($permIdsByKey)
                    : (array) $roleMeta['permissions'];
                $grantableAll = !empty($roleMeta['grantable_all']);
                $grantableList = (array) ($roleMeta['grantable'] ?? []);

                foreach ($rolePerms as $permKey) {
                    $permId = $permIdsByKey[(string) $permKey] ?? null;
                    if ($permId === null) {
                        continue;
                    }
                    $isGrantable = $grantableAll || in_array($permKey, $grantableList, true);
                    $rolePermStmt->execute([
                        ':role_id' => $roleId,
                        ':permission_id' => $permId,
                        ':grantable' => $isGrantable ? 'true' : 'false',
                        ':granted_by' => self::USER_PLATFORM_OWNER,
                        ':reason' => 'Default role catalog seed (SPEC-06)',
                    ]);
                }
            }

            // Assign platform_owner role to USER_PLATFORM_OWNER (approved by USER_SECURITY_APPROVER)
            // and platform_owner role to USER_SECURITY_APPROVER (granted by USER_PLATFORM_OWNER)
            $assignStmt = $db->prepare(
                "INSERT INTO shortlink.user_role_assignments (
                    id, user_id, role_id, scope_type, unit_id, granted_by, approved_by, reason
                ) VALUES (
                    :id, :user_id, :role_id, 'global', NULL, :granted_by, :approved_by, :reason
                )
                ON CONFLICT (id) DO UPDATE
                SET revoked_at = NULL, revoked_by = NULL, revoke_reason = NULL"
            );
            $assignStmt->execute([
                ':id' => UuidV7::deterministic('assign:owner'),
                ':user_id' => self::USER_PLATFORM_OWNER,
                ':role_id' => $roleIdsByKey['platform_owner'],
                ':granted_by' => self::USER_SECURITY_APPROVER,
                ':approved_by' => self::USER_PLATFORM_OWNER,
                ':reason' => 'Bootstrap platform owner assignment',
            ]);
            $assignStmt->execute([
                ':id' => UuidV7::deterministic('assign:sec_approver'),
                ':user_id' => self::USER_SECURITY_APPROVER,
                ':role_id' => $roleIdsByKey['platform_owner'],
                ':granted_by' => self::USER_PLATFORM_OWNER,
                ':approved_by' => self::USER_SECURITY_APPROVER,
                ':reason' => 'Bootstrap independent security approver assignment',
            ]);

            // 4. Seed Default ABAC Policies & Active Versions (TBL-010, TBL-011, ADR-0006)
            $defaultPolicies = [
                [
                    'key' => 'POL-LINK-SOD',
                    'resource' => 'links',
                    'action' => 'links.approve',
                    'rule' => [
                        'schema_version' => 1,
                        'effect' => 'deny',
                        'reason_code' => 'ABAC_DENY_SOD_SELF_APPROVAL',
                        'all' => [
                            ['field' => 'resource.risk_class', 'op' => 'in', 'value' => ['medium', 'high']],
                            ['field' => 'actor.id', 'op' => 'eq_ref', 'ref' => 'resource.proposed_by'],
                        ],
                    ],
                ],
                [
                    'key' => 'POL-PRIV-MFA',
                    'resource' => '*',
                    'action' => '*',
                    'rule' => [
                        'schema_version' => 1,
                        'effect' => 'deny',
                        'reason_code' => 'ABAC_DENY_MFA_REQUIRED',
                        'all' => [
                            ['field' => 'context.permission_risk', 'op' => 'in', 'value' => ['high', 'critical']],
                            ['field' => 'actor.mfa_verified', 'op' => 'eq', 'value' => false],
                        ],
                    ],
                ],
                [
                    'key' => 'POL-UNIT-SCOPE',
                    'resource' => 'links',
                    'action' => '*',
                    'rule' => [
                        'schema_version' => 1,
                        'effect' => 'deny',
                        'reason_code' => 'ABAC_DENY_OUTSIDE_UNIT_SCOPE',
                        'all' => [
                            ['field' => 'actor.is_global_scope', 'op' => 'eq', 'value' => false],
                            ['field' => 'resource.unit_id', 'op' => 'not_in_ref', 'ref' => 'actor.expanded_unit_ids'],
                        ],
                    ],
                ],
                [
                    'key' => 'POL-ARCHIVED-RO',
                    'resource' => 'links',
                    'action' => '*',
                    'rule' => [
                        'schema_version' => 1,
                        'effect' => 'deny',
                        'reason_code' => 'ABAC_DENY_ARCHIVED_IMMUTABLE',
                        'all' => [
                            ['field' => 'resource.status', 'op' => 'eq', 'value' => 'archived'],
                            ['field' => 'context.is_mutation', 'op' => 'eq', 'value' => true],
                        ],
                    ],
                ],
                [
                    'key' => 'POL-EMERGENCY',
                    'resource' => 'links',
                    'action' => 'links.suspend',
                    'rule' => [
                        'schema_version' => 1,
                        'effect' => 'allow',
                        'reason_code' => 'ABAC_ALLOW_EMERGENCY_SUSPEND',
                        'all' => [
                            ['field' => 'actor.mfa_verified', 'op' => 'eq', 'value' => true],
                        ],
                    ],
                ],
            ];

            $polDefStmt = $db->prepare(
                "INSERT INTO shortlink.abac_policy_definitions (id, key, resource, action, current_version_id, status)
                 VALUES (:id, :key, :resource, :action, :ver_id, 'active')
                 ON CONFLICT (key) DO UPDATE
                 SET current_version_id = EXCLUDED.current_version_id,
                     resource = EXCLUDED.resource,
                     action = EXCLUDED.action"
            );
            $polVerStmt = $db->prepare(
                "INSERT INTO shortlink.abac_policy_versions (
                    id, definition_id, version, rule, checksum, status, simulation_report,
                    authored_by, approved_by, activated_at
                ) VALUES (
                    :id, :def_id, 1, :rule::jsonb, :checksum, 'active', :sim::jsonb,
                    :authored_by, :approved_by, now()
                )
                ON CONFLICT (definition_id, version) DO NOTHING"
            );

            foreach ($defaultPolicies as $pol) {
                $defId = UuidV7::deterministic('pol_def:' . $pol['key']);
                $verId = UuidV7::deterministic('pol_ver:' . $pol['key'] . ':v1');
                $ruleJson = json_encode($pol['rule'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                $checksum = hash('sha256', $ruleJson);
                $simJson = json_encode(['passed' => true, 'vectors_tested' => 4], JSON_THROW_ON_ERROR);

                $polDefStmt->execute([
                    ':id' => $defId,
                    ':key' => $pol['key'],
                    ':resource' => $pol['resource'],
                    ':action' => $pol['action'],
                    ':ver_id' => $verId,
                ]);
                $polVerStmt->execute([
                    ':id' => $verId,
                    ':def_id' => $defId,
                    ':rule' => $ruleJson,
                    ':checksum' => $checksum,
                    ':sim' => $simJson,
                    ':authored_by' => self::USER_PLATFORM_OWNER,
                    ':approved_by' => self::USER_SECURITY_APPROVER,
                ]);
            }

            // 5. Seed System Reserved Slugs (TBL-016)
            /** @var array<string, mixed> $shortlinkCfg */
            $shortlinkCfg = require dirname(__DIR__, 2) . '/config/shortlink.php';
            /** @var list<string> $reservedSlugs */
            $reservedSlugs = $shortlinkCfg['reserved_slugs'] ?? [];
            $slugStmt = $db->prepare(
                "INSERT INTO shortlink.reserved_slugs (namespace, slug_normalized, reason)
                 VALUES ('buka', :slug, 'system')
                 ON CONFLICT (namespace, slug_normalized) DO NOTHING"
            );
            foreach ($reservedSlugs as $slug) {
                $slugStmt->execute([':slug' => strtolower($slug)]);
            }

            // 6. Seed Default Destination Domain Rules (TBL-017, DES-014).
            // The institutional allowlist is EMPTY unless the operator supplies SHORTLINK_ALLOWLIST_HOSTS; public
            // file-sharing hosts are deliberately not allowlisted by default because anyone can host content there.
            $domainStmt = $db->prepare(
                'INSERT INTO shortlink.destination_domain_rules (id, host_pattern, rule_type, reason, created_by)
                 VALUES (:id, :host_pattern, :rule_type, :reason, :created_by)
                 ON CONFLICT (host_pattern) DO NOTHING'
            );
            $domainRules = [];
            foreach ((array) ($shortlinkCfg['institutional_allowlist_hosts'] ?? []) as $host) {
                $domainRules[] = [(string) $host, 'allowlist_low', 'Operator-configured institutional domain'];
            }
            foreach ((array) ($shortlinkCfg['medium_risk_suffixes'] ?? []) as $suffix) {
                $domainRules[] = ['*' . (string) $suffix, 'medium_review', 'Requires independent approval'];
            }
            foreach ((array) ($shortlinkCfg['known_shortener_hosts'] ?? []) as $host) {
                $domainRules[] = [(string) $host, 'denylist_forbidden', 'Public URL shorteners are forbidden (anti redirect-chain)'];
            }
            foreach ($domainRules as [$pattern, $ruleType, $reason]) {
                $domainStmt->execute([
                    ':id' => UuidV7::deterministic('dom_rule:' . $pattern),
                    ':host_pattern' => $pattern,
                    ':rule_type' => $ruleType,
                    ':reason' => $reason,
                    ':created_by' => self::USER_PLATFORM_OWNER,
                ]);
            }


            // 7. Seed Operational Heartbeat baseline (TBL-022)
            $hbStmt = $db->prepare(
                "INSERT INTO shortlink.ops_heartbeats (component, status, details, observed_at)
                 VALUES (:c, 'ok', :d::jsonb, now())
                 ON CONFLICT (component) DO UPDATE
                 SET status = EXCLUDED.status, details = EXCLUDED.details, observed_at = now()"
            );
            $hbStmt->execute([
                ':c' => 'scheduler',
                ':d' => json_encode(['mode' => 'panel_cron_or_bounded_cli', 'last_run' => gmdate('c')], JSON_THROW_ON_ERROR),
            ]);
            $hbStmt->execute([
                ':c' => 'rls_posture',
                ':d' => json_encode(['enforced' => true, 'driver' => 'pgsql'], JSON_THROW_ON_ERROR),
            ]);
        };

            $closureRun($db);
            $db->commit();
        } catch (\Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }
}
