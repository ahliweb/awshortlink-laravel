<?php

declare(strict_types=1);

namespace App\Domain\AccessControl\Gate;

use App\Domain\AccessControl\Abac\PolicyEvaluator;
use App\Domain\AccessControl\Database\RlsContext;
use App\Domain\AccessControl\PermissionCatalog;
use App\Domain\Audit\AuditWriter;
use App\Support\PostgreSql;
use App\Support\UuidV7;
use PDO;

/**
 * 4-Stage Fail-Closed Authorization Pipeline (SPEC-06, ADR-0006, #19, #42).
 *
 * Permit <=> Active Identity ∧ RBAC Permission ∧ ABAC Policy ∧ Application Policy
 * Paired with transaction-local PostgreSQL RLS (`RlsContext`).
 */
final class AuthorizationPipeline
{
    /**
     * @param array<string, mixed> $resourceAttributes
     * @return array{
     *   permitted: bool,
     *   verdict: 'allow'|'deny',
     *   reason_code: string,
     *   http_status: int,
     *   actor: array<string, mixed>,
     *   matched_roles: list<string>,
     *   grantable_permissions: list<string>,
     *   expanded_unit_ids: list<string>,
     *   is_global_scope: bool,
     *   abac_trace: list<array<string, mixed>>,
     *   policy_version_id: ?string,
     *   rls_context: ?RlsContext
     * }
     */
    public static function evaluate(
        string $actorId,
        string $permissionKey,
        string $resourceType,
        array $resourceAttributes = [],
        ?bool $sessionMfaVerified = null,
        ?PDO $pdo = null,
        bool $recordAudit = true,
    ): array {
        // Validate permission exists in source-controlled catalog first (fail closed on unknown key)
        if (!PermissionCatalog::exists($permissionKey)) {
            return self::denyResult(
                actorId: $actorId,
                reasonCode: 'UNKNOWN_PERMISSION_KEY',
                httpStatus: 403,
            );
        }

        $permMeta = PermissionCatalog::getOrFail($permissionKey);
        $isMutation = PermissionCatalog::isMutationPermission($permissionKey);

        if (!UuidV7::isValid($actorId)) {
            return self::denyResult($actorId, 'INVALID_ACTOR_ID', 401);
        }

        // Load actor identity, memberships, roles, and active ABAC policies under diagnostic global read
        $ctx = RlsContext::systemGlobal($actorId);
        return $ctx->run(static function (PDO $db) use (
            $actorId,
            $permissionKey,
            $permMeta,
            $isMutation,
            $resourceType,
            $resourceAttributes,
            $sessionMfaVerified,
            $recordAudit
        ): array {
            // Stage 1: Active Identity & Session MFA state
            $userStmt = $db->prepare(
                'SELECT id, name, email, status, mfa_enrolled_at, is_protected_owner
                 FROM shortlink.users
                 WHERE id = :id'
            );
            $userStmt->execute([':id' => $actorId]);
            /** @var array<string, mixed>|false $user */
            $user = $userStmt->fetch();

            if (!is_array($user)) {
                return self::denyResult($actorId, 'IDENTITY_NOT_FOUND', 401);
            }

            $userStatus = (string) $user['status'];
            if ($userStatus !== 'active') {
                return self::auditAndReturn(
                    db: $db,
                    recordAudit: $recordAudit,
                    actorId: $actorId,
                    unitId: isset($resourceAttributes['unit_id']) ? (string) $resourceAttributes['unit_id'] : null,
                    permissionKey: $permissionKey,
                    resourceType: $resourceType,
                    result: self::denyResult($actorId, 'IDENTITY_NOT_ACTIVE_' . strtoupper($userStatus), 403, $user)
                );
            }

            $mfaVerified = $sessionMfaVerified ?? ($user['mfa_enrolled_at'] !== null);

            // Stage 2: Active Role Assignments & Unit Closure Scope Expansion
            $assignStmt = $db->prepare(
                "SELECT ura.id, ura.role_id, r.key AS role_key, r.sensitivity, ura.scope_type, ura.unit_id
                 FROM shortlink.user_role_assignments ura
                 JOIN shortlink.roles r ON r.id = ura.role_id
                 WHERE ura.user_id = :user_id
                   AND ura.revoked_at IS NULL
                   AND r.status = 'active'
                   AND ura.valid_from <= now()
                   AND (ura.valid_until IS NULL OR ura.valid_until > now())"
            );
            $assignStmt->execute([':user_id' => $actorId]);
            /** @var list<array<string, mixed>> $assignments */
            $assignments = $assignStmt->fetchAll();

            // Active unit memberships
            $memStmt = $db->prepare(
                "SELECT unit_id
                 FROM shortlink.user_unit_memberships
                 WHERE user_id = :user_id
                   AND status = 'active'
                   AND valid_from <= now()
                   AND (valid_until IS NULL OR valid_until > now())"
            );
            $memStmt->execute([':user_id' => $actorId]);
            /** @var list<string> $memberUnitIds */
            $memberUnitIds = $memStmt->fetchAll(PDO::FETCH_COLUMN);

            $isGlobalScope = false;
            $directUnitIds = $memberUnitIds;
            $descendantRoots = [];
            $roleIds = [];
            $matchedRoles = [];

            foreach ($assignments as $a) {
                $roleIds[] = (string) $a['role_id'];
                $matchedRoles[] = (string) $a['role_key'];
                $scopeType = (string) $a['scope_type'];
                if ($scopeType === 'global') {
                    $isGlobalScope = true;
                } elseif ($scopeType === 'unit' && !empty($a['unit_id'])) {
                    $directUnitIds[] = (string) $a['unit_id'];
                } elseif ($scopeType === 'unit_descendants' && !empty($a['unit_id'])) {
                    $directUnitIds[] = (string) $a['unit_id'];
                    $descendantRoots[] = (string) $a['unit_id'];
                }
            }

            $expandedUnitIds = array_values(array_unique($directUnitIds));
            if ($descendantRoots !== []) {
                $ph = implode(',', array_fill(0, count($descendantRoots), '?'));
                $closureStmt = $db->prepare(
                    "SELECT DISTINCT descendant_id::text
                     FROM shortlink.unit_closure
                     WHERE ancestor_id IN ($ph)"
                );
                $closureStmt->execute(array_values(array_unique($descendantRoots)));
                /** @var list<string> $descendants */
                $descendants = $closureStmt->fetchAll(PDO::FETCH_COLUMN);
                $expandedUnitIds = array_values(array_unique(array_merge($expandedUnitIds, $descendants)));
            }

            if ($isGlobalScope) {
                $allUnitsStmt = $db->query("SELECT id::text FROM shortlink.units WHERE status = 'active'");
                /** @var list<string> $allUnits */
                $allUnits = $allUnitsStmt->fetchAll(PDO::FETCH_COLUMN);
                $expandedUnitIds = array_values(array_unique(array_merge($expandedUnitIds, $allUnits)));
            }

            if ($roleIds === []) {
                return self::auditAndReturn(
                    db: $db,
                    recordAudit: $recordAudit,
                    actorId: $actorId,
                    unitId: isset($resourceAttributes['unit_id']) ? (string) $resourceAttributes['unit_id'] : null,
                    permissionKey: $permissionKey,
                    resourceType: $resourceType,
                    result: self::denyResult($actorId, 'RBAC_NO_ACTIVE_ROLE', 403, $user)
                );
            }

            // Query permissions granted by active roles
            $uniqueRoleIds = array_values(array_unique($roleIds));
            $rolePh = implode(',', array_fill(0, count($uniqueRoleIds), '?'));
            $permStmt = $db->prepare(
                "SELECT p.key AS perm_key, bool_or(rp.grantable) AS is_grantable
                 FROM shortlink.role_permissions rp
                 JOIN shortlink.permissions p ON p.id = rp.permission_id
                 WHERE rp.role_id IN ($rolePh)
                 GROUP BY p.key"
            );
            $permStmt->execute($uniqueRoleIds);
            /** @var list<array{perm_key: string, is_grantable: bool}> $grantedRows */
            $grantedRows = $permStmt->fetchAll();

            $hasPermission = false;
            $grantablePermissions = [];
            foreach ($grantedRows as $gr) {
                if ($gr['perm_key'] === $permissionKey) {
                    $hasPermission = true;
                }
                if ((bool) $gr['is_grantable']) {
                    $grantablePermissions[] = (string) $gr['perm_key'];
                }
            }

            if (!$hasPermission) {
                return self::auditAndReturn(
                    db: $db,
                    recordAudit: $recordAudit,
                    actorId: $actorId,
                    unitId: isset($resourceAttributes['unit_id']) ? (string) $resourceAttributes['unit_id'] : null,
                    permissionKey: $permissionKey,
                    resourceType: $resourceType,
                    result: [
                        'permitted' => false,
                        'verdict' => 'deny',
                        'reason_code' => 'RBAC_PERMISSION_DENIED',
                        'http_status' => 403,
                        'actor' => [
                            'id' => $actorId,
                            'status' => $userStatus,
                            'mfa_verified' => $mfaVerified,
                        ],
                        'matched_roles' => array_values(array_unique($matchedRoles)),
                        'grantable_permissions' => $grantablePermissions,
                        'expanded_unit_ids' => $expandedUnitIds,
                        'is_global_scope' => $isGlobalScope,
                        'abac_trace' => [],
                        'policy_version_id' => null,
                        'rls_context' => null,
                    ]
                );
            }

            // Stage 3: Evaluate Active ABAC Policies
            $polStmt = $db->query(
                "SELECT d.key AS definition_key, d.resource, d.action, v.id AS version_id, v.rule::text AS rule_json
                 FROM shortlink.abac_policy_definitions d
                 JOIN shortlink.abac_policy_versions v ON v.id = d.current_version_id
                 WHERE d.status = 'active' AND v.status = 'active'
                 ORDER BY d.key ASC"
            );
            /** @var list<array<string, mixed>> $polRows */
            $polRows = $polStmt->fetchAll();

            $activePolicies = [];
            foreach ($polRows as $pr) {
                /** @var array<string, mixed> $decodedRule */
                $decodedRule = json_decode((string) $pr['rule_json'], true, 512, JSON_THROW_ON_ERROR);
                $activePolicies[] = [
                    'definition_key' => (string) $pr['definition_key'],
                    'version_id' => (string) $pr['version_id'],
                    'resource' => (string) $pr['resource'],
                    'action' => (string) $pr['action'],
                    'rule' => $decodedRule,
                ];
            }

            $bag = [
                'actor' => [
                    'id' => $actorId,
                    'status' => $userStatus,
                    'mfa_verified' => $mfaVerified,
                    'is_global_scope' => $isGlobalScope,
                    'expanded_unit_ids' => $expandedUnitIds,
                ],
                'resource' => array_merge([
                    'id' => null,
                    'unit_id' => null,
                    'creator_id' => null,
                    'proposed_by' => null,
                    'status' => null,
                    'risk_class' => 'low',
                    'visibility' => 'public',
                ], $resourceAttributes),
                'context' => [
                    'permission_key' => $permissionKey,
                    'permission_risk' => $permMeta['risk'],
                    'is_mutation' => $isMutation,
                    'scope_type' => $isGlobalScope ? 'global' : 'unit',
                ],
            ];

            $abacResult = PolicyEvaluator::evaluateAll($resourceType, $permissionKey, $activePolicies, $bag);
            if ($abacResult['verdict'] === 'deny') {
                return self::auditAndReturn(
                    db: $db,
                    recordAudit: $recordAudit,
                    actorId: $actorId,
                    unitId: isset($resourceAttributes['unit_id']) ? (string) $resourceAttributes['unit_id'] : null,
                    permissionKey: $permissionKey,
                    resourceType: $resourceType,
                    result: [
                        'permitted' => false,
                        'verdict' => 'deny',
                        'reason_code' => $abacResult['reason_code'],
                        'http_status' => 403,
                        'actor' => $bag['actor'],
                        'matched_roles' => array_values(array_unique($matchedRoles)),
                        'grantable_permissions' => $grantablePermissions,
                        'expanded_unit_ids' => $expandedUnitIds,
                        'is_global_scope' => $isGlobalScope,
                        'abac_trace' => $abacResult['trace'],
                        'policy_version_id' => $abacResult['matched_version_id'],
                        'rls_context' => null,
                    ]
                );
            }

            // Stage 4: Permit + Build RLS Context
            $rlsContext = RlsContext::forActor(
                actorId: $actorId,
                unitIds: $expandedUnitIds,
                isGlobal: $isGlobalScope
            );

            $permitResult = [
                'permitted' => true,
                'verdict' => 'allow',
                'reason_code' => 'PERMITTED_RBAC_AND_ABAC',
                'http_status' => 200,
                'actor' => $bag['actor'],
                'matched_roles' => array_values(array_unique($matchedRoles)),
                'grantable_permissions' => $grantablePermissions,
                'expanded_unit_ids' => $expandedUnitIds,
                'is_global_scope' => $isGlobalScope,
                'abac_trace' => $abacResult['trace'],
                'policy_version_id' => $abacResult['matched_version_id'],
                'rls_context' => $rlsContext,
            ];

            // Record access decision audit for high/critical permits or when requested
            if ($recordAudit && in_array($permMeta['risk'], ['high', 'critical'], true)) {
                AuditWriter::recordAccessDecision(
                    db: $db,
                    actorId: $actorId,
                    unitId: isset($resourceAttributes['unit_id']) ? (string) $resourceAttributes['unit_id'] : null,
                    permission: $permissionKey,
                    resourceType: $resourceType,
                    verdict: 'allow',
                    reasonCode: 'PERMITTED_RBAC_AND_ABAC',
                    policyVersionId: $abacResult['matched_version_id']
                );
            }

            return $permitResult;
        }, $pdo);
    }

    /**
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    private static function auditAndReturn(
        PDO $db,
        bool $recordAudit,
        string $actorId,
        ?string $unitId,
        string $permissionKey,
        string $resourceType,
        array $result
    ): array {
        if ($recordAudit && UuidV7::isValid($actorId)) {
            AuditWriter::recordAccessDecision(
                db: $db,
                actorId: $actorId,
                unitId: $unitId,
                permission: $permissionKey,
                resourceType: $resourceType,
                verdict: (string) $result['verdict'],
                reasonCode: (string) $result['reason_code'],
                policyVersionId: isset($result['policy_version_id']) ? (string) $result['policy_version_id'] : null
            );
        }
        return $result;
    }

    /**
     * @param array<string, mixed>|null $user
     * @return array<string, mixed>
     */
    private static function denyResult(
        string $actorId,
        string $reasonCode,
        int $httpStatus,
        ?array $user = null
    ): array {
        return [
            'permitted' => false,
            'verdict' => 'deny',
            'reason_code' => $reasonCode,
            'http_status' => $httpStatus,
            'actor' => [
                'id' => $actorId,
                'status' => $user['status'] ?? 'unknown',
                'mfa_verified' => false,
            ],
            'matched_roles' => [],
            'grantable_permissions' => [],
            'expanded_unit_ids' => [],
            'is_global_scope' => false,
            'abac_trace' => [],
            'policy_version_id' => null,
            'rls_context' => null,
        ];
    }
}

