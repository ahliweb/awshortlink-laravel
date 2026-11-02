<?php

declare(strict_types=1);

namespace App\Domain\AccessControl;

use App\Domain\AccessControl\Abac\PolicyEvaluator;
use App\Domain\AccessControl\Abac\RuleSchemaValidator;
use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Domain\Identity\IdentityService;
use App\Support\UuidV7;
use PDO;
use RuntimeException;

/**
 * Managed RBAC Role Matrix, Delegated Grants, Dual-Control Requests & ABAC Policy Lifecycle Service (#40, #41).
 */
final class RbacAbacService
{
    /**
     * Creates a custom RBAC role (`is_protected = false`) (#40, API-040).
     *
     * @return array<string, mixed>
     */
    public static function createCustomRole(
        string $actorId,
        string $key,
        string $label,
        string $sensitivity = 'normal',
        ?string $ownerUnitId = null,
        string $reason = 'Create custom role',
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'roles.create',
            resourceType: 'roles',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        if ($sensitivity === 'protected') {
            throw new RuntimeException('CUSTOM_ROLE_CANNOT_BE_PROTECTED');
        }

        $roleId = UuidV7::generate();
        $cleanKey = strtolower(trim($key));

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $roleId,
            $cleanKey,
            $label,
            $sensitivity,
            $ownerUnitId,
            $reason
        ): array {
            $stmt = $db->prepare(
                "INSERT INTO shortlink.roles (
                    id, key, label, is_protected, sensitivity, status, owner_unit_id, created_by
                ) VALUES (
                    :id, :key, :label, false, :sensitivity, 'active', :owner_unit_id, :created_by
                )
                RETURNING id, key, label, is_protected, sensitivity, status, version"
            );
            $stmt->execute([
                ':id' => $roleId,
                ':key' => $cleanKey,
                ':label' => trim($label),
                ':sensitivity' => $sensitivity,
                ':owner_unit_id' => $ownerUnitId,
                ':created_by' => $actorId,
            ]);
            /** @var array<string, mixed> $role */
            $role = $stmt->fetch();

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'roles.created',
                subjectType: 'role',
                subjectId: $roleId,
                subjectVersion: 1,
                unitId: $ownerUnitId,
                beforeState: null,
                afterState: $role,
                reason: $reason
            );

            return $role;
        }, $pdo);
    }

    /**
     * Replaces a custom role's permission matrix while enforcing the delegation ceiling (`grantable = true`) (#40, API-042).
     *
     * @param list<array{permission_key: string, grantable?: bool}> $permissions
     * @return array{role_id: string, permissions_count: int, version: int}
     */
    public static function replaceRolePermissions(
        string $actorId,
        string $roleId,
        array $permissions,
        string $reason,
        ?int $expectedVersion = null,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'roles.permissions.update',
            resourceType: 'roles',
            resourceAttributes: ['id' => $roleId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        // Validate every permission key & check delegation ceiling
        $grantableSet = $auth['grantable_permissions'];
        foreach ($permissions as $item) {
            $permKey = (string) ($item['permission_key'] ?? '');
            PermissionCatalog::getOrFail($permKey);
            if (!in_array($permKey, $grantableSet, true)) {
                throw new RuntimeException(sprintf(
                    'DELEGATION_CEILING_EXCEEDED: Actor cannot grant permission "%s" beyond their own grantable ceiling.',
                    $permKey
                ));
            }
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $roleId,
            $permissions,
            $reason,
            $expectedVersion
        ): array {
            $roleStmt = $db->prepare('SELECT id, key, is_protected, version FROM shortlink.roles WHERE id = :id');
            $roleStmt->execute([':id' => $roleId]);
            /** @var array<string, mixed>|false $role */
            $role = $roleStmt->fetch();
            if (!is_array($role)) {
                throw new RuntimeException('ROLE_NOT_FOUND');
            }
            if ((bool) $role['is_protected']) {
                throw new RuntimeException('PROTECTED_ROLE_IMMUTABLE: Built-in protected roles cannot have their permission matrix altered.');
            }
            $lockStmt = $db->prepare('SELECT version FROM shortlink.roles WHERE id = :id FOR UPDATE');
            $lockStmt->execute([':id' => $roleId]);
            if ($expectedVersion !== null && (int) $role['version'] !== $expectedVersion) {
                throw new RuntimeException('STALE_VERSION: Expected version ' . $expectedVersion);
            }

            $del = $db->prepare('DELETE FROM shortlink.role_permissions WHERE role_id = :role_id');
            $del->execute([':role_id' => $roleId]);

            $ins = $db->prepare(
                'INSERT INTO shortlink.role_permissions (role_id, permission_id, grantable, granted_by, reason)
                 SELECT :role_id, p.id, :grantable, :granted_by, :reason
                 FROM shortlink.permissions p
                 WHERE p.key = :perm_key'
            );
            foreach ($permissions as $item) {
                $ins->execute([
                    ':role_id' => $roleId,
                    ':grantable' => !empty($item['grantable']) ? 'true' : 'false',
                    ':granted_by' => $actorId,
                    ':reason' => $reason,
                    ':perm_key' => (string) $item['permission_key'],
                ]);
            }

            $newVersion = ((int) $role['version']) + 1;
            $upd = $db->prepare('UPDATE shortlink.roles SET version = :v, updated_at = now() WHERE id = :id');
            $upd->execute([':v' => $newVersion, ':id' => $roleId]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'roles.permissions_updated',
                subjectType: 'role',
                subjectId: $roleId,
                subjectVersion: $newVersion,
                beforeState: ['version' => (int) $role['version']],
                afterState: ['permissions_count' => count($permissions), 'version' => $newVersion],
                reason: $reason
            );

            return [
                'role_id' => $roleId,
                'permissions_count' => count($permissions),
                'version' => $newVersion,
            ];
        }, $pdo);
    }

    /**
     * Assigns a role to a user or creates a dual-control `access_change_request` when sensitivity/scope requires independent approval (#40, API-043).
     *
     * @return array<string, mixed>
     */
    public static function assignRoleOrRequest(
        string $actorId,
        string $targetUserId,
        string $roleKey,
        string $scopeType,
        ?string $unitId,
        string $reason,
        ?string $validUntil = null,
        ?PDO $pdo = null,
    ): array {
        if ($actorId === $targetUserId) {
            throw new RuntimeException('SELF_ROLE_GRANT_FORBIDDEN: Cannot grant role to oneself.');
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'user_roles.assign',
            resourceType: 'user_role_assignments',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        // Non-global actors can only grant within their expanded unit scope
        if (!$auth['is_global_scope']) {
            if ($scopeType === 'global' || $unitId === null || !in_array($unitId, $auth['expanded_unit_ids'], true)) {
                throw new RuntimeException('DELEGATION_SCOPE_EXCEEDED: Cannot assign role outside authorized unit scope.');
            }
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $targetUserId,
            $roleKey,
            $scopeType,
            $unitId,
            $reason,
            $validUntil,
            $auth
        ): array {
            $roleStmt = $db->prepare('SELECT id, key, sensitivity FROM shortlink.roles WHERE key = :key AND status = \'active\'');
            $roleStmt->execute([':key' => $roleKey]);
            /** @var array<string, mixed>|false $role */
            $role = $roleStmt->fetch();
            if (!is_array($role)) {
                throw new RuntimeException('ROLE_NOT_FOUND:' . $roleKey);
            }

            $roleId = (string) $role['id'];
            $sensitivity = (string) $role['sensitivity'];

            // Check that every permission in the target role is within the actor's grantable ceiling
            $permStmt = $db->prepare(
                'SELECT p.key FROM shortlink.role_permissions rp
                 JOIN shortlink.permissions p ON p.id = rp.permission_id
                 WHERE rp.role_id = :role_id'
            );
            $permStmt->execute([':role_id' => $roleId]);
            /** @var list<string> $rolePerms */
            $rolePerms = $permStmt->fetchAll(PDO::FETCH_COLUMN);
            foreach ($rolePerms as $rp) {
                if (!in_array($rp, $auth['grantable_permissions'], true)) {
                    throw new RuntimeException(sprintf(
                        'DELEGATION_CEILING_EXCEEDED: Role "%s" contains permission "%s" outside actor grantable ceiling.',
                        $roleKey,
                        $rp
                    ));
                }
            }

            // Dual-control required for sensitive/protected roles or global scope
            if (in_array($sensitivity, ['sensitive', 'protected'], true) || $scopeType === 'global') {
                $reqId = UuidV7::generate();
                $payload = json_encode([
                    'role_key' => $roleKey,
                    'valid_until' => $validUntil,
                ], JSON_THROW_ON_ERROR);

                $reqStmt = $db->prepare(
                    "INSERT INTO shortlink.access_change_requests (
                        id, unit_id, requested_by, target_user_id, role_id, scope_type, change_payload, status, reason
                    ) VALUES (
                        :id, :unit_id, :requested_by, :target_user_id, :role_id, :scope_type, :payload::jsonb, 'pending', :reason
                    )"
                );
                $reqStmt->execute([
                    ':id' => $reqId,
                    ':unit_id' => $unitId,
                    ':requested_by' => $actorId,
                    ':target_user_id' => $targetUserId,
                    ':role_id' => $roleId,
                    ':scope_type' => $scopeType,
                    ':payload' => $payload,
                    ':reason' => $reason,
                ]);

                AuditWriter::recordMutation(
                    db: $db,
                    actorId: $actorId,
                    action: 'user_roles.request_created',
                    subjectType: 'access_change_request',
                    subjectId: $reqId,
                    subjectVersion: 1,
                    unitId: $unitId,
                    afterState: ['request_id' => $reqId, 'role_key' => $roleKey, 'target_user_id' => $targetUserId],
                    reason: $reason
                );

                return [
                    'mode' => 'pending_dual_control',
                    'request_id' => $reqId,
                    'status' => 'pending',
                    'role_key' => $roleKey,
                ];
            }

            // Direct assignment for normal unit-scoped role
            $assignId = UuidV7::generate();
            $ins = $db->prepare(
                'INSERT INTO shortlink.user_role_assignments (
                    id, user_id, role_id, scope_type, unit_id, valid_until, granted_by, reason
                ) VALUES (
                    :id, :user_id, :role_id, :scope_type, :unit_id, :valid_until, :granted_by, :reason
                )'
            );
            $ins->execute([
                ':id' => $assignId,
                ':user_id' => $targetUserId,
                ':role_id' => $roleId,
                ':scope_type' => $scopeType,
                ':unit_id' => $unitId,
                ':valid_until' => $validUntil,
                ':granted_by' => $actorId,
                ':reason' => $reason,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'user_roles.assigned',
                subjectType: 'user_role_assignment',
                subjectId: $assignId,
                subjectVersion: 1,
                unitId: $unitId,
                afterState: ['assignment_id' => $assignId, 'role_key' => $roleKey, 'user_id' => $targetUserId],
                reason: $reason
            );

            return [
                'mode' => 'assigned_immediately',
                'assignment_id' => $assignId,
                'status' => 'active',
                'role_key' => $roleKey,
            ];
        }, $pdo);
    }

    /**
     * Independently approves or denies a pending dual-control `access_change_request` (`decided_by <> requested_by`) (#40, API-045).
     *
     * @return array<string, mixed>
     */
    public static function decideAccessChangeRequest(
        string $approverId,
        string $requestId,
        string $decision,
        string $decisionReason,
        ?PDO $pdo = null,
    ): array {
        if (!in_array($decision, ['approved', 'denied'], true)) {
            throw new RuntimeException('INVALID_DECISION');
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $approverId,
            permissionKey: 'user_roles.approve_request',
            resourceType: 'access_change_requests',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $approverId,
            $requestId,
            $decision,
            $decisionReason
        ): array {
            $stmt = $db->prepare(
                'SELECT id, unit_id, requested_by, target_user_id, role_id, scope_type, change_payload::text AS payload_json, status
                 FROM shortlink.access_change_requests
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $requestId]);
            /** @var array<string, mixed>|false $req */
            $req = $stmt->fetch();
            if (!is_array($req)) {
                throw new RuntimeException('ACCESS_CHANGE_REQUEST_NOT_FOUND');
            }
            if ($req['status'] !== 'pending') {
                throw new RuntimeException('ACCESS_CHANGE_REQUEST_ALREADY_DECIDED');
            }
            if ($req['requested_by'] === $approverId) {
                throw new RuntimeException('SOD_SELF_APPROVAL_FORBIDDEN: Approver cannot approve their own access change request.');
            }
            if ($req['target_user_id'] === $approverId) {
                throw new RuntimeException('SOD_TARGET_APPROVAL_FORBIDDEN: Target user cannot approve their own role grant.');
            }

            $upd = $db->prepare(
                'UPDATE shortlink.access_change_requests
                 SET status = :status, decided_by = :decided_by, decision_reason = :reason, decided_at = now()
                 WHERE id = :id'
            );
            $upd->execute([
                ':status' => $decision,
                ':decided_by' => $approverId,
                ':reason' => $decisionReason,
                ':id' => $requestId,
            ]);

            $assignmentId = null;
            if ($decision === 'approved') {
                /** @var array<string, mixed> $payload */
                $payload = json_decode((string) $req['payload_json'], true, 512, JSON_THROW_ON_ERROR);
                $assignmentId = UuidV7::generate();
                $ins = $db->prepare(
                    'INSERT INTO shortlink.user_role_assignments (
                        id, user_id, role_id, scope_type, unit_id, valid_until, granted_by, approved_by, reason
                    ) VALUES (
                        :id, :user_id, :role_id, :scope_type, :unit_id, :valid_until, :granted_by, :approved_by, :reason
                    )'
                );
                $ins->execute([
                    ':id' => $assignmentId,
                    ':user_id' => $req['target_user_id'],
                    ':role_id' => $req['role_id'],
                    ':scope_type' => $req['scope_type'],
                    ':unit_id' => $req['unit_id'],
                    ':valid_until' => $payload['valid_until'] ?? null,
                    ':granted_by' => $req['requested_by'],
                    ':approved_by' => $approverId,
                    ':reason' => $decisionReason,
                ]);
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $approverId,
                action: 'user_roles.request_' . $decision,
                subjectType: 'access_change_request',
                subjectId: $requestId,
                subjectVersion: 2,
                unitId: isset($req['unit_id']) ? (string) $req['unit_id'] : null,
                beforeState: ['status' => 'pending'],
                afterState: ['status' => $decision, 'assignment_id' => $assignmentId],
                reason: $decisionReason
            );

            return [
                'request_id' => $requestId,
                'status' => $decision,
                'assignment_id' => $assignmentId,
            ];
        }, $pdo);
    }

    /**
     * Revokes a user role assignment while protecting the last active `platform_owner` (#40, API-044).
     */
    public static function revokeRoleAssignment(
        string $actorId,
        string $assignmentId,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'user_roles.revoke',
            resourceType: 'user_role_assignments',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($actorId, $assignmentId, $reason): array {
            $stmt = $db->prepare(
                'SELECT ura.id, ura.user_id, ura.unit_id, ura.revoked_at, r.key AS role_key
                 FROM shortlink.user_role_assignments ura
                 JOIN shortlink.roles r ON r.id = ura.role_id
                 WHERE ura.id = :id
                 FOR UPDATE OF ura'
            );
            $stmt->execute([':id' => $assignmentId]);
            /** @var array<string, mixed>|false $row */
            $row = $stmt->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('ASSIGNMENT_NOT_FOUND');
            }
            if ($row['revoked_at'] !== null) {
                throw new RuntimeException('ASSIGNMENT_ALREADY_REVOKED');
            }
            if ($row['role_key'] === 'platform_owner') {
                IdentityService::assertNotLastActivePlatformOwner($db, (string) $row['user_id']);
            }

            $upd = $db->prepare(
                'UPDATE shortlink.user_role_assignments
                 SET revoked_at = now(), revoked_by = :actor, revoke_reason = :reason
                 WHERE id = :id'
            );
            $upd->execute([
                ':actor' => $actorId,
                ':reason' => $reason,
                ':id' => $assignmentId,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'user_roles.revoked',
                subjectType: 'user_role_assignment',
                subjectId: $assignmentId,
                subjectVersion: 2,
                unitId: isset($row['unit_id']) ? (string) $row['unit_id'] : null,
                beforeState: ['revoked_at' => null],
                afterState: ['revoked_by' => $actorId],
                reason: $reason
            );

            return [
                'assignment_id' => $assignmentId,
                'status' => 'revoked',
            ];
        }, $pdo);
    }

    /**
     * Creates a new constrained JSON ABAC policy draft version (`status = 'draft'`) (#41, API-046).
     *
     * @param array<string, mixed> $rule
     * @return array<string, mixed>
     */
    public static function createAbacPolicyDraft(
        string $actorId,
        string $policyKey,
        string $resource,
        string $action,
        array $rule,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $validation = RuleSchemaValidator::validate($rule);
        if (!$validation['valid']) {
            throw new RuntimeException('ABAC_SCHEMA_INVALID:' . implode('; ', $validation['errors']));
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'policies.create',
            resourceType: 'abac_policies',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $policyKey,
            $resource,
            $action,
            $rule,
            $reason
        ): array {
            $defStmt = $db->prepare('SELECT id FROM shortlink.abac_policy_definitions WHERE key = :key FOR UPDATE');
            $defStmt->execute([':key' => $policyKey]);
            $defId = $defStmt->fetchColumn();

            if (!is_string($defId) || $defId === '') {
                $defId = UuidV7::generate();
                $insDef = $db->prepare(
                    "INSERT INTO shortlink.abac_policy_definitions (id, key, resource, action, status)
                     VALUES (:id, :key, :resource, :action, 'active')"
                );
                $insDef->execute([
                    ':id' => $defId,
                    ':key' => $policyKey,
                    ':resource' => $resource,
                    ':action' => $action,
                ]);
            }

            $verStmt = $db->prepare('SELECT coalesce(max(version), 0) + 1 FROM shortlink.abac_policy_versions WHERE definition_id = :def_id');
            $verStmt->execute([':def_id' => $defId]);
            $nextVer = (int) $verStmt->fetchColumn();

            $verId = UuidV7::generate();
            $ruleJson = json_encode($rule, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $checksum = hash('sha256', $ruleJson);

            $insVer = $db->prepare(
                "INSERT INTO shortlink.abac_policy_versions (
                    id, definition_id, version, rule, checksum, status, authored_by
                ) VALUES (
                    :id, :def_id, :ver, :rule::jsonb, :checksum, 'draft', :authored_by
                )"
            );
            $insVer->execute([
                ':id' => $verId,
                ':def_id' => $defId,
                ':ver' => $nextVer,
                ':rule' => $ruleJson,
                ':checksum' => $checksum,
                ':authored_by' => $actorId,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'policies.draft_created',
                subjectType: 'abac_policy_version',
                subjectId: $verId,
                subjectVersion: $nextVer,
                afterState: ['policy_key' => $policyKey, 'version' => $nextVer, 'checksum' => $checksum],
                reason: $reason
            );

            return [
                'definition_id' => $defId,
                'version_id' => $verId,
                'policy_key' => $policyKey,
                'version' => $nextVer,
                'status' => 'draft',
                'checksum' => $checksum,
            ];
        }, $pdo);
    }

    /**
     * Simulates and submits an ABAC policy draft version for independent approval (#41, API-047).
     *
     * @param list<array{bag: array{actor: array<string, mixed>, resource: array<string, mixed>, context: array<string, mixed>}, expected_matched: bool}> $testVectors
     * @return array<string, mixed>
     */
    public static function simulateAndSubmitAbacVersion(
        string $actorId,
        string $versionId,
        array $testVectors,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        if ($testVectors === []) {
            throw new RuntimeException('ABAC_SIMULATION_VECTORS_EMPTY');
        }

        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'policies.submit',
            resourceType: 'abac_policies',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $versionId,
            $testVectors,
            $reason
        ): array {
            $stmt = $db->prepare(
                'SELECT id, definition_id, version, rule::text AS rule_json, status, authored_by
                 FROM shortlink.abac_policy_versions
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $versionId]);
            /** @var array<string, mixed>|false $ver */
            $ver = $stmt->fetch();
            if (!is_array($ver)) {
                throw new RuntimeException('ABAC_VERSION_NOT_FOUND');
            }
            if (!in_array($ver['status'], ['draft', 'simulated'], true)) {
                throw new RuntimeException('ABAC_VERSION_INVALID_STATE_FOR_SUBMIT');
            }

            /** @var array<string, mixed> $rule */
            $rule = json_decode((string) $ver['rule_json'], true, 512, JSON_THROW_ON_ERROR);
            $results = [];
            $allPassed = true;

            foreach ($testVectors as $idx => $vec) {
                $eval = PolicyEvaluator::evaluateRule($rule, $vec['bag']);
                $passed = $eval['matched'] === (bool) $vec['expected_matched'];
                if (!$passed) {
                    $allPassed = false;
                }
                $results[] = [
                    'vector_index' => $idx,
                    'matched' => $eval['matched'],
                    'expected_matched' => (bool) $vec['expected_matched'],
                    'passed' => $passed,
                ];
            }

            if (!$allPassed) {
                throw new RuntimeException('ABAC_SIMULATION_FAILED: One or more test vectors failed.');
            }

            $reportJson = json_encode([
                'passed' => true,
                'vectors_tested' => count($testVectors),
                'results' => $results,
            ], JSON_THROW_ON_ERROR);

            $upd = $db->prepare(
                "UPDATE shortlink.abac_policy_versions
                 SET status = 'submitted', simulation_report = :report::jsonb
                 WHERE id = :id"
            );
            $upd->execute([':report' => $reportJson, ':id' => $versionId]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'policies.simulated_and_submitted',
                subjectType: 'abac_policy_version',
                subjectId: $versionId,
                subjectVersion: (int) $ver['version'],
                beforeState: ['status' => $ver['status']],
                afterState: ['status' => 'submitted', 'vectors_tested' => count($testVectors)],
                reason: $reason
            );

            return [
                'version_id' => $versionId,
                'status' => 'submitted',
                'simulation_passed' => true,
                'vectors_tested' => count($testVectors),
            ];
        }, $pdo);
    }

    /**
     * Independently approves and activates a submitted ABAC policy version (`approved_by <> authored_by`) (#41, API-048).
     *
     * @return array<string, mixed>
     */
    public static function publishAbacVersion(
        string $approverId,
        string $versionId,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $approverId,
            permissionKey: 'policies.publish',
            resourceType: 'abac_policies',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($approverId, $versionId, $reason): array {
            $stmt = $db->prepare(
                'SELECT id, definition_id, version, status, authored_by, simulation_report
                 FROM shortlink.abac_policy_versions
                 WHERE id = :id
                 FOR UPDATE'
            );
            $stmt->execute([':id' => $versionId]);
            /** @var array<string, mixed>|false $ver */
            $ver = $stmt->fetch();
            if (!is_array($ver)) {
                throw new RuntimeException('ABAC_VERSION_NOT_FOUND');
            }
            if ($ver['status'] !== 'submitted') {
                throw new RuntimeException('ABAC_PUBLISH_REQUIRES_SUBMITTED_STATUS: Cannot publish unsimulated/unsubmitted draft.');
            }
            if ($ver['authored_by'] === $approverId) {
                throw new RuntimeException('ABAC_SOD_SELF_APPROVAL_FORBIDDEN: Policy author cannot approve their own policy version.');
            }

            $defId = (string) $ver['definition_id'];

            // Supersede current active version for this definition
            $sup = $db->prepare(
                "UPDATE shortlink.abac_policy_versions
                 SET status = 'superseded'
                 WHERE definition_id = :def_id AND status = 'active'"
            );
            $sup->execute([':def_id' => $defId]);

            // Activate new version
            $act = $db->prepare(
                "UPDATE shortlink.abac_policy_versions
                 SET status = 'active', approved_by = :approver, activated_at = now()
                 WHERE id = :id"
            );
            $act->execute([':approver' => $approverId, ':id' => $versionId]);

            $updDef = $db->prepare(
                'UPDATE shortlink.abac_policy_definitions
                 SET current_version_id = :ver_id, version = version + 1, updated_at = now()
                 WHERE id = :def_id'
            );
            $updDef->execute([':ver_id' => $versionId, ':def_id' => $defId]);

            $insApp = $db->prepare(
                "INSERT INTO shortlink.abac_policy_approvals (id, version_id, actor_id, decision, reason)
                 VALUES (:id, :ver_id, :actor, 'approve', :reason)"
            );
            $insApp->execute([
                ':id' => UuidV7::generate(),
                ':ver_id' => $versionId,
                ':actor' => $approverId,
                ':reason' => $reason,
            ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $approverId,
                action: 'policies.published',
                subjectType: 'abac_policy_version',
                subjectId: $versionId,
                subjectVersion: (int) $ver['version'],
                policyVersionId: $versionId,
                beforeState: ['status' => 'submitted'],
                afterState: ['status' => 'active', 'approved_by' => $approverId],
                reason: $reason
            );

            return [
                'definition_id' => $defId,
                'version_id' => $versionId,
                'version' => (int) $ver['version'],
                'status' => 'active',
                'approved_by' => $approverId,
            ];
        }, $pdo);
    }

    /**
     * Rolls back an ABAC policy definition to a previously approved/superseded version (#41, API-049).
     *
     * @return array<string, mixed>
     */
    public static function rollbackAbacPolicy(
        string $actorId,
        string $policyKey,
        int $targetVersion,
        string $reason,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'policies.rollback',
            resourceType: 'abac_policies',
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($actorId, $policyKey, $targetVersion, $reason): array {
            $defStmt = $db->prepare('SELECT id, current_version_id FROM shortlink.abac_policy_definitions WHERE key = :key FOR UPDATE');
            $defStmt->execute([':key' => $policyKey]);
            /** @var array<string, mixed>|false $def */
            $def = $defStmt->fetch();
            if (!is_array($def)) {
                throw new RuntimeException('ABAC_DEFINITION_NOT_FOUND');
            }

            $defId = (string) $def['id'];
            $verStmt = $db->prepare(
                "SELECT id, version, status, approved_by
                 FROM shortlink.abac_policy_versions
                 WHERE definition_id = :def_id AND version = :ver
                 FOR UPDATE"
            );
            $verStmt->execute([':def_id' => $defId, ':ver' => $targetVersion]);
            /** @var array<string, mixed>|false $target */
            $target = $verStmt->fetch();
            if (!is_array($target) || empty($target['approved_by'])) {
                throw new RuntimeException('ABAC_ROLLBACK_TARGET_NOT_PREVIOUSLY_APPROVED');
            }

            $targetVerId = (string) $target['id'];

            $db->prepare("UPDATE shortlink.abac_policy_versions SET status = 'superseded' WHERE definition_id = :d AND status = 'active'")
                ->execute([':d' => $defId]);

            $db->prepare("UPDATE shortlink.abac_policy_versions SET status = 'active', activated_at = now() WHERE id = :id")
                ->execute([':id' => $targetVerId]);

            $db->prepare('UPDATE shortlink.abac_policy_definitions SET current_version_id = :vid, version = version + 1, updated_at = now() WHERE id = :did')
                ->execute([':vid' => $targetVerId, ':did' => $defId]);

            $db->prepare("INSERT INTO shortlink.abac_policy_approvals (id, version_id, actor_id, decision, reason) VALUES (:id, :vid, :actor, 'rollback', :reason)")
                ->execute([
                    ':id' => UuidV7::generate(),
                    ':vid' => $targetVerId,
                    ':actor' => $actorId,
                    ':reason' => $reason,
                ]);

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'policies.rolled_back',
                subjectType: 'abac_policy_version',
                subjectId: $targetVerId,
                subjectVersion: $targetVersion,
                policyVersionId: $targetVerId,
                beforeState: ['current_version_id' => $def['current_version_id']],
                afterState: ['current_version_id' => $targetVerId, 'version' => $targetVersion],
                reason: $reason
            );

            return [
                'policy_key' => $policyKey,
                'active_version_id' => $targetVerId,
                'active_version' => $targetVersion,
                'status' => 'active',
            ];
        }, $pdo);
    }
}
