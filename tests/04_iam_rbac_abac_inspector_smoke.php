<?php

declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap/autoload.php';

use App\Database\Migrator;
use App\Domain\AccessControl\Abac\RuleSchemaValidator;
use App\Domain\AccessControl\EffectiveAccessInspector;
use App\Domain\AccessControl\RbacAbacService;
use App\Domain\Identity\IdentityService;
use App\Support\Totp;
use Tests\TestAssert;

echo "==> [04] Running IAM Lifecycle, RBAC Ceiling, Dual-Control, ABAC Lifecycle & Effective Access Inspector Tests (TST-015, TST-016, TST-019, #11, #19, #39, #40, #41, #42)...\n";

Migrator::resetAllData();

// 1. User invitation -> MFA TOTP enrollment -> login session -> suspension revokes session (#11, #39)
$invited = IdentityService::inviteUser(
    actorId: Migrator::USER_PLATFORM_OWNER,
    name: 'Branch A staff',
    email: 'staff.branch-a@example.org',
    unitId: Migrator::UNIT_BRANCH_A,
    reason: 'Invite unit editor for Branch A'
);
$staffUserId = (string) $invited['id'];
TestAssert::same('invited', $invited['status'], 'Invited user starts in invited status');

$mfaSecret = Totp::generateSecret();
$validOtp = Totp::codeAt($mfaSecret, time());
$activated = IdentityService::acceptInvitation(
    userId: $staffUserId,
    plainPassword: 'StafArselPassword#2026!',
    mfaSecret: $mfaSecret,
    totpCode: $validOtp
);
TestAssert::same('active', $activated['status'], 'Accepted invitation transitions user to active');

// Authenticate with password + TOTP MFA
$session = IdentityService::authenticate(
    email: 'staff.branch-a@example.org',
    plainPassword: 'StafArselPassword#2026!',
    totpCode: Totp::codeAt($mfaSecret, time())
);
TestAssert::true($session['mfa_verified'], 'Session must record mfa_verified = true');
$checkActive = IdentityService::validateSession($session['session_id']);
TestAssert::true($checkActive['valid'], 'Newly created session must be valid');

// Assign unit_admin role to another user so we can test delegation ceiling
$invitedAdmin = IdentityService::inviteUser(
    actorId: Migrator::USER_PLATFORM_OWNER,
    name: 'Branch A head',
    email: 'head.branch-a@example.org',
    unitId: Migrator::UNIT_BRANCH_A,
    reason: 'Invite unit admin'
);
$unitAdminId = (string) $invitedAdmin['id'];
$adminSecret = Totp::generateSecret();
IdentityService::acceptInvitation($unitAdminId, 'KapusArselPass#2026!', $adminSecret, Totp::codeAt($adminSecret, time()));

$directAssign = RbacAbacService::assignRoleOrRequest(
    actorId: Migrator::USER_PLATFORM_OWNER,
    targetUserId: $unitAdminId,
    roleKey: 'unit_admin',
    scopeType: 'unit',
    unitId: Migrator::UNIT_BRANCH_A,
    reason: 'Assign unit_admin to Branch A head'
);
TestAssert::same('assigned_immediately', $directAssign['mode'], 'Normal unit role assigned immediately');

// Unit admin can grant `editor` within PKM_ARSEL (within grantable ceiling),
// but CANNOT grant `org_admin` or grant into UNIT_DIVISION_A!
$editorAssign = RbacAbacService::assignRoleOrRequest(
    actorId: $unitAdminId,
    targetUserId: $staffUserId,
    roleKey: 'editor',
    scopeType: 'unit',
    unitId: Migrator::UNIT_BRANCH_A,
    reason: 'Unit admin assigns editor in same unit'
);
TestAssert::same('assigned_immediately', $editorAssign['mode'], 'Unit admin can grant editor within own unit');

TestAssert::throws(
    static fn () => RbacAbacService::assignRoleOrRequest(
        actorId: $unitAdminId,
        targetUserId: $staffUserId,
        roleKey: 'editor',
        scopeType: 'unit',
        unitId: Migrator::UNIT_DIVISION_A,
        reason: 'Attempt cross-unit grant'
    ),
    'DELEGATION_SCOPE_EXCEEDED',
    'Unit admin must be blocked from granting role in another unit'
);

TestAssert::throws(
    static fn () => RbacAbacService::assignRoleOrRequest(
        actorId: $unitAdminId,
        targetUserId: $staffUserId,
        roleKey: 'org_admin',
        scopeType: 'unit',
        unitId: Migrator::UNIT_BRANCH_A,
        reason: 'Attempt privilege escalation above grantable ceiling'
    ),
    'DELEGATION_CEILING_EXCEEDED',
    'Unit admin must be blocked from granting role containing permissions above their grantable ceiling'
);

// 2. Dual-control access_change_request for sensitive role (`approver`) (#40, TST-015)
$dualReq = RbacAbacService::assignRoleOrRequest(
    actorId: Migrator::USER_PLATFORM_OWNER,
    targetUserId: $unitAdminId,
    roleKey: 'approver',
    scopeType: 'unit',
    unitId: Migrator::UNIT_BRANCH_A,
    reason: 'Request sensitive approver role for Kapus'
);
TestAssert::same('pending_dual_control', $dualReq['mode'], 'Sensitive role grant creates pending dual-control request');

// Requester cannot self-approve their own access_change_request!
TestAssert::throws(
    static fn () => RbacAbacService::decideAccessChangeRequest(
        approverId: Migrator::USER_PLATFORM_OWNER,
        requestId: (string) $dualReq['request_id'],
        decision: 'approved',
        decisionReason: 'Attempt self-approve access request'
    ),
    'SOD_SELF_APPROVAL_FORBIDDEN',
    'Requester must be blocked from approving own access_change_request'
);

// Independent security approver approves -> creates active assignment
$decided = RbacAbacService::decideAccessChangeRequest(
    approverId: Migrator::USER_SECURITY_APPROVER,
    requestId: (string) $dualReq['request_id'],
    decision: 'approved',
    decisionReason: 'Independently approved by security approver'
);
TestAssert::same('approved', $decided['status'], 'Independent approval succeeds');

// 3. Custom role creation & protected role immutability (#40)
$customRole = RbacAbacService::createCustomRole(
    actorId: Migrator::USER_PLATFORM_OWNER,
    key: 'campaign_coordinator',
    label: 'Koordinator Kampanye Kesehatan',
    sensitivity: 'normal',
    ownerUnitId: Migrator::UNIT_DIVISION_A
);
$replaced = RbacAbacService::replaceRolePermissions(
    actorId: Migrator::USER_PLATFORM_OWNER,
    roleId: (string) $customRole['id'],
    permissions: [
        ['permission_key' => 'links.read_public', 'grantable' => false],
        ['permission_key' => 'links.list_internal', 'grantable' => false],
        ['permission_key' => 'campaigns.read', 'grantable' => false],
    ],
    reason: 'Set custom role permissions',
    expectedVersion: 1
);
TestAssert::same(3, $replaced['permissions_count'], 'Custom role has 3 permissions');

// Attempting to modify built-in protected role permission matrix must fail
$ownerRoleId = \App\Support\UuidV7::deterministic('role:platform_owner');
TestAssert::throws(
    static fn () => RbacAbacService::replaceRolePermissions(
        actorId: Migrator::USER_PLATFORM_OWNER,
        roleId: $ownerRoleId,
        permissions: [['permission_key' => 'links.read_public']],
        reason: 'Attempt mutate protected role'
    ),
    'PROTECTED_ROLE_IMMUTABLE',
    'Built-in protected roles must be immutable'
);

// 4. Last active platform_owner lockout protection (TST-015)
// Revoke USER_SECURITY_APPROVER's platform_owner assignment first (leaving USER_PLATFORM_OWNER as last active owner),
// then verify suspending/revoking USER_PLATFORM_OWNER is blocked with LAST_OWNER_PROTECTED!
$secOwnerAssignId = \App\Support\UuidV7::deterministic('assign:sec_approver');
RbacAbacService::revokeRoleAssignment(
    actorId: Migrator::USER_PLATFORM_OWNER,
    assignmentId: $secOwnerAssignId,
    reason: 'Test leaving single platform_owner'
);
$lastOwnerAssignId = \App\Support\UuidV7::deterministic('assign:owner');
TestAssert::throws(
    static fn () => RbacAbacService::revokeRoleAssignment(
        actorId: Migrator::USER_PLATFORM_OWNER,
        assignmentId: $lastOwnerAssignId,
        reason: 'Attempt revoke last platform_owner'
    ),
    'LAST_OWNER_PROTECTED',
    'Cannot revoke the last active platform_owner assignment'
);

// Restore USER_SECURITY_APPROVER platform_owner via Migrator::seedCatalog so both owners remain active
Migrator::seedCatalog();

// 5. Suspending a user immediately revokes their active sessions (#39)
$suspUser = IdentityService::changeUserStatus(
    actorId: Migrator::USER_PLATFORM_OWNER,
    targetUserId: $staffUserId,
    newStatus: 'suspended',
    reason: 'Temporary leave suspension'
);
TestAssert::same('suspended', $suspUser['status'], 'User status is suspended');
TestAssert::same(1, $suspUser['revoked_sessions'], 'Active session was immediately revoked');
$checkAfterSuspend = IdentityService::validateSession($session['session_id']);
TestAssert::same(false, $checkAfterSuspend['valid'], 'Revoked session is no longer valid');
TestAssert::same('SESSION_REVOKED', $checkAfterSuspend['reason_code'], 'Session reason_code is SESSION_REVOKED');

// Reinstate staff user
IdentityService::changeUserStatus(
    actorId: Migrator::USER_PLATFORM_OWNER,
    targetUserId: $staffUserId,
    newStatus: 'active',
    reason: 'Returned from leave'
);

// 6. Organizational Unit Creation, Cycle Detection & Subtree Reparenting (#39, DES-002)
$subUnit = IdentityService::createUnit(
    actorId: Migrator::USER_PLATFORM_OWNER,
    code: 'PUSTU_MENDAWAI',
    name: 'Sub-branch A1',
    parentId: Migrator::UNIT_BRANCH_A,
    reason: 'Create child sub-branch under Branch A'
);
$pustuId = (string) $subUnit['id'];

// Cycle detection: cannot move PKM_ARSEL under its own child PUSTU_MENDAWAI
TestAssert::throws(
    static fn () => IdentityService::moveUnit(
        actorId: Migrator::USER_PLATFORM_OWNER,
        unitId: Migrator::UNIT_BRANCH_A,
        newParentId: $pustuId,
        reason: 'Attempt cycle in unit tree'
    ),
    'CYCLE_DETECTED_IN_UNIT_TREE',
    'Moving unit under its own descendant must throw CYCLE_DETECTED_IN_UNIT_TREE'
);

// Valid move: move PUSTU_MENDAWAI under UNIT_DIVISION_A
$movedUnit = IdentityService::moveUnit(
    actorId: Migrator::USER_PLATFORM_OWNER,
    unitId: $pustuId,
    newParentId: Migrator::UNIT_DIVISION_A,
    reason: 'Reorganize sub-branch under Division A'
);
TestAssert::same(Migrator::UNIT_DIVISION_A, $movedUnit['parent_id'], 'Unit parent_id updated');

// 7. Constrained Declarative ABAC Policy Lifecycle: Schema Validation -> Draft -> Simulate -> Independent Publish -> Rollback (#41, TST-016)
$invalidScriptRule = [
    'schema_version' => 1,
    'effect' => 'deny',
    'reason_code' => 'ABAC_BAD_SCRIPT',
    'script' => 'eval("return true;")',
    'all' => [['field' => 'actor.status', 'op' => 'eq', 'value' => 'active']],
];
$valBad = RuleSchemaValidator::validate($invalidScriptRule);
TestAssert::same(false, $valBad['valid'], 'Rule containing script key must be rejected');

$draftPol = RbacAbacService::createAbacPolicyDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    policyKey: 'POL-CUSTOM-VISIBILITY',
    resource: 'links',
    action: 'links.export',
    rule: [
        'schema_version' => 1,
        'effect' => 'deny',
        'reason_code' => 'ABAC_DENY_UNLISTED_EXPORT',
        'all' => [
            ['field' => 'resource.visibility', 'op' => 'eq', 'value' => 'unlisted'],
            ['field' => 'actor.is_global_scope', 'op' => 'eq', 'value' => false],
        ],
    ],
    reason: 'Create draft ABAC policy v1'
);

// Cannot publish before simulation & submission!
TestAssert::throws(
    static fn () => RbacAbacService::publishAbacVersion(
        approverId: Migrator::USER_SECURITY_APPROVER,
        versionId: (string) $draftPol['version_id'],
        reason: 'Attempt publish unsimulated draft'
    ),
    'ABAC_PUBLISH_REQUIRES_SUBMITTED_STATUS',
    'Cannot publish unsimulated draft ABAC version'
);

// Simulate & submit
$simSub = RbacAbacService::simulateAndSubmitAbacVersion(
    actorId: Migrator::USER_PLATFORM_OWNER,
    versionId: (string) $draftPol['version_id'],
    testVectors: [
        [
            'bag' => [
                'actor' => ['is_global_scope' => false],
                'resource' => ['visibility' => 'unlisted'],
                'context' => [],
            ],
            'expected_matched' => true,
        ],
        [
            'bag' => [
                'actor' => ['is_global_scope' => true],
                'resource' => ['visibility' => 'unlisted'],
                'context' => [],
            ],
            'expected_matched' => false,
        ],
    ],
    reason: 'Simulate & submit v1'
);
TestAssert::same('submitted', $simSub['status'], 'Simulation passed and version submitted');

// Author cannot self-approve their own submitted ABAC policy version!
TestAssert::throws(
    static fn () => RbacAbacService::publishAbacVersion(
        approverId: Migrator::USER_PLATFORM_OWNER,
        versionId: (string) $draftPol['version_id'],
        reason: 'Attempt self-publish ABAC policy'
    ),
    'ABAC_SOD_SELF_APPROVAL_FORBIDDEN',
    'ABAC policy author must be blocked from approving own policy version'
);

// Independent approver publishes v1
$pubV1 = RbacAbacService::publishAbacVersion(
    approverId: Migrator::USER_SECURITY_APPROVER,
    versionId: (string) $draftPol['version_id'],
    reason: 'Independently approved & published v1'
);
TestAssert::same('active', $pubV1['status'], 'ABAC policy v1 is now active');

// Create, simulate, and publish v2, then rollback to v1
$draftPolV2 = RbacAbacService::createAbacPolicyDraft(
    actorId: Migrator::USER_PLATFORM_OWNER,
    policyKey: 'POL-CUSTOM-VISIBILITY',
    resource: 'links',
    action: 'links.export',
    rule: [
        'schema_version' => 1,
        'effect' => 'deny',
        'reason_code' => 'ABAC_DENY_UNLISTED_EXPORT_V2',
        'all' => [
            ['field' => 'resource.visibility', 'op' => 'eq', 'value' => 'unlisted'],
        ],
    ],
    reason: 'Create draft v2'
);
RbacAbacService::simulateAndSubmitAbacVersion(
    actorId: Migrator::USER_PLATFORM_OWNER,
    versionId: (string) $draftPolV2['version_id'],
    testVectors: [[
        'bag' => ['actor' => [], 'resource' => ['visibility' => 'unlisted'], 'context' => []],
        'expected_matched' => true,
    ]],
    reason: 'Submit v2'
);
RbacAbacService::publishAbacVersion(
    approverId: Migrator::USER_SECURITY_APPROVER,
    versionId: (string) $draftPolV2['version_id'],
    reason: 'Publish v2'
);

$rolledBackPol = RbacAbacService::rollbackAbacPolicy(
    actorId: Migrator::USER_SECURITY_APPROVER,
    policyKey: 'POL-CUSTOM-VISIBILITY',
    targetVersion: 1,
    reason: 'Rollback to v1'
);
TestAssert::same(1, $rolledBackPol['active_version'], 'ABAC policy rolled back to version 1');

// 8. Effective Access Inspector with Redaction Verification (#42, TST-019)
$inspectedAllow = EffectiveAccessInspector::inspect(
    inspectorActorId: Migrator::USER_PLATFORM_OWNER,
    subjectUserId: $staffUserId,
    permissionKey: 'links.create_draft',
    resourceType: 'links',
    resourceAttributes: ['unit_id' => Migrator::UNIT_BRANCH_A]
);
TestAssert::same('allow', $inspectedAllow['verdict'], 'Editor in PKM_ARSEL is allowed links.create_draft in PKM_ARSEL');
TestAssert::same('PERMITTED_RBAC_AND_ABAC', $inspectedAllow['reason_code'], 'Permit reason_code');

$inspectedCrossUnitDeny = EffectiveAccessInspector::inspect(
    inspectorActorId: Migrator::USER_PLATFORM_OWNER,
    subjectUserId: $staffUserId,
    permissionKey: 'links.create_draft',
    resourceType: 'links',
    resourceAttributes: ['unit_id' => Migrator::UNIT_DIVISION_A]
);
TestAssert::same('deny', $inspectedCrossUnitDeny['verdict'], 'Editor in PKM_ARSEL is denied links.create_draft in BIDANG_P2P');
TestAssert::same('ABAC_DENY_OUTSIDE_UNIT_SCOPE', $inspectedCrossUnitDeny['reason_code'], 'Denied by POL-UNIT-SCOPE');

$inspectorJson = json_encode($inspectedAllow, JSON_THROW_ON_ERROR);
TestAssert::same(false, str_contains($inspectorJson, $mfaSecret), 'EffectiveAccessInspector must never leak mfa_secret');

echo "    [PASS] 04_iam_rbac_abac_inspector_smoke.php (" . TestAssert::$assertions . " assertions)\n";

