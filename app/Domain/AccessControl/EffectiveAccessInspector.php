<?php

declare(strict_types=1);

namespace App\Domain\AccessControl;

use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use PDO;
use RuntimeException;

/**
 * Redacted Effective Access Inspector (SPEC-06, API-050, UI-016, #42, TST-019).
 *
 * Inspects why a target user is permitted or denied a specific permission on a resource
 * without ever exposing password hashes, MFA secrets, or session tokens.
 */
final class EffectiveAccessInspector
{
    /**
     * @param array<string, mixed> $resourceAttributes
     * @return array{
     *   inspected_by: string,
     *   subject_user_id: string,
     *   permission_key: string,
     *   resource_type: string,
     *   verdict: 'allow'|'deny',
     *   reason_code: string,
     *   identity_state: array{status: string, mfa_verified: bool},
     *   matched_roles: list<string>,
     *   expanded_unit_ids: list<string>,
     *   is_global_scope: bool,
     *   abac_trace: list<array<string, mixed>>,
     *   rls_posture_summary: array{enforced: bool, scope: string, unit_count: int},
     *   redacted_fields: list<string>
     * }
     */
    public static function inspect(
        string $inspectorActorId,
        string $subjectUserId,
        string $permissionKey,
        string $resourceType,
        array $resourceAttributes = [],
        ?bool $simulatedMfaVerified = null,
        ?PDO $pdo = null,
    ): array {
        // First authorize that the inspector holds `access.inspect` (PERM-052)
        $inspectorAuth = AuthorizationPipeline::evaluate(
            actorId: $inspectorActorId,
            permissionKey: 'access.inspect',
            resourceType: 'access_inspector',
            resourceAttributes: $resourceAttributes,
            pdo: $pdo,
            recordAudit: true
        );

        if (!$inspectorAuth['permitted']) {
            throw new RuntimeException(sprintf(
                'ACCESS_INSPECT_FORBIDDEN: %s',
                (string) $inspectorAuth['reason_code']
            ));
        }

        // Non-global inspectors can only inspect themselves or users within their expanded unit scope
        if (!$inspectorAuth['is_global_scope'] && $inspectorActorId !== $subjectUserId) {
            $targetUnit = $resourceAttributes['unit_id'] ?? null;
            if ($targetUnit !== null && !in_array((string) $targetUnit, $inspectorAuth['expanded_unit_ids'], true)) {
                throw new RuntimeException('ACCESS_INSPECT_OUTSIDE_UNIT_SCOPE: Cannot inspect user/resource outside unit scope.');
            }
        }

        $eval = AuthorizationPipeline::evaluate(
            actorId: $subjectUserId,
            permissionKey: $permissionKey,
            resourceType: $resourceType,
            resourceAttributes: $resourceAttributes,
            sessionMfaVerified: $simulatedMfaVerified,
            pdo: $pdo,
            recordAudit: true
        );

        return [
            'inspected_by' => $inspectorActorId,
            'subject_user_id' => $subjectUserId,
            'permission_key' => $permissionKey,
            'resource_type' => $resourceType,
            'verdict' => $eval['verdict'],
            'reason_code' => $eval['reason_code'],
            'identity_state' => [
                'status' => (string) ($eval['actor']['status'] ?? 'unknown'),
                'mfa_verified' => (bool) ($eval['actor']['mfa_verified'] ?? false),
            ],
            'matched_roles' => $eval['matched_roles'],
            'expanded_unit_ids' => $eval['expanded_unit_ids'],
            'is_global_scope' => $eval['is_global_scope'],
            'abac_trace' => $eval['abac_trace'],
            'rls_posture_summary' => [
                'enforced' => true,
                'scope' => $eval['is_global_scope'] ? 'global' : 'unit',
                'unit_count' => count($eval['expanded_unit_ids']),
            ],
            'redacted_fields' => [
                'password_hash',
                'mfa_secret_encrypted',
                'session_token',
                'api_credential_secret_hash',
            ],
        ];
    }
}

