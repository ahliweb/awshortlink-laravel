<?php

declare(strict_types=1);

namespace App\Domain\Audit;

use App\Support\UuidV7;
use PDO;

/**
 * Transactional Hash-Chained Audit Writer (SPEC-05 TBL-019/TBL-020, #18).
 *
 * Every state-changing mutation appends an immutable row to `shortlink.link_audit_events`
 * within the same database transaction. If the audit insert fails, the mutation rolls back.
 */
final class AuditWriter
{
    public const GENESIS_CONSTANT = 'AWSHORTLINK-GENESIS-V1';

    /**
     * @param array<string, mixed>|null $beforeState
     * @param array<string, mixed>|null $afterState
     * @return array{id: int, prev_hash: string, row_hash: string, occurred_at: string}
     */
    public static function recordMutation(
        PDO $db,
        string $actorId,
        string $action,
        string $subjectType,
        ?string $subjectId,
        ?int $subjectVersion = 1,
        ?string $unitId = null,
        ?string $linkId = null,
        ?array $beforeState = null,
        ?array $afterState = null,
        ?string $reason = null,
        ?string $requestId = null,
        ?string $policyVersionId = null,
        ?string $occurredAt = null,
    ): array {
        $reqId = $requestId ?? UuidV7::generate();
        $ts = $occurredAt ?? gmdate('Y-m-d\TH:i:s.u\Z');
        $beforeHash = $beforeState !== null ? self::canonicalStateHash($beforeState) : null;
        $afterHash = $afterState !== null ? self::canonicalStateHash($afterState) : null;

        // Serialize chain tail inside the active transaction via narrow SECURITY DEFINER helper
        $tailStmt = $db->query('SELECT shortlink.audit_chain_tail()');
        $prevHash = (string) $tailStmt->fetchColumn();

        $rowHash = self::computeRowHash(
            prevHash: $prevHash,
            unitId: $unitId,
            linkId: $linkId,
            actorId: $actorId,
            action: $action,
            subjectType: $subjectType,
            subjectId: $subjectId,
            subjectVersion: $subjectVersion,
            beforeHash: $beforeHash,
            afterHash: $afterHash,
            reason: $reason,
            requestId: $reqId,
            policyVersionId: $policyVersionId,
            occurredAt: $ts,
        );

        $insertStmt = $db->prepare(
            'INSERT INTO shortlink.link_audit_events (
                unit_id, link_id, actor_id, action, subject_type, subject_id, subject_version,
                before_hash, after_hash, reason, request_id, policy_version_id, occurred_at,
                prev_hash, row_hash
            ) VALUES (
                :unit_id, :link_id, :actor_id, :action, :subject_type, :subject_id, :subject_version,
                :before_hash, :after_hash, :reason, :request_id, :policy_version_id, :occurred_at,
                :prev_hash, :row_hash
            ) RETURNING id, occurred_at::text AS occurred_at_str'
        );
        $insertStmt->execute([
            ':unit_id' => $unitId,
            ':link_id' => $linkId,
            ':actor_id' => $actorId,
            ':action' => $action,
            ':subject_type' => $subjectType,
            ':subject_id' => $subjectId,
            ':subject_version' => $subjectVersion,
            ':before_hash' => $beforeHash,
            ':after_hash' => $afterHash,
            ':reason' => $reason,
            ':request_id' => $reqId,
            ':policy_version_id' => $policyVersionId,
            ':occurred_at' => $ts,
            ':prev_hash' => $prevHash,
            ':row_hash' => $rowHash,
        ]);
        /** @var array{id: int|string, occurred_at_str: string} $inserted */
        $inserted = $insertStmt->fetch();

        return [
            'id' => (int) $inserted['id'],
            'prev_hash' => $prevHash,
            'row_hash' => $rowHash,
            'occurred_at' => $ts,
        ];
    }

    public static function recordAccessDecision(
        PDO $db,
        string $actorId,
        ?string $unitId,
        string $permission,
        string $resourceType,
        string $verdict,
        string $reasonCode,
        ?string $policyVersionId = null,
    ): int {
        $stmt = $db->prepare(
            'INSERT INTO shortlink.access_decision_audit (
                actor_id, unit_id, permission, resource_type, verdict, reason_code, policy_version_id
            ) VALUES (
                :actor_id, :unit_id, :permission, :resource_type, :verdict, :reason_code, :policy_version_id
            ) RETURNING id'
        );
        $stmt->execute([
            ':actor_id' => $actorId,
            ':unit_id' => $unitId,
            ':permission' => $permission,
            ':resource_type' => $resourceType,
            ':verdict' => $verdict,
            ':reason_code' => $reasonCode,
            ':policy_version_id' => $policyVersionId,
        ]);

        return (int) $stmt->fetchColumn();
    }

    /**
     * @param array<string, mixed> $state
     */
    public static function canonicalStateHash(array $state): string
    {
        ksort($state);
        return hash('sha256', json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function computeRowHash(
        string $prevHash,
        ?string $unitId,
        ?string $linkId,
        ?string $actorId,
        string $action,
        string $subjectType,
        ?string $subjectId,
        ?int $subjectVersion,
        ?string $beforeHash,
        ?string $afterHash,
        ?string $reason,
        string $requestId,
        ?string $policyVersionId,
        string $occurredAt,
    ): string {
        $canonical = implode('|', [
            $prevHash,
            $unitId ?? '',
            $linkId ?? '',
            $actorId ?? '',
            $action,
            $subjectType,
            $subjectId ?? '',
            (string) ($subjectVersion ?? ''),
            $beforeHash ?? '',
            $afterHash ?? '',
            $reason ?? '',
            $requestId,
            $policyVersionId ?? '',
            self::normalizeTimestamp($occurredAt),
        ]);

        return hash('sha256', $canonical);
    }

    public static function normalizeTimestamp(string $ts): string
    {
        $dt = new \DateTimeImmutable($ts);
        return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');
    }
}
