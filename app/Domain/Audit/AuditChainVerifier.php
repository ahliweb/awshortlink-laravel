<?php

declare(strict_types=1);

namespace App\Domain\Audit;

use PDO;

/**
 * Cryptographic Audit Chain Verifier (API-032, PERM-024, TST-007, #18).
 */
final class AuditChainVerifier
{
    /**
     * @return array{
     *   valid: bool,
     *   checked_rows: int,
     *   first_broken_id: ?int,
     *   expected_hash: ?string,
     *   actual_hash: ?string,
     *   tail_hash: string
     * }
     */
    public static function verify(PDO $db, ?int $fromId = null, ?int $toId = null): array
    {
        $sql = 'SELECT id, unit_id, link_id, actor_id, action, subject_type, subject_id, subject_version,
                       before_hash, after_hash, reason, request_id, policy_version_id,
                       occurred_at::text AS occurred_at_str, prev_hash, row_hash
                FROM shortlink.link_audit_events
                WHERE 1=1';
        $params = [];
        if ($fromId !== null) {
            $sql .= ' AND id >= :from_id';
            $params[':from_id'] = $fromId;
        }
        if ($toId !== null) {
            $sql .= ' AND id <= :to_id';
            $params[':to_id'] = $toId;
        }
        $sql .= ' ORDER BY id ASC';

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        /** @var list<array<string, mixed>> $rows */
        $rows = $stmt->fetchAll();

        $expectedPrev = hash('sha256', AuditWriter::GENESIS_CONSTANT);
        if ($fromId !== null && $fromId > 1 && $rows !== []) {
            $prevStmt = $db->prepare('SELECT row_hash FROM shortlink.link_audit_events WHERE id < :from_id ORDER BY id DESC LIMIT 1');
            $prevStmt->execute([':from_id' => $fromId]);
            $priorHash = $prevStmt->fetchColumn();
            if (is_string($priorHash) && $priorHash !== '') {
                $expectedPrev = $priorHash;
            }
        }

        $checked = 0;
        $tailHash = $expectedPrev;

        foreach ($rows as $row) {
            $checked++;
            $rowId = (int) $row['id'];
            $actualPrev = (string) $row['prev_hash'];
            if (!hash_equals($expectedPrev, $actualPrev)) {
                return [
                    'valid' => false,
                    'checked_rows' => $checked,
                    'first_broken_id' => $rowId,
                    'expected_hash' => $expectedPrev,
                    'actual_hash' => $actualPrev,
                    'tail_hash' => $tailHash,
                ];
            }

            $effectiveLinkId = isset($row['link_id']) && $row['link_id'] !== ''
                ? (string) $row['link_id']
                : ($row['subject_type'] === 'link' ? (string) ($row['subject_id'] ?? '') : null);

            $recomputed = AuditWriter::computeRowHash(
                prevHash: $actualPrev,
                unitId: isset($row['unit_id']) ? (string) $row['unit_id'] : null,
                linkId: $effectiveLinkId,
                actorId: isset($row['actor_id']) ? (string) $row['actor_id'] : null,
                action: (string) $row['action'],
                subjectType: (string) $row['subject_type'],
                subjectId: isset($row['subject_id']) ? (string) $row['subject_id'] : null,
                subjectVersion: isset($row['subject_version']) ? (int) $row['subject_version'] : null,
                beforeHash: isset($row['before_hash']) ? (string) $row['before_hash'] : null,
                afterHash: isset($row['after_hash']) ? (string) $row['after_hash'] : null,
                reason: isset($row['reason']) ? (string) $row['reason'] : null,
                requestId: (string) $row['request_id'],
                policyVersionId: isset($row['policy_version_id']) ? (string) $row['policy_version_id'] : null,
                occurredAt: (string) $row['occurred_at_str'],
            );

            $actualRowHash = (string) $row['row_hash'];
            if (!hash_equals($recomputed, $actualRowHash)) {
                return [
                    'valid' => false,
                    'checked_rows' => $checked,
                    'first_broken_id' => $rowId,
                    'expected_hash' => $recomputed,
                    'actual_hash' => $actualRowHash,
                    'tail_hash' => $tailHash,
                ];
            }

            $expectedPrev = $actualRowHash;
            $tailHash = $actualRowHash;
        }

        return [
            'valid' => true,
            'checked_rows' => $checked,
            'first_broken_id' => null,
            'expected_hash' => null,
            'actual_hash' => null,
            'tail_hash' => $tailHash,
        ];
    }
}

