<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Support\UuidV7;
use PDO;
use RuntimeException;

/**
 * Privacy-Preserving Daily Aggregate Analytics, Campaigns & Safe Export Service (#17, #28, #33, TST-006).
 */
final class AnalyticsService
{
    /**
     * Queries daily aggregate stats for a link or unit with $k=10$ small-cohort suppression (DES-005).
     *
     * @return array{
     *   threshold_k: int,
     *   totals: array<string, mixed>,
     *   daily_series: list<array<string, mixed>>
     * }
     */
    public static function queryDailyStats(
        string $actorId,
        ?string $linkId = null,
        ?string $unitId = null,
        ?string $fromDate = null,
        ?string $toDate = null,
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'analytics.view',
            resourceType: 'analytics',
            resourceAttributes: ['id' => $linkId, 'unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($linkId, $unitId, $fromDate, $toDate): array {
            $sql = 'SELECT date_utc::text AS date_utc,
                           channel_code,
                           COALESCE(SUM(valid_clicks), 0)::bigint AS valid_clicks,
                           COALESCE(SUM(suspected_bot), 0)::bigint AS suspected_bot,
                           COALESCE(SUM(rejected), 0)::bigint AS rejected
                    FROM shortlink.link_daily_stats
                    WHERE 1=1';
            $params = [];
            if ($linkId !== null) {
                $sql .= ' AND link_id = :lid';
                $params[':lid'] = $linkId;
            }
            if ($unitId !== null) {
                $sql .= ' AND unit_id = :uid';
                $params[':uid'] = $unitId;
            }
            if ($fromDate !== null) {
                $sql .= ' AND date_utc >= :from_date';
                $params[':from_date'] = $fromDate;
            }
            if ($toDate !== null) {
                $sql .= ' AND date_utc <= :to_date';
                $params[':to_date'] = $toDate;
            }
            $sql .= ' GROUP BY date_utc, channel_code ORDER BY date_utc DESC, channel_code ASC';

            $stmt = $db->prepare($sql);
            $stmt->execute($params);
            /** @var list<array<string, mixed>> $rows */
            $rows = $stmt->fetchAll();

            $totalValid = 0;
            $totalBot = 0;
            $totalRejected = 0;
            $normalizedBuckets = [];

            foreach ($rows as $r) {
                $v = (int) $r['valid_clicks'];
                $b = (int) $r['suspected_bot'];
                $rej = (int) $r['rejected'];
                $totalValid += $v;
                $totalBot += $b;
                $totalRejected += $rej;
                $normalizedBuckets[] = [
                    'date_utc' => (string) $r['date_utc'],
                    'channel_code' => (string) $r['channel_code'],
                    'valid_clicks' => $v,
                    'suspected_bot' => $b,
                    'rejected' => $rej,
                ];
            }

            return [
                'threshold_k' => CohortSuppressor::DEFAULT_K,
                'totals' => CohortSuppressor::applyBucket([
                    'valid_clicks' => $totalValid,
                    'suspected_bot' => $totalBot,
                    'rejected' => $totalRejected,
                ]),
                'daily_series' => CohortSuppressor::applySeries($normalizedBuckets),
            ];
        }, $pdo);
    }

    /**
     * Creates a unit campaign (`campaigns.create`, PERM-020, #28, API-026).
     *
     * @return array<string, mixed>
     */
    public static function createCampaign(
        string $actorId,
        string $unitId,
        string $code,
        string $name,
        string $status = 'running',
        ?string $startAt = null,
        ?string $endAt = null,
        string $reason = 'Create campaign',
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'campaigns.create',
            resourceType: 'campaigns',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        $campaignId = UuidV7::generate();
        $cleanCode = strtoupper(trim($code));

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $campaignId,
            $unitId,
            $cleanCode,
            $name,
            $status,
            $startAt,
            $endAt,
            $reason
        ): array {
            $stmt = $db->prepare(
                'INSERT INTO shortlink.campaigns (id, unit_id, code, name, status, owner_id, start_at, end_at)
                 VALUES (:id, :unit_id, :code, :name, :status, :owner_id, :start_at, :end_at)
                 RETURNING id, unit_id, code, name, status, owner_id'
            );
            $stmt->execute([
                ':id' => $campaignId,
                ':unit_id' => $unitId,
                ':code' => $cleanCode,
                ':name' => trim($name),
                ':status' => $status,
                ':owner_id' => $actorId,
                ':start_at' => $startAt,
                ':end_at' => $endAt,
            ]);
            /** @var array<string, mixed> $camp */
            $camp = $stmt->fetch();

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'campaigns.created',
                subjectType: 'campaign',
                subjectId: $campaignId,
                subjectVersion: 1,
                unitId: $unitId,
                afterState: $camp,
                reason: $reason
            );

            return $camp;
        }, $pdo);
    }

    /**
     * Purges daily stats older than 13 months per retention policy (ADR-0003, DES-007, #33).
     */
    public static function pruneExpiredDailyStats(PDO $migratorPdo, int $retentionMonths = 13): int
    {
        $migratorPdo->beginTransaction();
        try {
            $migratorPdo->exec('SET LOCAL ROLE awshortlink_owner');
            $stmt = $migratorPdo->prepare(
                "DELETE FROM shortlink.link_daily_stats
                 WHERE date_utc < (CURRENT_DATE - (:months || ' months')::interval)::date"
            );
            $stmt->execute([':months' => $retentionMonths]);
            $deleted = $stmt->rowCount();
            $migratorPdo->commit();
            return $deleted;
        } catch (\Throwable $e) {
            if ($migratorPdo->inTransaction()) {
                $migratorPdo->rollBack();
            }
            throw $e;
        }
    }
}

