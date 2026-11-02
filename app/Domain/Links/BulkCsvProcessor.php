<?php

declare(strict_types=1);

namespace App\Domain\Links;

use App\Domain\AccessControl\Gate\AuthorizationPipeline;
use App\Domain\Audit\AuditWriter;
use App\Domain\DestinationPolicy\DestinationRiskClassifier;
use App\Domain\Resolver\SlugCanonicalizer;
use PDO;
use RuntimeException;

/**
 * Bulk CSV Short Link Dry-Run, Safe Import & Formula-Safe Export Service (#29, TST-012, API-051, API-052).
 */
final class BulkCsvProcessor
{
    private const FORMULA_PREFIXES = ['=', '+', '-', '@', "\t", "\r"];

    /**
     * Neutralizes spreadsheet formula injection (`=CMD()`, `+`, `-`, `@`, `\t`, `\r`) on cell values.
     */
    public static function sanitizeCellForExport(string $value): string
    {
        if ($value === '') {
            return '';
        }
        if (in_array($value[0], self::FORMULA_PREFIXES, true)) {
            return "'" . $value;
        }
        return $value;
    }

    /**
     * Rejects or strips dangerous formula prefixes on imported titles/slugs.
     */
    public static function containsFormulaInjection(string $value): bool
    {
        $trimmed = ltrim($value, ' ');
        return $trimmed !== '' && in_array($trimmed[0], self::FORMULA_PREFIXES, true);
    }

    /**
     * @param list<array{slug: string, title: string, destination_url: string, visibility?: string}> $rows
     * @return array{
     *   dry_run: bool,
     *   valid: bool,
     *   total_rows: int,
     *   created_count: int,
     *   row_results: list<array<string, mixed>>
     * }
     */
    public static function importRows(
        string $actorId,
        string $unitId,
        array $rows,
        bool $dryRun = true,
        string $reason = 'Bulk CSV short link import',
        ?PDO $pdo = null,
    ): array {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'csv.import',
            resourceType: 'links',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use (
            $actorId,
            $unitId,
            $rows,
            $dryRun,
            $reason,
            $pdo
        ): array {
            $rowResults = [];
            $allValid = true;
            $seenSlugs = [];

            foreach ($rows as $idx => $row) {
                $rawSlug = (string) ($row['slug'] ?? '');
                $rawTitle = (string) ($row['title'] ?? '');
                $rawUrl = (string) ($row['destination_url'] ?? '');
                $errors = [];

                if (self::containsFormulaInjection($rawTitle) || self::containsFormulaInjection($rawSlug)) {
                    $errors[] = 'CSV_FORMULA_INJECTION_DETECTED';
                }

                $slugCanon = SlugCanonicalizer::canonicalize($rawSlug);
                if (!$slugCanon['valid'] || $slugCanon['slug_normalized'] === null) {
                    $errors[] = $slugCanon['error_code'] ?? 'INVALID_SLUG';
                } else {
                    $normSlug = $slugCanon['slug_normalized'];
                    if (isset($seenSlugs[$normSlug])) {
                        $errors[] = 'DUPLICATE_SLUG_IN_BATCH';
                    } else {
                        $seenSlugs[$normSlug] = true;
                        $resStmt = $db->prepare("SELECT 1 FROM shortlink.reserved_slugs WHERE namespace = 'buka' AND slug_normalized = :s");
                        $resStmt->execute([':s' => $normSlug]);
                        if ($resStmt->fetchColumn() !== false) {
                            $errors[] = 'SLUG_ALREADY_RESERVED';
                        }
                    }
                }

                $urlVerdict = DestinationRiskClassifier::evaluate($rawUrl, $db);
                if (!$urlVerdict['allowed']) {
                    $errors[] = $urlVerdict['error_code'] ?? 'DESTINATION_FORBIDDEN';
                }

                if ($errors !== []) {
                    $allValid = false;
                }

                $rowResults[] = [
                    'row_number' => $idx + 1,
                    'slug' => $slugCanon['slug_normalized'] ?? $rawSlug,
                    'valid' => $errors === [],
                    'risk_class' => $urlVerdict['risk_class'],
                    'errors' => $errors,
                ];
            }

            // Atomic batch rule: if dry_run=true OR any row has errors, do not persist any row!
            if ($dryRun || !$allValid) {
                return [
                    'dry_run' => $dryRun,
                    'valid' => $allValid,
                    'total_rows' => count($rows),
                    'created_count' => 0,
                    'row_results' => $rowResults,
                ];
            }

            $createdCount = 0;
            foreach ($rows as $idx => $row) {
                $draft = LinkLifecycleService::createDraft(
                    actorId: $actorId,
                    unitId: $unitId,
                    rawSlug: (string) $row['slug'],
                    title: (string) $row['title'],
                    destinationUrl: (string) $row['destination_url'],
                    visibility: (string) ($row['visibility'] ?? 'public'),
                    reason: $reason,
                    pdo: $db
                );
                $rowResults[$idx]['link_id'] = $draft['id'];
                $createdCount++;
            }

            AuditWriter::recordMutation(
                db: $db,
                actorId: $actorId,
                action: 'csv.batch_imported',
                subjectType: 'csv_import',
                subjectId: null,
                subjectVersion: 1,
                unitId: $unitId,
                afterState: ['total_rows' => count($rows), 'created_count' => $createdCount],
                reason: $reason
            );

            return [
                'dry_run' => false,
                'valid' => true,
                'total_rows' => count($rows),
                'created_count' => $createdCount,
                'row_results' => $rowResults,
            ];
        }, $pdo);
    }

    /**
     * Exports scoped short links as formula-safe CSV lines (#29, TST-012, API-052).
     */
    public static function exportScopedCsv(string $actorId, ?string $unitId = null, ?PDO $pdo = null): string
    {
        $auth = AuthorizationPipeline::evaluate(
            actorId: $actorId,
            permissionKey: 'csv.export',
            resourceType: 'links',
            resourceAttributes: ['unit_id' => $unitId],
            pdo: $pdo
        );
        if (!$auth['permitted'] || $auth['rls_context'] === null) {
            throw new RuntimeException('AUTH_DENIED:' . $auth['reason_code']);
        }

        return $auth['rls_context']->run(static function (PDO $db) use ($unitId): string {
            $sql = 'SELECT l.slug_normalized, l.title, l.status, l.visibility, d.url_canonical, d.risk_class
                    FROM shortlink.links l
                    LEFT JOIN shortlink.link_destinations d ON d.id = l.current_destination_id
                    WHERE 1=1';
            $params = [];
            if ($unitId !== null) {
                $sql .= ' AND l.unit_id = :uid';
                $params[':uid'] = $unitId;
            }
            $sql .= ' ORDER BY l.slug_normalized ASC';

            $stmt = $db->prepare($sql);
            $stmt->execute($params);
            /** @var list<array<string, mixed>> $rows */
            $rows = $stmt->fetchAll();

            $fh = fopen('php://temp', 'r+');
            if ($fh === false) {
                throw new RuntimeException('CSV_STREAM_ERROR');
            }
            fputcsv($fh, ['slug', 'title', 'status', 'visibility', 'url_canonical', 'risk_class'], ',', '"', '');
            foreach ($rows as $r) {
                fputcsv($fh, [
                    self::sanitizeCellForExport((string) $r['slug_normalized']),
                    self::sanitizeCellForExport((string) $r['title']),
                    self::sanitizeCellForExport((string) $r['status']),
                    self::sanitizeCellForExport((string) $r['visibility']),
                    self::sanitizeCellForExport((string) ($r['url_canonical'] ?? '')),
                    self::sanitizeCellForExport((string) ($r['risk_class'] ?? '')),
                ], ',', '"', '');
            }
            rewind($fh);
            $csv = (string) stream_get_contents($fh);
            fclose($fh);
            return $csv;
        }, $pdo);
    }
}

