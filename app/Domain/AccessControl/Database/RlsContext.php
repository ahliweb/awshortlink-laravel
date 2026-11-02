<?php

declare(strict_types=1);

namespace App\Domain\AccessControl\Database;

use App\Support\PostgreSql;
use App\Support\UuidV7;
use PDO;
use RuntimeException;
use Throwable;

/**
 * Transaction-local PostgreSQL RLS Context Manager (SPEC-05, ADR-0005, #12, #19, #38).
 *
 * Guarantees that every scoped query or mutation executes inside an explicit database
 * transaction (`BEGIN ... COMMIT/ROLLBACK`) with `SET LOCAL` (`set_config(..., true)`)
 * so pooled connections never leak `app.actor_id`, `app.unit_ids`, or `app.scope`.
 */
final class RlsContext
{
    public const SYSTEM_ACTOR_ID = '00000000-0000-7000-8000-000000000001';
    public const ROOT_UNIT_ID = '00000000-0000-7000-8000-000000000010';

    public function __construct(
        public readonly string $actorId,
        /** @var list<string> */
        public readonly array $unitIds = [],
        public readonly string $scope = 'unit',
        public readonly ?string $requestId = null,
    ) {
        if (!UuidV7::isValid($this->actorId)) {
            throw new RuntimeException('RLS_CONTEXT_INVALID_ACTOR: actorId must be a valid UUID.');
        }
        foreach ($this->unitIds as $unitId) {
            if (!UuidV7::isValid($unitId)) {
                throw new RuntimeException(sprintf('RLS_CONTEXT_INVALID_UNIT: "%s" is not a valid UUID.', $unitId));
            }
        }
        if (!in_array($this->scope, ['unit', 'global', 'self'], true)) {
            throw new RuntimeException(sprintf('RLS_CONTEXT_INVALID_SCOPE: "%s" is not valid.', $this->scope));
        }
    }

    public static function systemGlobal(?string $actorId = null): self
    {
        return new self(
            actorId: $actorId ?? self::SYSTEM_ACTOR_ID,
            unitIds: [self::ROOT_UNIT_ID],
            scope: 'global',
            requestId: UuidV7::generate()
        );
    }

    public static function forActor(
        string $actorId,
        array $unitIds,
        bool $isGlobal = false,
        ?string $requestId = null
    ): self {
        return new self(
            actorId: $actorId,
            unitIds: array_values(array_unique($unitIds)),
            scope: $isGlobal ? 'global' : 'unit',
            requestId: $requestId ?? UuidV7::generate()
        );
    }

    /**
     * Executes `$callback(PDO $pdo)` inside an explicit PostgreSQL transaction with
     * transaction-local `app.actor_id`, `app.unit_ids` (optionally expanded via `unit_closure`),
     * and `app.scope`. Automatically commits on success and rolls back on exception.
     *
     * @template T
     * @param callable(PDO): T $callback
     * @return T
     */
    public function run(callable $callback, ?PDO $pdo = null, bool $expandDescendants = false): mixed
    {
        $db = $pdo ?? PostgreSql::app();
        $ownsTx = !$db->inTransaction();

        if ($ownsTx) {
            $db->beginTransaction();
        }

        try {
            $this->applyLocalSettings($db, $expandDescendants);
            $result = $callback($db);
            if ($ownsTx && $db->inTransaction()) {
                $db->commit();
            }
            return $result;
        } catch (Throwable $e) {
            if ($ownsTx && $db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
    }

    public function applyLocalSettings(PDO $db, bool $expandDescendants = false): void
    {
        if (!$db->inTransaction()) {
            throw new RuntimeException('RLS_CONTEXT_REQUIRES_TRANSACTION: set_config(..., true) requires an active transaction.');
        }

        $stmt = $db->prepare(
            "SELECT set_config('app.actor_id', :actor_id, true),
                    set_config('app.scope', :scope, true),
                    set_config('app.unit_ids', :unit_ids, true)"
        );

        $unitCsv = implode(',', $this->unitIds);
        $stmt->execute([
            ':actor_id' => $this->actorId,
            ':scope' => $this->scope,
            ':unit_ids' => $unitCsv,
        ]);

        if ($expandDescendants && $this->unitIds !== []) {
            $placeholders = implode(',', array_fill(0, count($this->unitIds), '?'));
            $closureStmt = $db->prepare(
                "SELECT DISTINCT descendant_id::text
                 FROM shortlink.unit_closure
                 WHERE ancestor_id IN ($placeholders)"
            );
            $closureStmt->execute(array_values($this->unitIds));
            /** @var list<string> $expanded */
            $expanded = $closureStmt->fetchAll(PDO::FETCH_COLUMN);
            $merged = array_values(array_unique(array_merge($this->unitIds, $expanded)));
            $updateUnits = $db->prepare("SELECT set_config('app.unit_ids', :unit_ids, true)");
            $updateUnits->execute([':unit_ids' => implode(',', $merged)]);
        }
    }
}

