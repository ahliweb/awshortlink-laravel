<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

use App\Support\PostgreSql;
use PDO;
use Throwable;

/**
 * ALG-005 (Part 2): Atomic Aggregate Click Counter Writer (ADR-0003, DES-011, #17).
 *
 * Calls `shortlink.record_click(uuid, smallint, text)` via `awshortlink_resolver`.
 * Never stores IP addresses, User-Agent strings, cookies, or query strings.
 */
final class RecordClick
{
    public static function record(
        string $linkId,
        int $botClass,
        string $channelCode = '',
        ?PDO $resolverPdo = null
    ): bool {
        if ($botClass === 3) {
            return true;
        }

        $safeChannel = preg_match('/^[a-z0-9_-]{1,24}$/i', $channelCode)
            ? strtolower($channelCode)
            : '';

        try {
            $db = $resolverPdo ?? PostgreSql::resolver();
            $stmt = $db->prepare('SELECT shortlink.record_click(:link_id::uuid, :bot_class::smallint, :channel)');
            $stmt->execute([
                ':link_id' => $linkId,
                ':bot_class' => $botClass,
                ':channel' => $safeChannel,
            ]);
            return true;
        } catch (Throwable) {
            // Analytics write failure must never break public redirect (ALG-003 step 7)
            return false;
        }
    }
}

