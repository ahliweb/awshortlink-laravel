<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

/**
 * Small-Cohort Privacy Suppressor (ADR-0003, DES-005 k=10, #17, #33, TST-006).
 *
 * Any breakdown bucket with total clicks in `1..9` (`0 < count < k`, where `k = 10`)
 * is masked (`suppressed: true`, `display: '<10'`, `valid_clicks: null`) so small cohorts
 * cannot be singled out. Zero (`0`) and `>= 10` are shown normally.
 */
final class CohortSuppressor
{
    public const DEFAULT_K = 10;

    /**
     * @param array{
     *   valid_clicks: int,
     *   suspected_bot?: int,
     *   rejected?: int,
     *   date_utc?: string,
     *   channel_code?: string
     * } $bucket
     * @return array<string, mixed>
     */
    public static function applyBucket(array $bucket, int $k = self::DEFAULT_K): array
    {
        $valid = (int) ($bucket['valid_clicks'] ?? 0);
        $bot = (int) ($bucket['suspected_bot'] ?? 0);
        $rejected = (int) ($bucket['rejected'] ?? 0);

        if ($valid > 0 && $valid < $k) {
            return array_merge($bucket, [
                'suppressed' => true,
                'threshold_k' => $k,
                'valid_clicks' => null,
                'valid_clicks_display' => '<' . $k,
                'suspected_bot' => $bot >= $k || $bot === 0 ? $bot : null,
                'rejected' => $rejected,
            ]);
        }

        return array_merge($bucket, [
            'suppressed' => false,
            'threshold_k' => $k,
            'valid_clicks' => $valid,
            'valid_clicks_display' => (string) $valid,
            'suspected_bot' => $bot,
            'rejected' => $rejected,
        ]);
    }

    /**
     * @param list<array<string, mixed>> $buckets
     * @return list<array<string, mixed>>
     */
    public static function applySeries(array $buckets, int $k = self::DEFAULT_K): array
    {
        return array_map(
            static fn (array $b): array => self::applyBucket($b, $k),
            $buckets
        );
    }
}

