<?php

declare(strict_types=1);

namespace App\Domain\Analytics;

/**
 * ALG-005 (Part 1): In-Memory Privacy-Preserving Bot & Prefetch Classifier (#17, TV-024).
 *
 * Classifies incoming requests using transient headers only (never stored):
 * - 0 = human_eligible (valid_clicks)
 * - 1 = known_bot_ua (suspected_bot)
 * - 2 = prefetch_or_missing_headers (suspected_bot)
 * - 3 = synthetic_probe (rejected / ignored)
 */
final class BotClassifier
{
    /**
     * @param array<string, string> $headers Case-insensitive HTTP headers
     */
    public static function classify(array $headers): int
    {
        $normalized = [];
        foreach ($headers as $k => $v) {
            $normalized[strtolower($k)] = trim($v);
        }

        // 3 = synthetic internal probe
        if (($normalized['x-synthetic-probe'] ?? '') === '1' || ($normalized['x-aw-healthcheck'] ?? '') === '1') {
            return 3;
        }

        // 2 = browser prefetch / prerender
        $purpose = strtolower($normalized['purpose'] ?? $normalized['sec-purpose'] ?? $normalized['x-moz'] ?? '');
        if (str_contains($purpose, 'prefetch') || str_contains($purpose, 'preview') || str_contains($purpose, 'prerender')) {
            return 2;
        }

        $ua = $normalized['user-agent'] ?? '';
        if ($ua === '' || strlen($ua) < 8) {
            return 2;
        }

        // 1 = known bot / crawler / messenger link previewer (TV-024)
        $botPatterns = [
            'whatsapp', 'telegrambot', 'facebookexternalhit', 'facebot', 'twitterbot',
            'slackbot', 'discordbot', 'linkedinbot', 'googlebot', 'bingbot', 'yandexbot',
            'ahrefsbot', 'semrushbot', 'MJ12bot', 'curl/', 'wget/', 'python-requests',
            'go-http-client', 'headlesschrome', 'phantomjs', 'playwright', 'puppeteer',
            'uptimerobot', 'pingdom', 'statuscake', 'bot/', 'crawler', 'spider',
        ];
        $uaLower = strtolower($ua);
        foreach ($botPatterns as $pattern) {
            if (str_contains($uaLower, strtolower($pattern))) {
                return 1;
            }
        }

        return 0;
    }
}

