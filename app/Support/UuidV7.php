<?php

declare(strict_types=1);

namespace App\Support;

/**
 * RFC 9562 UUIDv7 Generator & Validator (DES-001).
 */
final class UuidV7
{
    public static function generate(?int $timestampMs = null): string
    {
        $ms = $timestampMs ?? (int) floor(microtime(true) * 1000);
        $rand = random_bytes(10);

        $timeHex = str_pad(dechex($ms), 12, '0', STR_PAD_LEFT);
        $randHex = bin2hex($rand);

        // Set version 7 (0111) in the top 4 bits of octet 6
        $verAndRandA = '7' . substr($randHex, 1, 3);
        // Set variant RFC 9562 (10xx) in the top 2 bits of octet 8
        $variantByte = (hexdec(substr($randHex, 4, 2)) & 0x3f) | 0x80;
        $varHex = str_pad(dechex($variantByte), 2, '0', STR_PAD_LEFT);

        return sprintf(
            '%s-%s-%s-%s%s-%s',
            substr($timeHex, 0, 8),
            substr($timeHex, 8, 4),
            $verAndRandA,
            $varHex,
            substr($randHex, 6, 2),
            substr($randHex, 8, 12)
        );
    }

    public static function isValid(string $uuid): bool
    {
        return (bool) preg_match(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $uuid
        );
    }

    public static function deterministic(string $namespaceSeed): string
    {
        $hash = hash('sha256', 'awshortlink-uuidv7:' . $namespaceSeed);
        return sprintf(
            '%s-%s-7%s-8%s-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            substr($hash, 13, 3),
            substr($hash, 17, 3),
            substr($hash, 20, 12)
        );
    }
}

