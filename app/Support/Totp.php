<?php

declare(strict_types=1);

namespace App\Support;

/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30s period) for Privileged Staff MFA (DES-006).
 */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(int $length = 32): string
    {
        $bytes = random_bytes($length);
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::ALPHABET[ord($bytes[$i]) & 31];
        }
        return $secret;
    }

    public static function codeAt(string $base32Secret, int $unixTime, int $period = 30, int $digits = 6): string
    {
        $counter = intdiv($unixTime, $period);
        $key = self::base32Decode($base32Secret);
        $binCounter = pack('N*', 0) . pack('N*', $counter);
        $hash = hash_hmac('sha1', $binCounter, $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $truncated = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        );
        $otp = $truncated % (10 ** $digits);
        return str_pad((string) $otp, $digits, '0', STR_PAD_LEFT);
    }

    public static function verify(string $base32Secret, string $code, ?int $unixTime = null, int $window = 1): bool
    {
        $trimmed = trim($code);
        if (!preg_match('/^\d{6}$/', $trimmed)) {
            return false;
        }
        $now = $unixTime ?? time();
        for ($step = -$window; $step <= $window; $step++) {
            $expected = self::codeAt($base32Secret, $now + ($step * 30));
            if (hash_equals($expected, $trimmed)) {
                return true;
            }
        }
        return false;
    }

    private static function base32Decode(string $input): string
    {
        $clean = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $input) ?? '');
        $buffer = 0;
        $bitsLeft = 0;
        $output = '';
        $len = strlen($clean);
        for ($i = 0; $i < $len; $i++) {
            $val = strpos(self::ALPHABET, $clean[$i]);
            if ($val === false) {
                continue;
            }
            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;
            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xff);
            }
        }
        return $output;
    }
}

