<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Enterprise Brute-Force Rate Limiter & Account Lockout Defense.
 * Tracks failed authentication attempts per IP and per normalized email.
 */
final class AuthRateLimiter
{
    public const MAX_ATTEMPTS = 5;
    public const DECAY_SECONDS = 900; // 15 minutes lockout

    /**
     * Checks if the given IP address or email is currently locked out.
     *
     * @return array{allowed: bool, attempts: int, max_attempts: int, retry_after: int}
     */
    public static function check(string $ip, string $email): array
    {
        $dir = self::storageDir();
        $now = time();

        $keys = [
            'ip_' . hash('sha256', trim($ip)),
        ];

        $cleanEmail = strtolower(trim($email));
        if ($cleanEmail !== '') {
            $keys[] = 'em_' . hash('sha256', $cleanEmail);
        }

        $maxAttemptsRecorded = 0;
        $maxRetryAfter = 0;

        foreach ($keys as $k) {
            $file = $dir . '/' . $k . '.json';
            if (!is_file($file)) {
                continue;
            }

            $content = @file_get_contents($file);
            if ($content === false || $content === '') {
                continue;
            }

            $data = json_decode($content, true);
            if (!is_array($data) || !isset($data['attempts']) || !is_array($data['attempts'])) {
                continue;
            }

            // Filter out timestamps older than decay window
            $validTimestamps = array_values(array_filter(
                $data['attempts'],
                static fn (mixed $ts): bool => is_int($ts) && ($now - $ts) < self::DECAY_SECONDS
            ));

            $count = count($validTimestamps);
            if ($count > $maxAttemptsRecorded) {
                $maxAttemptsRecorded = $count;
            }

            if ($count >= self::MAX_ATTEMPTS) {
                $earliest = min($validTimestamps);
                $retryAfter = ($earliest + self::DECAY_SECONDS) - $now;
                if ($retryAfter > 0 && $retryAfter > $maxRetryAfter) {
                    $maxRetryAfter = $retryAfter;
                }
            }
        }

        if ($maxRetryAfter > 0) {
            return [
                'allowed' => false,
                'attempts' => $maxAttemptsRecorded,
                'max_attempts' => self::MAX_ATTEMPTS,
                'retry_after' => $maxRetryAfter,
            ];
        }

        return [
            'allowed' => true,
            'attempts' => $maxAttemptsRecorded,
            'max_attempts' => self::MAX_ATTEMPTS,
            'retry_after' => 0,
        ];
    }

    /**
     * Records a failed authentication attempt.
     */
    public static function hit(string $ip, string $email): int
    {
        $dir = self::storageDir();
        $now = time();

        $keys = [
            'ip_' . hash('sha256', trim($ip)),
        ];

        $cleanEmail = strtolower(trim($email));
        if ($cleanEmail !== '') {
            $keys[] = 'em_' . hash('sha256', $cleanEmail);
        }

        $recordedMax = 0;

        foreach ($keys as $k) {
            $file = $dir . '/' . $k . '.json';
            $attempts = [];

            if (is_file($file)) {
                $content = @file_get_contents($file);
                if ($content !== false && $content !== '') {
                    $data = json_decode($content, true);
                    if (is_array($data) && isset($data['attempts']) && is_array($data['attempts'])) {
                        $attempts = array_values(array_filter(
                            $data['attempts'],
                            static fn (mixed $ts): bool => is_int($ts) && ($now - $ts) < self::DECAY_SECONDS
                        ));
                    }
                }
            }

            $attempts[] = $now;
            @file_put_contents($file, json_encode(['attempts' => $attempts], JSON_UNESCAPED_SLASHES), LOCK_EX);

            $c = count($attempts);
            if ($c > $recordedMax) {
                $recordedMax = $c;
            }
        }

        return $recordedMax;
    }

    /**
     * Clears failed attempt counters upon successful authentication.
     */
    public static function clear(string $ip, string $email): void
    {
        $dir = self::storageDir();

        $keys = [
            'ip_' . hash('sha256', trim($ip)),
        ];

        $cleanEmail = strtolower(trim($email));
        if ($cleanEmail !== '') {
            $keys[] = 'em_' . hash('sha256', $cleanEmail);
        }

        foreach ($keys as $k) {
            $file = $dir . '/' . $k . '.json';
            if (is_file($file)) {
                @unlink($file);
            }
        }
    }

    /**
     * Calculates the remaining attempts before account/IP temporary lockout.
     */
    public static function remainingAttempts(string $ip, string $email): int
    {
        $check = self::check($ip, $email);
        $rem = self::MAX_ATTEMPTS - $check['attempts'];
        return max(0, $rem);
    }

    private static function storageDir(): string
    {
        // Private (0700) directory, preferably inside the application's own storage. A world-readable/shared /tmp
        // path would let other local users read or poison throttle state on shared hosting.
        $configured = getenv('THROTTLE_STORAGE_DIR');
        $dir = ($configured !== false && $configured !== '')
            ? $configured
            : dirname(__DIR__, 2) . '/storage/framework/throttle';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            $dir = sys_get_temp_dir() . '/shortlink_auth_throttle_' . (function_exists('posix_getuid') ? posix_getuid() : 'u');
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }
        }

        return $dir;
    }
}

