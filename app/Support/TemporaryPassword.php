<?php

declare(strict_types=1);

namespace App\Support;

/**
 * High-entropy one-time password shown once to the administrator who creates/resets an account.
 */
final class TemporaryPassword
{
    public static function generate(): string
    {
        // 18 random bytes = 144 bits of entropy, URL-safe base64 (24 chars), plus fixed classes for policy checks.
        return 'Tmp-' . rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=') . '!';
    }
}
