<?php

declare(strict_types=1);

namespace App\Domain\AccessControl;

use InvalidArgumentException;

/**
 * Source-Controlled Permission Catalog Validator (PERM-001..062, SPEC-06, #19, #40).
 */
final class PermissionCatalog
{
    /** @var array<string, array{code: string, key: string, description: string, risk: string}>|null */
    private static ?array $byKey = null;

    /**
     * @return array<string, array{code: string, key: string, description: string, risk: string}>
     */
    public static function allByKey(): array
    {
        if (self::$byKey !== null) {
            return self::$byKey;
        }

        /** @var array<string, mixed> $cfg */
        $cfg = require dirname(__DIR__, 3) . '/config/permissions.php';
        /** @var array<string, array{key: string, description: string, risk: string}> $perms */
        $perms = $cfg['permissions'] ?? [];

        $map = [];
        foreach ($perms as $code => $meta) {
            $map[$meta['key']] = [
                'code' => $code,
                'key' => $meta['key'],
                'description' => $meta['description'],
                'risk' => $meta['risk'],
            ];
        }
        self::$byKey = $map;
        return self::$byKey;
    }

    public static function exists(string $permissionKey): bool
    {
        $all = self::allByKey();
        return isset($all[$permissionKey]);
    }

    /**
     * @return array{code: string, key: string, description: string, risk: string}
     */
    public static function getOrFail(string $permissionKey): array
    {
        $all = self::allByKey();
        if (!isset($all[$permissionKey])) {
            throw new InvalidArgumentException(sprintf(
                'UNKNOWN_PERMISSION_KEY: Permission "%s" is not in the source-controlled catalog (PERM-001..062).',
                $permissionKey
            ));
        }
        return $all[$permissionKey];
    }

    public static function isMutationPermission(string $permissionKey): bool
    {
        foreach (['.read', '.list_', '.view', '.inspect', '.simulate', '.verify_chain', '.export', 'qr.generate', 'csv.export'] as $readFragment) {
            if (str_contains($permissionKey, $readFragment)) {
                return false;
            }
        }
        return true;
    }
}

