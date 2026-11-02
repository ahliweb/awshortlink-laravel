<?php

declare(strict_types=1);

namespace App\Support;

use PDO;
use RuntimeException;

/**
 * Enforces the PostgreSQL-Only Database Contract (ADR-0005, #10, #12, #38, #43).
 *
 * Refuses SQLite, MySQL, and MariaDB in all environments and manages role-separated
 * PDO connections (`awshortlink_app`, `awshortlink_resolver`, `awshortlink_migrator`).
 */
final class PostgreSql
{
    /** @var array<string, PDO> */
    private static array $connections = [];

    public static function assertDriverAllowed(string $driver): void
    {
        if (strtolower($driver) !== 'pgsql') {
            throw new RuntimeException(sprintf(
                'SECURITY_VIOLATION: Database driver "%s" is forbidden. AW Shortlink requires PostgreSQL (pgsql) with compulsory RLS in all environments.',
                $driver
            ));
        }
    }

    /**
     * @return array<string, mixed>
     */
    public static function config(): array
    {
        /** @var array<string, mixed> $cfg */
        $cfg = require dirname(__DIR__, 2) . '/config/database.php';
        $default = (string) ($cfg['default'] ?? 'pgsql');
        self::assertDriverAllowed($default);
        return $cfg;
    }

    public static function connection(string $name = 'pgsql', bool $fresh = false): PDO
    {
        if (!$fresh && isset(self::$connections[$name])) {
            return self::$connections[$name];
        }

        $cfg = self::config();
        /** @var array<string, array<string, mixed>> $conns */
        $conns = $cfg['connections'] ?? [];
        if (!isset($conns[$name])) {
            throw new RuntimeException(sprintf('Unknown PostgreSQL connection profile "%s".', $name));
        }

        $profile = $conns[$name];
        self::assertDriverAllowed((string) ($profile['driver'] ?? ''));

        $dsn = sprintf(
            'pgsql:host=%s;port=%d;dbname=%s',
            (string) $profile['host'],
            (int) $profile['port'],
            (string) $profile['database']
        );

        $pdo = new PDO(
            $dsn,
            (string) $profile['username'],
            (string) $profile['password'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );

        $pdo->exec('SET search_path = shortlink, pg_catalog');
        self::$connections[$name] = $pdo;

        return $pdo;
    }

    public static function app(): PDO
    {
        return self::connection('pgsql');
    }

    public static function resolver(): PDO
    {
        return self::connection('pgsql_resolver');
    }

    public static function migrator(): PDO
    {
        return self::connection('pgsql_migrator');
    }

    public static function resetConnections(): void
    {
        self::$connections = [];
    }

    /**
     * Introspects PostgreSQL role posture and compulsory RLS enforcement (#38, #43, TST-018).
     *
     * @return array{
     *   healthy: bool,
     *   server_version: string,
     *   current_user: string,
     *   app_role_posture: array<string, mixed>,
     *   resolver_role_posture: array<string, mixed>,
     *   tables_total: int,
     *   tables_with_rls_and_force: int,
     *   unprotected_tables: list<string>,
     *   tables_owned_by_app_role: int,
     *   policies_count: int
     * }
     */
    public static function introspectSecurityPosture(?PDO $pdo = null): array
    {
        $db = $pdo ?? self::app();

        $version = (string) $db->query('SHOW server_version')->fetchColumn();
        $currentUser = (string) $db->query('SELECT current_user')->fetchColumn();

        $roleStmt = $db->prepare(
            'SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
             FROM pg_catalog.pg_roles
             WHERE rolname = :rolname'
        );
        $roleStmt->execute([':rolname' => 'awshortlink_app']);
        /** @var array<string, mixed>|false $appRole */
        $appRole = $roleStmt->fetch();

        $roleStmt->execute([':rolname' => 'awshortlink_resolver']);
        /** @var array<string, mixed>|false $resolverRole */
        $resolverRole = $roleStmt->fetch();

        $tablesStmt = $db->query(
            "SELECT c.relname AS table_name,
                    c.relrowsecurity AS rls_enabled,
                    c.relforcerowsecurity AS rls_forced,
                    pg_catalog.pg_get_userbyid(c.relowner) AS owner_name
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'shortlink'
               AND c.relkind = 'r'
             ORDER BY c.relname"
        );
        /** @var list<array<string, mixed>> $tables */
        $tables = $tablesStmt->fetchAll();

        $unprotected = [];
        $ownedByApp = 0;
        $protectedCount = 0;
        foreach ($tables as $t) {
            $rlsEnabled = (bool) $t['rls_enabled'];
            $rlsForced = (bool) $t['rls_forced'];
            if ($rlsEnabled && $rlsForced) {
                $protectedCount++;
            } else {
                $unprotected[] = (string) $t['table_name'];
            }
            if (($t['owner_name'] ?? '') === 'awshortlink_app') {
                $ownedByApp++;
            }
        }

        $policiesCount = (int) $db->query(
            "SELECT count(*) FROM pg_catalog.pg_policies WHERE schemaname = 'shortlink'"
        )->fetchColumn();

        $appSafe = is_array($appRole)
            && !$appRole['rolsuper']
            && !$appRole['rolcreaterole']
            && !$appRole['rolcreatedb']
            && !$appRole['rolbypassrls'];

        $resolverSafe = is_array($resolverRole)
            && !$resolverRole['rolsuper']
            && !$resolverRole['rolcreaterole']
            && !$resolverRole['rolcreatedb']
            && !$resolverRole['rolbypassrls'];

        $healthy = $appSafe
            && $resolverSafe
            && count($tables) >= 27
            && $unprotected === []
            && $ownedByApp === 0
            && $policiesCount >= 60;

        return [
            'healthy' => $healthy,
            'server_version' => $version,
            'current_user' => $currentUser,
            'app_role_posture' => is_array($appRole) ? $appRole : [],
            'resolver_role_posture' => is_array($resolverRole) ? $resolverRole : [],
            'tables_total' => count($tables),
            'tables_with_rls_and_force' => $protectedCount,
            'unprotected_tables' => $unprotected,
            'tables_owned_by_app_role' => $ownedByApp,
            'policies_count' => $policiesCount,
        ];
    }
}

