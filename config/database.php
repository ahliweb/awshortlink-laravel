<?php

declare(strict_types=1);

/**
 * PostgreSQL-Only Database Configuration (ADR-0005, REQ-021, REQ-024).
 *
 * SQLite, MySQL, and MariaDB are strictly prohibited in local, test, staging, and production.
 */

$envHost = getenv('DB_HOST') ?: null;
$envPort = getenv('DB_PORT') ?: null;
$envDatabase = getenv('DB_DATABASE') ?: null;
$envUsername = getenv('DB_USERNAME') ?: null;
$envPassword = getenv('DB_PASSWORD') ?: null;
$envSslMode = getenv('DB_SSLMODE') ?: null;

// SECURITY: there are deliberately NO default passwords. A missing password yields an empty one and the
// connection is refused, instead of silently falling back to a well-known credential.
$defaultHost = $envHost ?? '127.0.0.1';
$defaultPort = $envPort ?? '5432';
$defaultDatabase = $envDatabase ?? 'awshortlink';
$defaultUsername = $envUsername ?? 'awshortlink_app';
$defaultPassword = $envPassword ?? '';
$defaultSslMode = $envSslMode ?? 'prefer';

return [
    'default' => 'pgsql',

    'prohibited_drivers' => ['sqlite', 'mysql', 'mariadb', 'sqlsrv'],

    'connections' => [
        // Runtime application role: non-owner, NOSUPERUSER, NOBYPASSRLS, subject to mandatory RLS
        'pgsql' => [
            'driver' => 'pgsql',
            'host' => $defaultHost,
            'port' => $defaultPort,
            'database' => $defaultDatabase,
            'username' => $defaultUsername,
            'password' => $defaultPassword,
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'shortlink',
            'sslmode' => $defaultSslMode,
        ],

        // Public anonymous resolver role: SELECT on shortlink.public_resolvable_links & EXECUTE shortlink.record_click only
        // Falls back to runtime credentials on shared hosting environments if separate resolver user is not defined.
        'pgsql_resolver' => [
            'driver' => 'pgsql',
            'host' => getenv('DB_RESOLVER_HOST') ?: $defaultHost,
            'port' => getenv('DB_RESOLVER_PORT') ?: $defaultPort,
            'database' => getenv('DB_RESOLVER_DATABASE') ?: $defaultDatabase,
            'username' => getenv('DB_RESOLVER_USERNAME') ?: ($envUsername ?? 'awshortlink_resolver'),
            'password' => getenv('DB_RESOLVER_PASSWORD') ?: ($envPassword ?? ''),
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'shortlink',
            'sslmode' => getenv('DB_RESOLVER_SSLMODE') ?: $defaultSslMode,
        ],

        // Operator-only migrator role (direct connection, never used by web runtime)
        // Falls back to runtime credentials on shared hosting environments if separate migrator user is not defined.
        'pgsql_migrator' => [
            'driver' => 'pgsql',
            'host' => getenv('DB_MIGRATOR_HOST') ?: $defaultHost,
            'port' => getenv('DB_MIGRATOR_PORT') ?: $defaultPort,
            'database' => getenv('DB_MIGRATOR_DATABASE') ?: $defaultDatabase,
            'username' => getenv('DB_MIGRATOR_USERNAME') ?: ($envUsername ?? 'awshortlink_migrator'),
            'password' => getenv('DB_MIGRATOR_PASSWORD') ?: ($envPassword ?? ''),
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'shortlink',
            'sslmode' => getenv('DB_MIGRATOR_SSLMODE') ?: $defaultSslMode,
        ],
    ],
];
