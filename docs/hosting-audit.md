# Hosting Discovery & Compatibility Audit — MUST PASS BEFORE FRAMEWORK SCAFFOLD

**Constraint:** SSH to production is unavailable. This is a capability audit for your target URL (for example https://links.example.org/buka/). Unknowns are **NOT** assumptions of readiness.

## Host intake form (to be filled by authorized operator; never include secrets)
| Control | Required evidence | Result |
| --- | --- | --- |
| HOST-01 | Host owner, panel vendor, type and contact | NOT VERIFIED |
| HOST-02 | PHP >=8.3 and enabled extensions required by Laravel + Filament | NOT VERIFIED |
| HOST-03 | **PostgreSQL mandatory** (supported major/patch, pdo_pgsql/pgsql, service connection, TLS, grants for RLS policy DDL) | NOT VERIFIED |
| HOST-04 | Apache mod_rewrite + AllowOverride OR Nginx location route delegation | NOT VERIFIED |
| HOST-05 | Parent website route map /buka path collision and SSL behavior | NOT VERIFIED |
| HOST-06 | Private application path outside public_html / document root | NOT VERIFIED |
| HOST-07 | Storage and bootstrap/cache writable by PHP; file ownership | NOT VERIFIED |
| HOST-08 | HTTPS, secure SFTP/FTPS or verified panel File Manager upload | NOT VERIFIED |
| HOST-09 | Cron and PHP CLI path available? Is persistent process prohibited? | NOT VERIFIED |
| HOST-10 | Safe migration operator mechanism, phpMyAdmin? backup+restore | NOT VERIFIED |
| HOST-11 | Outbound network DNS/HTTP only for optional link checker; restrictions | NOT VERIFIED |
| HOST-12 | Backups and SLA; error log access; incident reporting | NOT VERIFIED |
| HOST-13 | Webserver support for Livewire update/assets under /buka prefix | NOT VERIFIED |
| HOST-14 | Institutional authorization to edit the parent website's routing | NOT VERIFIED |

## Feasibility decision matrix
- If PHP or extension requirements not met: **BLOCK** Laravel 13 on that host; seek approved hosting upgrade or a separately managed approved host preserving the public path.
- If /buka rewrite/delegation unavailable: **BLOCK** public URL target; cannot fix purely in app code.
- If private app placement outside webroot unavailable: **BLOCK** production; do not expose source/vendor/.env.
- If cron unavailable: keep P0 synchronous bounded functions and manual reporting; defer scheduled checks, queue-based reports and automatic retention. Security-critical expiry/suspend must be enforced at request time.
- If safe migrations/backup not available: **BLOCK** production; app needs reliable schema updates.
- If PostgreSQL is missing or PHP pdo_pgsql cannot connect: **NO-GO** and request approved hosting or managed PostgreSQL upgrade. Never fall back to MySQL/MariaDB/SQLite. PostgreSQL migrations and RLS must be tested against the exact host major version.
- If public path can only be delegated by parent website reverse proxy: require host operator configuration, no SSH for developer.

## Verification test cases
Browse root public website before and after /buka installation; test /buka/, valid slug, absent slug, nested slug conflict, .env/vendor/artisan exposure 403/404, Livewire interactive form, admin asset loading, redirects and HTTPS. Measure response codes and rollback route restoration. Keep screenshots and operator signoff outside public repo if they include internals.

## Hosting sign-off
Operator: TBD | Date: TBD | Approved topology: TBD | Open blockers: 14 | **Status: NO-GO**.


## Additional hard hosting checkpoints
HOST-15: PostgreSQL runtime nonowner/no BYPASSRLS and dedicated migrator/backup credentials; ability to ENABLE/FORCE RLS and CREATE POLICY, verified by operator. **NOT VERIFIED**.
HOST-16: approved PostgreSQL migration/backup/restore without developer SSH (pgAdmin, psql via operator, provider console or sanctioned Artisan job), and secure direct DB route. **NOT VERIFIED**.
HOST-17: institutional owners for user/role/permission provisioning and ABAC approval, protected initial owner/MFA and break-glass procedure. **NOT VERIFIED**.
Current status remains NO-GO for production release until facts and human signatures; see postgresql-rls-design.md.

---

## Locked Local / CI Target Baseline vs. Production Gate ([ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md))
Per stakeholder direction (2026-11-01, `DEC-018`):
1. **Local Development & Automated CI (`#10`–`#23`, `#38`–`#42`)** target **PostgreSQL 17/18** (`DB_CONNECTION=pgsql`, `pdo_pgsql` + `pgsql` extensions, `ENABLE/FORCE ROW LEVEL SECURITY`, separate `awshortlink_owner`, `awshortlink_migrator`, `awshortlink_app`, `awshortlink_resolver`, and `awshortlink_backup` roles) and **PHP >= 8.3** under **Topology A** (dedicated `/buka/` front controller with private app root outside webroot) or **Topology C** (reverse-proxied dedicated host).
2. **Staging & Production Cutover (`#24`–`#26`, `#43`, Gate 15)** remain strictly **NO-GO** until the hosting operator executes the verification queries below and signs `HOST-01..17`.

### Operator PostgreSQL & RLS Capability Probe (run via `psql` or pgAdmin)
~~~sql
-- 1. Verify PostgreSQL version (>= 17 recommended; >= 15 required for security_invoker views)
SELECT version(), current_setting('server_version_num')::int AS version_num;

-- 2. Verify current operator privileges to create schema, roles, and RLS policies
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
FROM pg_roles WHERE rolname = current_user;

-- 3. Verify TLS status on active connection
SELECT ssl, version AS tls_version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();

-- 4. Verify connection limit budget
SELECT current_setting('max_connections')::int AS max_connections,
       count(*) AS active_connections FROM pg_stat_activity;
~~~

### Operator PHP Runtime Probe (run via panel PHP CLI — never leave in public webroot)
~~~bash
php -r '
$required = ["pdo", "pdo_pgsql", "pgsql", "mbstring", "openssl", "intl", "ctype", "json", "hash", "gd"];
$missing = array_filter($required, fn($ext) => !extension_loaded($ext));
echo "PHP_VERSION=" . PHP_VERSION . PHP_EOL;
echo "MISSING_EXT=" . (empty($missing) ? "NONE" : implode(",", $missing)) . PHP_EOL;
'
~~~
