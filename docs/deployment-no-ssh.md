# Production Deployment Without SSH — Runbook v1.0.0 (Gate 15 Approved 2026-11-01)

**Status:** Gate 15 Approved (`DEC-021`). Release artifact built via `bash scripts/build-artifact.sh`, backup/restore rehearsed via `bash scripts/rehearse-backup-restore.sh`, and post-deployment synthetic verification automated via `bash scripts/post-deploy-verify.sh`.

## Decision tree
1. Is PHP version/extensions compatible (including **pdo_pgsql** and **pgsql**), HTTPS and **PostgreSQL** present? **No -> stop** and request host upgrade/approved alternative.
2. Can host map only /buka/* to Laravel public/index.php while preserving parent website? **No -> stop**; request reverse proxy/location rule from operator; don't overwrite parent routes.
3. Can private app directory sit OUTSIDE webroot, with writable storage and bootstrap/cache? **No -> stop**; never publish .env, vendor, source.
4. Is there safe PostgreSQL migration, RLS policy DDL and role provisioning with operator-managed CLI/host tools? **No -> require reviewed PostgreSQL SQL plus pgAdmin/psql/provider DB console and Laravel migration-state reconciliation**, or choose approved host. Never create public artisan endpoint.
5. Is cron available? **No -> defer scheduler-dependent P1**, but expiration/suspension enforced synchronously.
6. Prove Livewire update/script endpoints under /buka/ and admin session cookie path+SameSite+Secure without collisions.

## Proposed directories (paths vary by host)
~~~text
/home/ACCOUNT/awshortlink/releases/2026xxxx-<hash>/  Laravel private app
/home/ACCOUNT/awshortlink/shared/.env           secret outside release/webroot
/home/ACCOUNT/awshortlink/shared/storage/        durable writable storage
/home/ACCOUNT/public_html/buka/                 ONLY public/index.php + built public assets
~~~
If symlinks or atomic renames are not permitted, use a documented maintenance-window staged copy + checksum/manifest verification and backout. Private release path in index.php must be environment-specific and protected. Never assume a static Laravel public directory can be uploaded wholesale without path rewriting and Livewire verification.

## Trusted local/CI preparation
- composer install --no-dev --prefer-dist --optimize-autoloader with locked composer.lock; run composer audit and check platform requirements for *production PHP*.
- npm ci and npm run build only on trusted build environment; include public/build manifest and Filament assets compatible with chosen versions.
- Run unit/feature/integration tests **only with PostgreSQL** (production-equivalent version, mandatory RLS and least-privilege DB roles) and test HTTPS path prefix; static analysis, dependency scan, licenses and SBOM.
- Build release tar/zip containing app, vendor, compiled assets and manifest SHA256; exclude .env, logs, tests with sensitive fixtures, node_modules, dev secrets, deploy credentials. Generate and record artifact checksum.
- Never bake local config cache with local secrets/paths into production artifact. Optimize caches only in production-safe controlled step or leave uncached.

## Operator-assisted installation (no SSH)
1. Backup parent website .htaccess/vhost config, existing /buka path, DB and accessible files. Establish restore owner.
2. Upload release to nonpublic directory with File Manager or secure SFTP/FTPS; verify checksum and permissions. Place production .env in private shared path.
3. Confirm index.php autoload and bootstrap absolute paths, secure config, APP_KEY generated once by trusted operator and preserved across updates. APP_DEBUG=false, APP_ENV=production, APP_URL canonical origin with /buka prefix consideration.
4. Establish operator-owned /buka/* path dispatch; ensure **all** Laravel routes and assets (including Livewire endpoints) work. Verify domain host header, trusted proxy, session scope and CSRF behavior.
5. Apply approved PostgreSQL migrations, roles and RLS policy DDL with sanctioned operator CLI OR versioned SQL through pgAdmin/psql/provider console. Record each Laravel migration state, checksums, schema history and backup; compare actual schema after apply. Do not pretend manual SQL == artisan success without reconciliation.
6. Manually provision first central admin securely via controlled offline/admin procedure; no publicly reachable setup wizard.
7. Smoke test /buka/, valid slug, nonexistent/expired/suspended, admin MFA, Filament/Livewire, QR download, analytics degradation, health probe, parent website routes and security probes for .env/vendor/storage/artisan.
8. Update version/manifest and routing; capture human sign-off, synthetic monitoring and incident contacts. Keep previous release and DB restoration procedure.

## Upgrade and rollback
- Every release keeps change list, git tag, locked dependency version, artifact hash, DB migration checksum, deploy time/owner and previous release.
- Prefer additive expand/contract migrations; app rollback alone **cannot** undo destructive schema change safely. Restore DB from verified backup only after incident manager approves data-loss consequences and RPO.
- On broken redirect, restore previous /buka route mapping and package, verify existing website path, test 5 links + 404 + admin, announce incident.
- No unauthenticated HTTP setup, queue, cron, migrate or cache-clear endpoints. If production cannot execute required maintenance securely, stop deployment.

## Cron and queue contingencies
If panel supports Cron with PHP CLI, scheduler entry with exact verified PHP path; run DB-backed queue worker with --stop-when-empty and timeout through scheduled bounded command, overlap lock and observability. Avoid perpetual worker/daemon/supervisor requirement. No cron -> no automatic link health checks, delayed exports, cleanup/retention claims. Critical link expiry/suspension checked on GET path.

## Evidence required
HOST-01..14 record, artifacts & checksum, staged screenshots, security scans, test results, DB schema diff, approved operator identity and rollback rehearsal. See hosting-audit.md.


## Mandatory PostgreSQL production gate
Never deploy with MySQL/MariaDB/SQLite. Validate pdo_pgsql PHP, supported patched PostgreSQL, network/TLS, app role not owner/no BYPASSRLS, schema owner and migration credentials separated, policy enable/force, public resolver DB rights and full pg_dump/pg_restore (or provider backup) with restored grants/policies verified. Any data migration via SQL console must reconcile Laravel migrations table and checksums. Without SSH, involve approved hosting operator; NEVER publish a web-based migration/admin-tool execution route. Test RLS context (transaction-only) when pooled connections reused; no leakage between admin/user requests. First admin must be provisioned under institutional approval and MFA; role changes use protected workflow and audit. See postgresql-rls-design.md.
