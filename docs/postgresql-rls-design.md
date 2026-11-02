# PostgreSQL-Only Database Architecture and Mandatory RLS
Version: v1.1.0-draft | Date: 2026-10-31 | Status: proposed implementation, product direction confirmed; Gate 9 approval and hosting validation pending.

## Binding decision
**PostgreSQL is the sole supported database in local development, automated tests, staging and production.** MySQL, MariaDB, SQLite and mixed-driver fallback are explicitly out of scope. All database migrations, fixtures, CI integration, backup scripts and production deployments must target PostgreSQL. Laravel 13 uses the pgsql driver with PHP pdo_pgsql/pgsql. Prefer maintained, security-patched PostgreSQL 18 or 17 depending on approved provider; actual version must be pinned and recorded after hosting audit. Never assume production PostgreSQL is available just because a hosting panel exists.

### Mandatory host gate
- PostgreSQL service version, DB ownership, supported extensions, pdo_pgsql/pgsql, database reachability, TLS certificate verification for remote connections, privileges for migration policy DDL, runtime connection limit, backup/restore, and operator intervention without developer SSH.
- If PostgreSQL cannot be provisioned, **NO-GO** until an authorized PostgreSQL/hosting change; do not silently downgrade.
- Separate database credentials: schema owner/migration role (operator-only, not used for requests), runtime role (LOGIN, no superuser, no BYPASSRLS, no table ownership or schema DDL), optional separate read-only public resolver role and backup role. Do not use Laravel's DB superuser credentials to serve requests.
- Use a direct DB connection for migration, backup and DDL, even if runtime has a transaction pooler. Laravel 13 supports pooled and direct PostgreSQL connections; validate deployment's exact compatibility.

## Data controls
Private unit-scoped tables: links, destinations, units and memberships, campaigns, approvals, QR metadata, analytics, audit, user role assignments, role/permission management tables, ABAC policies, policy approvals and user identity fields must have explicit table-level RLS or stronger equivalent isolations proven in the review matrix.
- ENABLE ROW LEVEL SECURITY; FORCE ROW LEVEL SECURITY where applicable so owner-level accidental access is also constrained. Runtime is never table owner or BYPASSRLS.
- Define SELECT/INSERT/UPDATE/DELETE policies separately and implement USING for existing rows, WITH CHECK for inserted/new row values; keep default-deny behavior when no actor context is present. GRANT SQL permissions separately; an RLS policy never confers SQL privileges by itself.
- Roles in PostgreSQL are **not** app-level RBAC roles. App global admin is a validated permission/scope, never a database superuser or BYPASSRLS shortcut. Guard wide-scope access via signed-off policy design.
- Public resolver cannot impersonate an admin. Provide narrowly scoped read-only PostgreSQL access to sanitized current approved public redirect data through a least-privilege role / invoker view and policy. Do not allow a public database identity access to private audit, user, draft and unapproved destination records.
- App authorization remains mandatory through Laravel Auth, Policies/Gates, RBAC + ABAC; RLS is a second independent DB-level boundary.

## Transaction-local request context
An authenticated request resolves actor identity and unit membership **server-side**, then begins a database transaction, establishes a validated transaction-local context, performs all protected queries inside that transaction, commits/rolls back and closes context. Public resolution uses a separate narrow public policy. Never use a persistent session SET across pooled/reused connections. Example only (not a complete migration):
~~~sql
BEGIN;
SELECT set_config('app.actor_id', :trusted_actor_id, true);
SELECT set_config('app.unit_id', :verified_unit_id, true);
SELECT id, slug_normalized FROM links WHERE unit_id = :verified_unit_id;
COMMIT;
~~~
Read policy context with current_setting('app.unit_id', true); missing or invalid context MUST DENY, not fall back to all units. Parameterize SQL and cast carefully. Test PgBouncer transaction pooling and context reset on failure. A compromised SQL execution context can still forge claims; prevent injection, require least privilege and never pretend RLS alone solves arbitrary SQL execution.

### Illustrative RLS policy (locked ID types & helper functions per ADR-0007)
Primary keys use `uuid` (UUIDv7) for domain/IAM tables and `bigint` for audit tables (`DES-001`); organizational hierarchy uses `shortlink.unit_closure` (`DES-002`), expanded once per transaction into `app.unit_ids`:
~~~sql
ALTER TABLE shortlink.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE shortlink.links FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_014_links_select ON shortlink.links FOR SELECT TO awshortlink_app
  USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());

CREATE POLICY rls_014_links_insert ON shortlink.links FOR INSERT TO awshortlink_app
  WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
              AND creator_id = shortlink.ctx_actor());

CREATE POLICY rls_014_links_update ON shortlink.links FOR UPDATE TO awshortlink_app
  USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
  WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());

CREATE POLICY rls_014_links_resolver ON shortlink.links FOR SELECT TO awshortlink_resolver
  USING (published_at IS NOT NULL);
~~~
Superadmin (`platform_owner` / `org_admin`) is **never** a database superuser or `BYPASSRLS` role; `shortlink.ctx_is_global()` evaluates `current_setting('app.scope', true) = 'global' AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL`, which the application sets transaction-locally only after verifying an active global RBAC+ABAC grant. Avoid recursive policy queries or `SECURITY DEFINER` helpers with unsafe `search_path`. The only `SECURITY DEFINER` function is `shortlink.record_click(uuid, smallint)` (`SET search_path = shortlink, pg_temp`, owned by `awshortlink_owner`) to allow `awshortlink_resolver` to increment `link_daily_stats` without direct table write privileges (`DES-011`).

## Canonical RLS Policy Catalog (`RLS-001..022`)
| Policy ID | Target Table (`TBL-*`) | `awshortlink_app` SELECT (`USING`) | `awshortlink_app` INSERT (`WITH CHECK`) | `awshortlink_app` UPDATE (`USING` / `WITH CHECK`) | `awshortlink_app` DELETE | `awshortlink_resolver` |
| --- | --- | --- | --- | --- | --- | --- |
| **RLS-001** | `TBL-001 units` | `id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `ctx_is_global()` | `ctx_is_global()` | Denied | Denied |
| **RLS-002** | `TBL-002 unit_closure` | `ancestor_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `ctx_is_global()` | Denied | `ctx_is_global()` (move unit) | Denied |
| **RLS-003** | `TBL-003 users` | `id = ctx_actor() OR ctx_is_global() OR EXISTS (membership in ctx_unit_ids())` | `ctx_is_global() OR ctx_unit_ids() <> '{}'` | `id = ctx_actor() OR ctx_is_global() OR unit_admin scope` | Denied | Denied |
| **RLS-004** | `TBL-004 sessions` | `user_id = ctx_actor() OR ctx_is_global()` | `user_id = ctx_actor()` | `user_id = ctx_actor()` | `user_id = ctx_actor() OR ctx_is_global()` | Denied |
| **RLS-005** | `TBL-005 user_unit_memberships` | `user_id = ctx_actor() OR unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND created_by = ctx_actor() AND user_id <> ctx_actor()` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | Denied | Denied |
| **RLS-006** | `TBL-006 roles` | `ctx_actor() IS NOT NULL` | `ctx_is_global()` | `ctx_is_global() AND NOT is_protected` | Denied | Denied |
| **RLS-007** | `TBL-007 permissions` | `ctx_actor() IS NOT NULL` | Migrator only | Migrator only | Denied | Denied |
| **RLS-008** | `TBL-008 role_permissions` | `ctx_actor() IS NOT NULL` | `ctx_is_global() AND granted_by = ctx_actor()` | Denied | `ctx_is_global()` | Denied |
| **RLS-009** | `TBL-009 user_role_assignments` | `user_id = ctx_actor() OR unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND granted_by = ctx_actor() AND user_id <> ctx_actor()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global())` (revocation cols) | Denied | Denied |
| **RLS-010** | `TBL-010 abac_policy_definitions` | `ctx_actor() IS NOT NULL` | `ctx_is_global()` | `ctx_is_global()` | Denied | Denied |
| **RLS-011** | `TBL-011 abac_policy_versions` | `ctx_actor() IS NOT NULL` | `ctx_is_global() AND authored_by = ctx_actor()` | `ctx_is_global()` (status transitions only) | Denied | Denied |
| **RLS-012** | `TBL-012 abac_policy_approvals` | `ctx_is_global()` | `ctx_is_global() AND actor_id = ctx_actor()` (append-only) | Denied | Denied | Denied |
| **RLS-013** | `TBL-013 access_change_requests` | `requested_by = ctx_actor() OR target_user_id = ctx_actor() OR unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND requested_by = ctx_actor()` | `ctx_is_global()` (approval decision cols) | Denied | Denied |
| **RLS-014** | `TBL-014 links` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND creator_id = ctx_actor()` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | Denied | `SELECT WHERE published_at IS NOT NULL` |
| **RLS-015** | `TBL-015 link_destinations` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND proposed_by = ctx_actor()` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | Denied | Via `public_resolvable_links` view (`status = 'current'`) |
| **RLS-016** | `TBL-016 reserved_slugs` | `ctx_actor() IS NOT NULL` | `ctx_actor() IS NOT NULL` | Denied | `reason = 'draft'` only | Denied |
| **RLS-017** | `TBL-017 destination_domain_rules` | `ctx_actor() IS NOT NULL` | `ctx_is_global()` | `ctx_is_global()` | Denied | Denied |
| **RLS-018** | `TBL-018 link_approvals` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `(unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()) AND actor_id = ctx_actor()` | Denied | Denied | Denied |
| **RLS-019** | `TBL-019 link_audit_events` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | `ctx_actor() IS NOT NULL` (append-only) | Denied | Denied | Denied |
| **RLS-020** | `TBL-020 access_decision_audit` | `ctx_is_global()` | `ctx_actor() IS NOT NULL` (append-only) | Denied | Denied | Denied |
| **RLS-021** | `TBL-021 link_daily_stats` | `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()` | Via `shortlink.record_click()` only | Via `shortlink.record_click()` only | Denied | `EXECUTE ON FUNCTION shortlink.record_click` |
| **RLS-022** | `TBL-022 link_qr_assets`, `campaigns`, `api_credentials`, `app_settings`, `ops_heartbeats`, `abuse_reports` | Scoped by `unit_id = ANY(ctx_unit_ids())` (`qr`, `campaigns`), `owner_id = ctx_actor()` (`api_credentials`), or `ctx_is_global()` (`app_settings`, `ops_heartbeats`, `abuse_reports`) | Matching scope | Matching scope (`qr` immutable) | `api_credentials` revoke only | `abuse_reports` INSERT via rate-limited public form role |

## PostgreSQL schema expectations
Normalized slug UNIQUE(namespace, slug); permanent reservation of published slug; foreign keys, check constraints and indexes; UUID/JSONB optional where beneficial and reviewed; UTC timestamp storage; soft delete, optimistic version, transactional audit for privilege changes. See data-model.md and identity-rbac-abac.md. Migrator enforces RLS and policy definitions; CI validates pg_policies, relrowsecurity/relforcerowsecurity and pg_roles by introspection. Application connection does not permit DISABLE ROW LEVEL SECURITY.

## RLS/security test matrix (MUST pass)
1. Missing actor context selects zero private rows and rejects writes.
2. Unit A cannot SELECT, INSERT, UPDATE or DELETE Unit B's links, memberships, roles or policy versions; WITH CHECK denies changing unit_id.
3. Admin scope evaluated only by approved Laravel+ABAC and explicit RLS path; runtime DB role has no BYPASSRLS and is not owner.
4. Public resolver sees only published active sanitized target, no draft/private/user/approval or role tables.
5. Connection pooled between User A and User B does not reuse context; exception/rollback removes scope.
6. API, Filament lists/relation managers, background jobs, exports and raw Query Builder all get correct transaction-local scope.
7. Backup user can dump **all** authorized data (RLS must not silently omit rows), restore recovers grants and policies; verify row counts/tombstones/audit and restore tests.
8. Benchmark indexed lookup and RLS predicates under realistic institutional data and shared-host capacity.

## No-SSH PostgreSQL deployment
Prebuild Composer+assets elsewhere. Operator must provide approved PostgreSQL administration (pgAdmin/psql/managed DB console, or controlled PHP CLI migration mechanism) and enforce DDL and GRANT; phpMyAdmin is for MySQL, not PostgreSQL. Never expose artisan/migrate route on the public web. For backups use approved pg_dump/pg_restore or PostgreSQL provider backups with a separate management identity; restore rehearsal is mandatory. Check DB SSL and firewall between PHP hosting and DB. Hosting without PostgreSQL or RLS provisioning capability means deployment cannot proceed.

References:
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- https://www.postgresql.org/docs/current/sql-createpolicy.html
- https://laravel.com/docs/13.x/database
