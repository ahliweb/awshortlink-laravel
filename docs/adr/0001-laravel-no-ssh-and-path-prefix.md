# ADR-0001: Laravel modular monolith with no-SSH production artifact, mounted at /buka/

**Status: Accepted (Gate 9 Approved 2026-11-01)** | **Date:** 2026-10-31 | **Owner:** AW Shortlink product maintainers (project owner)

## Context
Initial deployment must coexist with an existing government website at https://links.example.org/ and expose short links at /buka/{slug}. Developers have no SSH access. AWCMS-One's Bun/Astro runtime is not suitable to install on unknown PHP-only hosting; only its design/governance lessons transfer.

## Decision proposed
- Laravel 13 and Filament 5 in one app with separate public resolver/admin/API routing and strict authorization.
- Trusted build machine installs Composer dependencies, compiles assets and validates release; production receives immutable package through secure file manager/SFTP/FTPS.
- Private code/secrets/storage outside public document root; /buka/ only contains front controller and compiled public assets. Host must support path-based routing, secure PHP dispatch, Livewire update route mapping and safe DB migrations.
- PostgreSQL exclusively selected; hosting must provide PostgreSQL or be NO-GO. No mandatory Redis, supervisor, Node/Bun or SSH in production.
- Direct redirect request never fetches external URL; cron-dependent features degrade gracefully.

## Rejected alternatives
- Deploy Bun/Astro/Cloudflare Workers as required stack: depends on unverified infrastructure and different runtime.
- Put entire Laravel repository in public_html/buka: leaks sensitive files.
- Public script to invoke artisan migrate or expose .env: critical vulnerability.
- 301 redirect for dynamic links: browser cache compromises revocation.

## Consequences / verification
+ Hosting-fit architecture when PHP/rewrites/private paths verified.
+ Simple low-cost operational model.
- Need rigorous packaging and operator-mediated schema migration.
- PHP version and route prefix remain hard gates; otherwise deploy elsewhere with approved reverse-proxy mapping.
- Filament/Livewire subpath integration must pass E2E.
- Preserve parent website routes; rollback documented and rehearsed.

## Decision record
Await Gate 9 approval with HOST-01...14 evidence; record approved variant, owner, date and tradeoffs before implementation.


> **Amendment 2026-10-31:** ADR-0005 replaces any previous alternative database choice: only PostgreSQL, with mandatory RLS. Laravel Admin/User IAM requires managed RBAC+ABAC per ADR-0006, and PostgreSQL operator-controlled migrations/backup despite no SSH. Host feasibility is a hard blocker, not reason to downgrade.
