# ADR-0004 — SUPERSEDED 2026-10-31

> Historical proposal only. **Superseded by [ADR-0005: PostgreSQL only and mandatory RLS](0005-postgresql-only-and-mandatory-rls.md).** Do not implement any MySQL/MariaDB/SQLite runtime, migration or integration alternatives.

# ADR-0004: Production DB selected from verified host; no SQLite integration shortcut

**Status:** Proposed | **Date:** 2026-10-31

## Context
No SSH and unknown hosting restrict runtime and DB availability. AWCMS-One is PostgreSQL-centric; this application is Laravel-native, and may deploy on MariaDB/MySQL or PostgreSQL.

## Proposed decision
- Select engine/version after HOST-03 audit; target one production DB for initial deployment. Never insist on PostgreSQL if hosting only permits supported MySQL/MariaDB.
- Use Laravel migrations and Eloquent portable SQL; engine-specific features only after ADR and tests; no production SQLite.
- On MySQL/MariaDB enforce RBAC/ABAC and per-unit scoping in app/service plus negative integration tests; do not claim DB RLS.
- On PostgreSQL RLS is optional hardening under tested per-request tenant scope; application authorization still mandatory.
- Production-equivalent integration environment replicates actual DB engine/version/charset/time zone; document backup consistency and migration rollback constraints.

## Consequences
Portable code with possible feature tradeoffs; additional CI matrix as DB engines expand. Host DB privileges and migration access are hard blockers, not implementation details. Decision locked at Gate 9.
