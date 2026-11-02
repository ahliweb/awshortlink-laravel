# ADR-0005: PostgreSQL as only database; mandatory Row-Level Security

**Status:** Accepted (Gate 9 Approved 2026-11-01); production host verification tracked at Gate 15 (#25/#43).  
**Supersedes:** ADR-0004 portability decision.

## Context
The user has selected PostgreSQL exclusively, replacing the prior MySQL/MariaDB or PostgreSQL option. PostgreSQL provides native Row-Level Security, which complements RBAC/ABAC for authenticated staff with multiple organizational units.

## Decision
PostgreSQL is the only DB for dev, tests, staging, and production; migrations, backup and test suites must be PostgreSQL-specific. Runtime uses non-owner, non-superuser, non-BYPASSRLS role; sensitive unit and IAM tables use RLS. SQL GRANT and app authorization are separate. Set trusted actor+unit context transaction-locally and verify safe pooled connections. Public shortlink resolver is isolated under minimal published-only privileges. Migration and backup use separate operator credentials.

## Consequences
Hosting that cannot provide PostgreSQL/pgsql extensions/DDL role permissions is NO-GO, not a reason to downgrade. No-SSH operator must provide safe PostgreSQL migration and restore. Require RLS coverage, negative cross-unit tests, transaction scope leak tests, migration checks and owner signoff.

## References
See docs/postgresql-rls-design.md; https://www.postgresql.org/docs/current/ddl-rowsecurity.html ; https://laravel.com/docs/13.x/database .
