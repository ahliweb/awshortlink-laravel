# ADR-0006: Managed RBAC + ABAC for admin and authenticated users

**Status:** Accepted (Gate 9 Approved 2026-11-01).

## Decision
Admin must manage users, roles, permissions, unit assignments, delegated privileges and versioned ABAC policies using protected Filament workflows. User workspace receives effective scope from verified account. RBAC (what action), ABAC (when/whose/under which conditions), Laravel Policies/Gates (service enforcement) and PostgreSQL RLS (row isolation) are mandatory defense-in-depth checks. Anonymous public sees approved redirects only.

Sensitive role and policy changes use simulation, independent approval, versioning, rollback, audit and MFA; protected owner cannot be lost. Never expose arbitrary SQL/PHP ABAC rule code or use PostgreSQL BYPASSRLS as an app superadmin capability.

## Rejected alternatives
UI-only menu hiding, hard-coded one-off permission flags, user-supplied scope assertions, arbitrary executable ABAC, and DB superuser session for admin.

## Evidence
See docs/identity-rbac-abac.md, docs/access-control.md and docs/postgresql-rls-design.md; implement with UI-011..018, REQ-021..025 and TST-015..019. Keep implementation blocked until Gate 9.
