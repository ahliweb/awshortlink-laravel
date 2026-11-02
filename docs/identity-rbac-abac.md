# Identity, Admin/User Access Management, RBAC + ABAC
Version: v1.1.0-draft | Date: 2026-10-31 | Status: planned product module, NOT implemented.

## Binding requirement
The Laravel + Filament application itself MUST manage accounts, roles, permissions, organizational scope assignments, policy versions and effective authorization for **administrators and authenticated users**. These are first-class P0 features with management screens, REST contracts, audits and tests—not only hard-coded role strings or hidden navigation. Anonymous citizens using QR remain separate: they may resolve approved public links only, with no administration access. Do not imply live implementation until code and tests have shipped.

## Personas and boundaries
| Account level | Example | Entitlement |
| --- | --- | --- |
| Platform/system owner | trusted security administrator | provision protected global roles, policy approvals under dual-control; never DB superuser |
| Central admin | central IT | user/unit management and all-link administration within explicit mandate |
| Unit admin | Division or branch owner | maintain own unit members/links, scoped grants not exceeding delegation |
| Authenticated user | editor, approver, analyst, auditor | privileges and workspaces defined by effective role+attributes |
| Public anonymous | QR scanner | public redirect only, no user records |

One user identity table unless a documented reason for multiple auth guards. User may hold multiple roles assigned for specific units/time windows. Distinguish protected/system roles from ordinary custom roles and prevent deletion of the last valid owner.

## P0 admin and user management screens
- UI-011 User Management: invite, activate, suspend, revoke sessions, MFA status, user search/filter, unit membership and audit (no plaintext passwords).
- UI-012 Role Management: immutable key, label, protected default roles, clone/version, active/inactive, reviewed change; protected superadmin not self-assigned.
- UI-013 Permission Matrix: source-controlled resource.action catalog; view role-to-permission differences; grant/revoke within grantor ceiling; no arbitrary application permission string creation that lacks enforcement.
- UI-014 ABAC Policy Manager: safe rule builder using predefined operators/attributes, no executable PHP/SQL; simulate, compare, submit, independent approve, activate, rollback and audit immutable policy version.
- UI-015 User Role Assignment: grant/revoke role on global/unit/descendant/owned-resource scope with valid_from/valid_until, reason and approver.
- UI-016 Effective Access Inspector: explain allow/deny by actor, role, unit, resource, action, current policy version without leaking restricted data.
- UI-017 Unit Hierarchy & Membership: structure, assignments, delegation windows, controlled transfers and revocation.
- UI-018 User Workspace/Profile: view own grants, update MFA/session, create and track own authorized links, no privilege editing.

All screens require 360px-friendly layout, WCAG 2.2 AA keyboard states, validation/empty/conflict/denied/loading, direct URL/API bypass tests and UI mock-based validation at Gate 4.

## Roles and permission catalog
Default roles: platform_owner, org_admin, unit_admin, editor, approver, analyst, auditor, authenticated_user. Public guest is not a privileged role. Permissions use resource.action syntax, e.g. users.read/users.invite/users.disable, roles.read/roles.create/roles.permissions.update, user_roles.assign/user_roles.revoke, policies.read/policies.create/policies.simulate/policies.publish, access.inspect, links.create_draft/links.approve/links.suspend, analytics.view, audit.view. Catalog declared in version-controlled code with migration/seeder consistency; administrators manage allowed assignments and approved policy versions.

## ABAC attributes and decision algorithm
Actor: identity, account state, verified MFA, active unit memberships, approved delegated scope. Resource: owner/unit, sensitivity, destination risk, lifecycle/status, author. Action: read/create/edit/approve/export/revoke/publish. Environment: verified current time, trusted session and institutional emergency state. No authorization from user-controlled role claims, forwarded headers or arbitrary client-supplied unit IDs.
**ALLOW only when:** active authenticated actor, a matching RBAC permission, valid ABAC constraints, Laravel Policy/Gate, and PostgreSQL RLS row scope all permit. DENY by default; API bearer scopes can narrow but cannot elevate rights. Public redirect follows separate explicit published-only access.

ABAC policy version lifecycle: draft -> simulate -> submit -> independently review -> approved -> active -> superseded/revoked; optimistic version checks, test vectors, revert to previously approved version and transactional append-only audit. No arbitrarily executable policy scripts. Never permit user editing their own permissions or approving their own high-risk access grant.

## At least five example scenarios
1. Editor in Branch A creates a draft only within A; B is denied, including guessed resource IDs.
2. Unit administrator invites a user for their branch but cannot grant org_admin role or policies.publish.
3. Central admin can disable a compromised user and revoke their sessions; change audited with reason and review.
4. Approver may approve a low-risk published target within assigned scope; cannot self-approve a high-risk target authored by them.
5. Analyst can read aggregate click reports for assigned units, not raw audit events or user records.
6. Auditor can inspect approved immutable audit events only; cannot modify a link, role or ABAC version.
7. Time-bound role stops working after validity expiry even if the browser session is still active.
8. Security owner simulates a policy change and obtains independent approval before publication.

## Canonical new tables (PostgreSQL only)
users (existing Laravel auth table adapted), units, user_unit_memberships, roles, permissions, role_permissions, user_role_assignments, abac_policy_definitions, abac_policy_versions (JSONB rules validated by schema), abac_policy_approvals, access_change_requests, access_decision_audit. Restrict FKs and privilege deletion, unique role/permission keys, explicit indexes, assignment validity checks and audit version hashes. Sensitive IAM tables have RLS SELECT/INSERT/UPDATE/DELETE with scoped policies; runtime never BYPASSRLS. Access decisions cannot be based on UI visibility alone.

## Security/integrity guarantees
- Nontechnical roles may assign only grantable permissions within their own delegated ceiling; global privilege changes require protected approval and MFA.
- No privilege escalation, self-approval, excessive delegation, implicit role inheritance or silent permission expansion.
- Apply change+audit in transaction; optimistic version and 409 on stale write; revoke tokens/sessions when access is withdrawn.
- Explain decision without exposing another unit's personal data. All privileged writes audited with actor, target, change, reason, policy version, approver, timestamp; no passwords or secrets logged.
- Tested against PostgreSQL actual RLS context; app users are not PostgreSQL users. Enforce in Filament, HTTP API, exports, jobs, resources and SQL.

## Contract and acceptance
OpenAPI adds role/user/permission/policy/assignment management and policy simulation with x-permission per endpoint, refusal/409 conflict examples. TST-015 user/role assignment and privilege ceilings; TST-016 ABAC version/simulation+approval; TST-017 RLS cross-unit and SQL access; TST-018 pooling context leakage; TST-019 privileged revoke/break-glass audit. Hosting, institutional security owner and product owner must approve role semantics at Gate 9.

## Locked IAM & Session Baseline ([ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md))
- **DES-002 (Unit Hierarchy):** Closure table `shortlink.unit_closure(ancestor_id, descendant_id, depth)` (`TBL-002`, `RLS-002`).
- **DES-004 (Editor Analytics):** Editors hold `analytics.view` (`PERM-017`) restricted to links they authored/own within their active unit scope.
- **DES-006 (MFA Policy):** TOTP (RFC 6238) mandatory for all staff accounts upon invitation acceptance; WebAuthn optional. Step-up MFA check enforced by `POL-PRIV-MFA` for `users.disable`, `user_roles.assign`, `roles.permissions.update`, `policies.publish`, and `links.suspend`.
- **DES-009 (P0 Link Publication Approval):** Role-based `links.approve` (`PERM-006`) combined with mandatory ABAC policy `POL-LINK-SOD` (`actor.id != resource.creator_id` when `resource.risk_class IN ('medium', 'high')`).
- **DES-012 (Session Lifetimes):** 30 minutes idle timeout, 8 hours absolute session expiry, cookie scoped to `/buka` (`Secure; HttpOnly; SameSite=Lax`), rotated on login and privilege change.

References:
- https://laravel.com/docs/13.x/authorization
- https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- https://www.postgresql.org/docs/current/ddl-rowsecurity.html
