# Access Control Matrix — v1.1.0-draft (Workflow 6 / SPEC-06)

**Approach:** managed user/admin RBAC and ABAC modules, Laravel Auth/Policies/Gates, scoped unit membership (`shortlink.unit_closure`, `DES-002`) and mandatory PostgreSQL RLS (`RLS-001..022`) for private/IAM data. Deny by default. SQL database roles (`awshortlink_owner`, `awshortlink_migrator`, `awshortlink_app`, `awshortlink_resolver`, `awshortlink_backup`) are distinct from product roles; transaction-local context is derived from authenticated server identity.

## Roles
- **SA (`platform_owner`)**: System/Platform Owner (protected role, dual-control required, cannot delete last active owner).
- **AD (`org_admin`)**: Central Admin (global mandate for link, unit, and user operations within delegation ceiling).
- **UA (`unit_admin`)**: Unit Admin (Division/Branch owner; scoped to `unit_descendants`).
- **ED (`editor`)**: Program/Unit Editor (creates/updates drafts, views own link analytics per `DES-004`).
- **AP (`approver`)**: Link Approver (reviews/approves/suspends destinations in scope, subject to `POL-LINK-SOD` per `DES-009`).
- **AN (`analyst`)**: Campaign/Program Analyst (reads/exports aggregate metrics with $k=10$ suppression per `DES-005`).
- **AU (`auditor`)**: Internal/Security Auditor (read-only access to hash-chained audit logs and effective access inspector).
- **US (`authenticated_user`)**: Baseline authenticated staff workspace (`UI-018` profile, MFA, own sessions).
- **PB (`public_anonymous`)**: Anonymous citizen/QR scanner (`GET|HEAD /buka/{slug}` only).

## Complete Permission Catalog & Role Matrix (`PERM-001..062`)
Source-controlled in `config/permissions.php` and seeded into `TBL-007 permissions`. Legend: **G** = Global; **U** = Unit / `unit_descendants`; **O** = Own resource in unit; **S** = Self only; **D** = Delegated only; **N** = Denied.

| PERM ID | Permission Key (`resource.action`) | Risk | SA | AD | UA | ED | AP | AN | AU | US | PB |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **PERM-001** | `links.read_public` | low | G | G | G | G | G | G | G | G | Public |
| **PERM-002** | `links.list_internal` | low | G | G | U | U | U | U | G/U | O | N |
| **PERM-003** | `links.create_draft` | low | G | G | U | U | N | N | N | N | N |
| **PERM-004** | `links.update_draft` | low | G | G | U | O | N | N | N | N | N |
| **PERM-005** | `links.submit` | low | G | G | U | O | N | N | N | N | N |
| **PERM-006** | `links.approve` | high | G | G | D (P1) | N | U | N | N | N | N |
| **PERM-007** | `links.reject` | medium | G | G | D (P1) | N | U | N | N | N | N |
| **PERM-008** | `links.suspend` | high | G | G | D | N | U | N | N | N | N |
| **PERM-009** | `links.reinstate` | high | G | G | N | N | U | N | N | N | N |
| **PERM-010** | `links.archive` | medium | G | G | U | N | N | N | N | N | N |
| **PERM-011** | `links.export` | medium | G | G | U | N | N | U | G/U | N | N |
| **PERM-012** | `destinations.propose` | medium | G | G | U | O | N | N | N | N | N |
| **PERM-013** | `destinations.view_history` | low | G | G | U | O | U | N | G/U | N | N |
| **PERM-014** | `destinations.rollback` | high | G | G | N | N | U | N | N | N | N |
| **PERM-015** | `qr.generate_public` | low | G | G | U | N | U | U | N | N | Published |
| **PERM-016** | `qr.generate_draft` | low | G | G | U | O* | U | N | N | N | N |
| **PERM-017** | `analytics.view` | low | G | G | U | O (`DES-004`) | U | G/U | G/U | N | N |
| **PERM-018** | `analytics.export` | medium | G | G | U | N | N | G/U | N | N | N |
| **PERM-019** | `campaigns.read` | low | G | G | U | U | U | G/U | G/U | N | N |
| **PERM-020** | `campaigns.create` | low | G | G | U | N | N | U | N | N | N |
| **PERM-021** | `campaigns.update` | low | G | G | U | N | N | U | N | N | N |
| **PERM-022** | `campaigns.archive` | medium | G | G | U | N | N | N | N | N | N |
| **PERM-023** | `audit.view` | medium | G | G | U | N | U | N | G/U | N | N |
| **PERM-024** | `audit.verify_chain` | medium | G | G | N | N | N | N | G | N | N |
| **PERM-025** | `audit.export` | high | G | N | N | N | N | N | G | N | N |
| **PERM-026** | `users.read` | medium | G | G | U | N | N | N | G/U | S | N |
| **PERM-027** | `users.invite` | medium | G | G | U | N | N | N | N | N | N |
| **PERM-028** | `users.update` | medium | G | G | U | N | N | N | N | S (profile) | N |
| **PERM-029** | `users.suspend` | high | G | G | U | N | N | N | N | N | N |
| **PERM-030** | `users.disable` | critical | G | G | N | N | N | N | N | N | N |
| **PERM-031** | `users.revoke_sessions` | high | G | G | U | N | N | N | N | S | N |
| **PERM-032** | `units.read` | low | G | G | U | U | U | G/U | G/U | S | N |
| **PERM-033** | `units.create` | high | G | G | N | N | N | N | N | N | N |
| **PERM-034** | `units.update` | medium | G | G | U (own) | N | N | N | N | N | N |
| **PERM-035** | `units.move` | critical | G | G | N | N | N | N | N | N | N |
| **PERM-036** | `units.memberships.manage` | high | G | G | U | N | N | N | N | N | N |
| **PERM-037** | `roles.read` | low | G | G | U | N | N | N | G | S | N |
| **PERM-038** | `roles.create` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-039** | `roles.update` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-040** | `roles.archive` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-041** | `roles.permissions.update` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-042** | `permissions.read` | low | G | G | U | N | N | N | G | S | N |
| **PERM-043** | `user_roles.assign` | high | G | G (ceiling) | U (normal) | N | N | N | N | N | N |
| **PERM-044** | `user_roles.revoke` | high | G | G (ceiling) | U (normal) | N | N | N | N | N | N |
| **PERM-045** | `user_roles.approve_request` | critical | G | G (non-self) | N | N | N | N | N | N | N |
| **PERM-046** | `policies.read` | medium | G | G | N | N | N | N | G | N | N |
| **PERM-047** | `policies.create` | high | G | G | N | N | N | N | N | N | N |
| **PERM-048** | `policies.simulate` | medium | G | G | N | N | N | N | G | N | N |
| **PERM-049** | `policies.submit` | high | G | G | N | N | N | N | N | N | N |
| **PERM-050** | `policies.publish` | critical | G (non-author) | N | N | N | N | N | N | N | N |
| **PERM-051** | `policies.rollback` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-052** | `access.inspect` | medium | G | G | U | N | N | N | G/U | S | N |
| **PERM-053** | `api_keys.manage_own` | medium | S | S | S | N | N | S | N | S | N |
| **PERM-054** | `api_keys.manage_scoped` | high | G | G | N | N | N | N | N | N | N |
| **PERM-055** | `settings.security` | critical | G | N | N | N | N | N | N | N | N |
| **PERM-056** | `settings.domain_rules.manage` | high | G | G (`DES-014`) | N | N | N | N | N | N | N |
| **PERM-057** | `ops.health.view` | medium | G | G | N | N | N | N | G | N | N |
| **PERM-058** | `csv.import` (P1 `#29`) | medium | G | G | U | N | N | N | N | N | N |
| **PERM-059** | `csv.export` (P1 `#29`) | medium | G | G | U | N | N | U | N | N | N |
| **PERM-060** | `health_checks.run` (P1 `#31`) | medium | G | G | N | N | N | N | N | N | N |
| **PERM-061** | `abuse_reports.triage` (P1 `#34`) | high | G | G | N | N | U | N | G | N | N |
| **PERM-062** | `workspace.self.manage` | low | S | S | S | S | S | S | S | S | N |

*\* Draft QR (`qr.generate_draft`) is watermarked (`DRAF — BELUM AKTIF`) and prohibited from public publication.*
*\*\* Editor analytics access (`PERM-017` / `DES-004`) is locked to own links within assigned unit in [ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md).*

## ABAC attributes
Required: actor.id, role, active session/MFA status, scope.unit_ids, resource.unit_id, resource.status, resource.creator_id, target.risk_level, action, pending_approval.actor_id, credential.scopes. For high-risk target approval: approver != creator unless emergency multi-approval exception recorded.

## Authorization rules
- Deny by default; evaluate action + ownership + status + risk + scope in controller AND service; scoping on every nested resource and export.
- Laravel Filament Resource query must scope records, but **also enforce Policies** on route actions, bulk operations, relation managers, metrics and downloads. Never rely on hidden sidebar.
- API credentials: hash at rest, one-time display, scope-per-operation, expiry, rotation/revoke, optional IP policy when appropriate, bounded rate limit; unauthorized actions return consistent 403/404 without existence leakage.
- Public routes may access only published safe fields; never return private target history, audit notes, approver, account, secrets.
- All mutations: actor, authorization verdict, version match, append-only audit in same transaction, return 409 on stale version.

## Mandatory negative tests
1. ED unit A reads/modifies/deletes link unit B by ID/slug.
2. AU reads approved audit only, attempts create/edit/approve and API mutations.
3. AP attempts self-approval on new external destination with high risk.
4. UA exports campaign stats from another unit or scopes a bulk op to all rows.
5. Revoked API token accesses endpoints; session expires; MFA-required operation without MFA.
6. PB hits Filament admin or unpublished QR routes.
7. Inactive account, altered unit membership or soft-deleted link remains blocked.

## Compatibility
PostgreSQL is the ONLY database. RLS must be enabled and enforced on scoped private and IAM tables with USING/WITH CHECK and deny-default; trusted transaction-local context and non-owner/no BYPASSRLS runtime identity. Policies/Gates+ABAC remain essential. Validate direct SQL, API, Filament, jobs and exports against unit A/B and no-context. Security owner signs matrix at Gate 9.


## Managed administration for admin and user levels
Filament protected screens UI-011..018: Users (invite/disable/revoke sessions), Roles, Permission Matrix, Role Assignment (unit/descendant/global/owned scopes with expiry), ABAC Policy Builder (restricted declarative JSON and operator allowlist, version/simulation/dual-approval), Effective Access Inspector and Unit Hierarchy. No arbitrary SQL/PHP scripting or manual privileges beyond grantor ceiling. Global application admin is NEVER PostgreSQL BYPASSRLS. Sensitive role grants and rules require independent approval and append-only audit. Effective decision = active identity AND RBAC grant AND ABAC predicate AND Laravel Policy AND PostgreSQL RLS. See identity-rbac-abac.md.
