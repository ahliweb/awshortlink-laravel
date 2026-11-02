# Data Model & Dictionary — v1.1.0-draft (Workflow 5 / SPEC-05)

**Target:** PostgreSQL ONLY in local, test, staging and production; no MySQL/MariaDB/SQLite ([ADR-0005](adr/0005-postgresql-only-and-mandatory-rls.md)). Primary keys locked in [ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md) (`DES-001`): **UUIDv7** for all domain/IAM aggregates, **`BIGINT GENERATED ALWAYS AS IDENTITY`** for hash-chained append-only audit tables. Organizational hierarchy uses a **closure table** (`shortlink.unit_closure`, `DES-002`). Normalized ASCII slug `[a-z0-9-]` (3..64 chars, `DES-013`) unique per namespace; UTC `timestamptz` stored, `Asia/Pontianak` (WIB) rendered in UI. Mandatory PostgreSQL RLS on all private and IAM tables.

## Logical ERD
~~~mermaid
erDiagram
    UNITS ||--o{ UNIT_CLOSURE : hierarchy
    UNITS ||--o{ LINKS : owns
    UNITS ||--o{ USER_UNIT_MEMBERSHIPS : scopes
    USERS ||--o{ USER_UNIT_MEMBERSHIPS : belongs_to
    USERS ||--o{ USER_ROLE_ASSIGNMENTS : holds
    ROLES ||--o{ USER_ROLE_ASSIGNMENTS : granted_in
    ROLES ||--o{ ROLE_PERMISSIONS : contains
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : cataloged_in
    ABAC_POLICY_DEFINITIONS ||--o{ ABAC_POLICY_VERSIONS : versions
    ABAC_POLICY_VERSIONS ||--o{ ABAC_POLICY_APPROVALS : reviewed_by
    USERS ||--o{ ACCESS_CHANGE_REQUESTS : requests
    USERS ||--o{ LINKS : authors
    LINKS ||--o{ LINK_DESTINATIONS : versions
    LINKS ||--o{ LINK_QR_ASSETS : renders
    LINKS ||--o{ LINK_DAILY_STATS : aggregates
    LINKS ||--o{ LINK_APPROVALS : workflows
    LINKS ||--o{ LINK_HEALTH_CHECKS : optional
    LINKS ||--o{ LINK_AUDIT_EVENTS : changes
    CAMPAIGNS ||--o{ LINKS : groups
    API_CREDENTIALS }o--|| USERS : owner
    RESERVED_SLUGS }o--|| LINKS : tombstone_optional
~~~

## Complete Table & Classification Catalog (`TBL-001..022`)
Every table in schema `shortlink` has an assigned `TBL-*` identifier, primary key type, data classification, PII indicator, retention schedule, and `RLS-*` policy binding (see [postgresql-rls-design.md](postgresql-rls-design.md) and [system-design.md](../design/system-design.md) §7.3–7.4):

| TBL ID | Table (`shortlink.*`) | PK (`DES-001`) | Classification | PII Columns | Retention Policy (`DPIA-006`) | RLS Policy ID |
| --- | --- | --- | --- | --- | --- | --- |
| **TBL-001** | `units` | `uuid` (UUIDv7) | Internal | None | Permanent institutional master data; soft-inactive only after link reassignment | `RLS-001` |
| **TBL-002** | `unit_closure` | `(ancestor_id, descendant_id)` | Internal | None | Rebuilt transactionally with `units` tree changes (`DES-002`) | `RLS-002` |
| **TBL-003** | `users` | `uuid` (UUIDv7) | Internal / Confidential (`password_hash`, `mfa_secret_encrypted`) | `PII-001` (`name`), `PII-002` (`email`) | Active during mandate; on offboarding (`disabled`), credentials/MFA wiped immediately, minimal `id, name, email` kept for audit attribution per archive schedule | `RLS-003` |
| **TBL-004** | `sessions` | `text` (random ID) | Confidential | `PII-003` (`user_id` session metadata; no raw IP stored) | Max 8h absolute / 30m idle (`DES-012`); purged within 24h of expiry or immediately on `revoke_sessions` | `RLS-004` |
| **TBL-005** | `user_unit_memberships` | `uuid` (UUIDv7) | Internal | `PII-004` (`user_id` → unit association) | Retained with staff audit history; revoked memberships flagged `status='revoked'` | `RLS-005` |
| **TBL-006** | `roles` | `uuid` (UUIDv7) | Sensitive Internal | None | Permanent while role referenced; protected roles (`platform_owner`, `org_admin`) immutable | `RLS-006` |
| **TBL-007** | `permissions` | `uuid` (UUIDv7) | Internal | None | Seeded from version-controlled `config/permissions.php` (`PERM-001..062`) | `RLS-007` |
| **TBL-008** | `role_permissions` | `(role_id, permission_id)` | Sensitive Internal | None | Current grant state; historical changes recorded in `link_audit_events` | `RLS-008` |
| **TBL-009** | `user_role_assignments` | `uuid` (UUIDv7) | Sensitive Internal | `PII-005` (`user_id`, `granted_by`, `approved_by`, `reason`) | Append/revoke-in-place history retained for ≥ 5 years per government access-audit schedule | `RLS-009` |
| **TBL-010** | `abac_policy_definitions` | `uuid` (UUIDv7) | Sensitive Internal | None | Retained permanently for policy version lineage | `RLS-010` |
| **TBL-011** | `abac_policy_versions` | `uuid` (UUIDv7) | Sensitive Internal | None | Immutable JSONB versions retained permanently for audit replay/rollback | `RLS-011` |
| **TBL-012** | `abac_policy_approvals` | `uuid` (UUIDv7) | Restricted | None (`actor_id` reference) | Append-only; retained ≥ 5 years with policy versions | `RLS-012` |
| **TBL-013** | `access_change_requests` | `uuid` (UUIDv7) | Sensitive Internal | `PII-006` (`requested_by`, `target_user_id`, `reason`) | Retained ≥ 2 years after approval/denial decision | `RLS-013` |
| **TBL-014** | `links` | `uuid` (UUIDv7) | Public (published `slug_normalized`, `title`) / Internal (`unit_id`, `creator_id`) | None (prohibited in slug/title) | Published links & slugs retained permanently as active or tombstoned (`archived`); never-published drafts deleted on discard | `RLS-014` |
| **TBL-015** | `link_destinations` | `uuid` (UUIDv7) | Internal (draft/superseded URLs restricted; current approved URL public) | None (URLs with NIK/RME/tokens/emails rejected by `ALG-002`) | Immutable revision history retained for lifetime of parent link | `RLS-015` |
| **TBL-016** | `reserved_slugs` | `(namespace, slug_normalized)` | Public Metadata | None | **Permanent (infinite)** for `reason IN ('system','published','policy')` | `RLS-016` |
| **TBL-017** | `destination_domain_rules` | `uuid` (UUIDv7) | Sensitive Internal | None | Versioned allowlist/denylist rules maintained by organisation IT (`DES-014`) | `RLS-017` |
| **TBL-018** | `link_approvals` | `uuid` (UUIDv7) | Restricted | None (`actor_id` reference) | Append-only; ≥ 5 years retention | `RLS-018` |
| **TBL-019** | `link_audit_events` | `bigint` (IDENTITY) | Restricted Append-Only | None (redacted before/after hashes and reason only) | Append-only hash-chained (`prev_hash`, `row_hash`); ≥ 5 years retention per institutional archive policy | `RLS-019` |
| **TBL-020** | `access_decision_audit` | `bigint` (IDENTITY) | Restricted Append-Only | None (actor UUID + reason_code only) | Append-only; 13 months online, archived thereafter | `RLS-020` |
| **TBL-021** | `link_daily_stats` | `(link_id, date_utc, channel_code)` | Aggregate Internal | **Zero PII** (`DES-007` raw click events off) | 13 months daily granularity, then rolled up into monthly totals (`DPIA-006`) | `RLS-021` |
| **TBL-022** | `link_qr_assets`, `campaigns`, `api_credentials`, `app_settings`, `ops_heartbeats`, `abuse_reports` (aux/P1) | `uuid` (UUIDv7) | Internal / Confidential (`api_credentials.secret_hash`) | `PII-007` (`abuse_reports.reporter_contact`, optional P1) | `link_qr_assets`: cached while link active; `api_credentials`: purged 30d after revocation; `abuse_reports.reporter_contact`: purged ≤ 90d after triage closure | `RLS-022` |

> **Note on `link_click_events` (`DES-007`):** Per [ADR-0003](adr/0003-privacy-first-aggregate-analytics.md) and [ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md), raw click event persistence is **OFF** in P0 and P1 default configurations. No table in PostgreSQL stores visitor IP addresses, User-Agent strings, cookies, or device fingerprints for short-link resolution.

## Column-Level PII Inventory & Data Subject Rights (`PII-001..007`)
| PII ID | Table.Column | Data Subject | Classification | Lawful Basis | Retention & Purge Mechanism | Subject Rights Path |
| --- | --- | --- | --- | --- | --- | --- |
| **PII-001** | `users.name` | Staff / Official | Internal PII | Official mandate (UU PDP Ps. 20) | Active tenure + archive attribution on `disabled` | View in `UI-018` (`getMe`); correction via `UI-011` (`updateManagedUser`) |
| **PII-002** | `users.email` | Staff / Official | Internal PII | Official mandate | Lowercase official email; anonymized to `<uuid>@disabled.invalid` only if legal erasure supersedes audit attribution | View in `UI-018`; update via `UI-011` |
| **PII-003** | `sessions.user_id`, `last_activity_at` | Staff / Official | Confidential | Security / Auth | 30m idle / 8h absolute TTL (`DES-012`); purged on logout or `revokeUserSessions` | Self-service view & revoke in `UI-018` (`listMySessions`, `revokeMySession`) |
| **PII-004** | `user_unit_memberships.user_id` | Staff / Official | Internal | Organizational scope | Retained for historical scope audit; active window bounded by `valid_until` | View in `UI-018` (`listMyGrants`) |
| **PII-005** | `user_role_assignments.user_id`, `reason` | Staff / Official | Sensitive Internal | Access accountability | ≥ 5 years access audit schedule | View own grants in `UI-018`; inspect in `UI-016` |
| **PII-006** | `access_change_requests.target_user_id`, `reason` | Staff / Official | Sensitive Internal | Dual-control approval | Purged/archived ≥ 2 years post-decision | Viewable by requester/approver in `UI-015` |
| **PII-007** | `abuse_reports.reporter_contact` (P1 `#34`) | Public reporter (optional) | Confidential PII | Public safety / consent | Optional field; automatically nulled/purged ≤ 90 days after incident closure | Optional at submission (`UI-009`); never exposed outside security triage |

## Constraints and indexes
- UNIQUE(namespace, slug_normalized) on reserved_slugs; every active/draft slug acquisition transacted with a unique lock and no reuse of published slug after soft delete.
- Index links(namespace, slug_normalized, status); links(unit_id, created_at); daily_stats(link_id, date_utc); approvals(link_id, timestamp); audit_events(actor_id, occurred_at).
- Constraint link.current_destination_id references version of same link enforced by application transaction and DB strategies verified per engine; prevent cross-link pointer corruption.
- Use optimistic locking/version or row lock on concurrent edits; approval must match submitted version; commit link revision + audit atomically.
- DB uniqueness case-fold and Unicode normalization policy: reserve lowercase ASCII slug for MVP, a-z0-9 and single dashes, 3-64 chars; reject leading/trailing dash and reserved words; use canonical DB collation or binary normalized column consistently.

## Data classification & retention
Public links/QR: published data. User identities, unit and approval: internal. Secrets, auth hashes and backups: confidential. Patient NIK/RME/medical info is **prohibited**, including query string. Default prefer **aggregate-only** clicks without raw events. If raw events approved, document exact lawful basis, fields, TTL (proposed <=30 days), access, purge mechanism before enabling. Aggregate retention proposed <=13 months subject to records schedule; audit retention determined by authority. Never claim automatic deletion when cron unavailable.

## Migrations & portability
- Build for PostgreSQL ONLY: test constraints, transactions, concurrent locks, indexes, RLS policies and scope on the production major version.
- Expand/contract schema deployments: add nullable/new tables -> deploy code -> backfill with bounded steps -> enforce constraints -> remove old fields only after backup and rollback window.
- Do not run schema changes from web endpoints. No destructive migration without rollback/restore proof.
- Database schema is canonical; migrations/ERD/data dictionary/seed fixtures stay in sync. No real patient/client data in fixtures.

## Five data invariants
1. A published short slug is never reassigned to another link ID.
2. Every redirectable link points to a currently approved, permitted destination version.
3. A destination version approved for another link or organization is never reused.
4. A write failing to persist audit fails transaction (except read-only click counters with explicit telemetry degradation).
5. A unit-scoped user cannot query another unit's nonpublic metadata, even by guessing ID.


## P0 PostgreSQL Identity/RBAC/ABAC Tables
| Table | Fields/requirements | Security |
| --- | --- | --- |
| users | Laravel identity, active, MFA, login, disabled_at | restricted user fields, RLS by actor/scopes |
| user_unit_memberships | user_id, unit_id, valid_from, valid_until, status, reviewed_by | scoped; cannot self-add |
| roles | unique key, protected, status, version, created_by | sensitive; not freely editable |
| permissions | unique resource.action key, catalog version | source-controlled catalog |
| role_permissions | role_id, permission_id, version, grantor, reason | scoped grant ceiling, audit |
| user_role_assignments | user_id, role_id, unit_id?, scope_type, validity, approved_by, revoked_at | RLS, immutable assignment history |
| abac_policy_definitions | key, resource, action, current_version, owner_unit, status | protected authoring |
| abac_policy_versions | definition_id, version, rule_jsonb, checksum, approved_by, activated_at | immutable, safe restricted DSL |
| abac_policy_approvals | actor, version_id, decision, reason, occurred_at | append only |
| access_change_requests | requested_by, target_user, change_jsonb, status, approval | workflow/dual control |
| access_decision_audit | actor, action, resource category, verdict, reason_code, policy_version, occurred_at | restricted sanitized audit |

PostgreSQL RLS is mandatory on tenant/unit-scoped and sensitive IAM tables. SQL roles separate app runtime and migration owner; runtime has no BYPASSRLS or DDL. Enforce explicit USING and WITH CHECK for SELECT/INSERT/UPDATE/DELETE. Include FK, unique, validity CHECK, indexes and retention for every IAM field. See postgresql-rls-design.md for DB policies and identity-rbac-abac.md for policy semantics.
