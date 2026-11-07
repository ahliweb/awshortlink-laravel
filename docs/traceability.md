# Cross-Specification Traceability Matrix — v1.1.0-draft (Workflow 9 / SPEC-09)

**Authority:** owner's internal cross-portfolio standard (the development-flow standard v2.1.1 §3 Gate 9).
Every product requirement (`REQ-001..025`) traces forward and backward to UI screens (`UI-001..018`), PostgreSQL tables (`TBL-001..022`) & PII fields (`PII-001..007`), authorization permissions (`PERM-001..062`) & RLS policies (`RLS-001..022`), domain algorithms (`ALG-001..005`), API contracts (`API-001..058`) & events (`EVT-001..006`), GitHub issues (`#1..#43`), and acceptance tests (`TST-001..019`).

## 1. Requirements → UI / Data / Policy / Algorithm / Contract / Issue / Test (`REQ-001..025`)

| REQ ID | Priority | UI Screen(s) | Tables (`TBL-*`) | Auth (`PERM-*` / `RLS-*`) | Algorithm (`ALG-*`) | Contract (`API-*` / `EVT-*` / Route) | Issues | Test ID(s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **REQ-001** Public redirect `/buka/{slug}` | P0 | `UI-009` | `TBL-014`, `TBL-015` (`public_resolvable_links`) | `PERM-001`, `RLS-014`, `RLS-015` | `ALG-003` (`TV-001`, `TV-015..020`) | `GET\|HEAD /buka/{slug}` (`x-non-api-routes`) | `#14` | `TST-001` |
| **REQ-002** Custom & random slug + permanent reservation | P0 | `UI-003` | `TBL-014`, `TBL-016` | `PERM-003`, `RLS-014`, `RLS-016` | `ALG-001`, `ALG-004` (`TV-001..005`, `TV-021`) | `API-002` (`createLink`), `API-003` (`checkSlugAvailability`) | `#12`, `#15` | `TST-002` |
| **REQ-003** Versioned destination edits | P0 | `UI-003`, `UI-004` | `TBL-014`, `TBL-015` | `PERM-004`, `PERM-012..014`, `RLS-014`, `RLS-015` | `ALG-004` (`TV-022`, `TV-023`) | `API-006` (`updateLinkDraft`), `API-007` (`listLinkDestinations`), `API-008` (`proposeDestination`), `API-009` (`rollbackLinkDestination`), `EVT-001` | `#15` | `TST-002` |
| **REQ-004** Destination URL safety policy | P0 | `UI-003`, `UI-007` | `TBL-015`, `TBL-017` | `PERM-012`, `PERM-056`, `RLS-015`, `RLS-017` | `ALG-002` (`TV-006..014`) | `API-004` (`validateDestination`), `API-008` (`proposeDestination`) | `#13` | `TST-003` |
| **REQ-005** Laravel 13 + Filament 5 admin CRUD | P0 | `UI-001`, `UI-002`, `UI-003`, `UI-004`, `UI-008` | `TBL-003`, `TBL-004`, `TBL-014`, `TBL-015` | `PERM-002..010`, `RLS-003`, `RLS-004`, `RLS-014` | `ALG-004` | `API-001` (`listLinks`), `API-002` (`createLink`), `API-005` (`getLink`), `API-006` (`updateLinkDraft`), `API-015` (`archiveLink`) | `#10`, `#11`, `#15` | `TST-004` |
| **REQ-006** Role/unit scoping & RBAC/ABAC enforcement | P0 | `UI-001..018` | `TBL-001..015` | `PERM-001..062`, `RLS-001..022`, `POL-UNIT-SCOPE` | `ALG-004` | All `API-001..058` (`x-permission`) | `#19` | `TST-004`, `TST-015` |
| **REQ-007** Expiry, suspension & revoked states | P0 | `UI-004`, `UI-007`, `UI-009` | `TBL-014`, `TBL-018` | `PERM-008..010`, `RLS-014`, `RLS-018`, `POL-ARCHIVED-RO`, `POL-EMERGENCY` | `ALG-003` (`TV-018`, `TV-019`, `DES-003`) | `API-013` (`suspendLink`), `API-014` (`reinstateLink`), `API-015` (`archiveLink`), `EVT-002` | `#14`, `#15` | `TST-001` |
| **REQ-008** Dynamic QR (SVG/PNG) | P0 | `UI-004`, `UI-005` | `TBL-014`, `TBL-022` (`link_qr_assets`) | `PERM-015`, `PERM-016`, `RLS-022` | `ALG-001` | `API-017` (`downloadLinkQr`), `EVT-001` | `#16` | `TST-005` |
| **REQ-009** Privacy-preserving aggregate analytics | P0 | `UI-001`, `UI-004`, `UI-006` | `TBL-021` (`link_daily_stats`) | `PERM-017`, `PERM-018`, `RLS-021` (`DES-004`, `DES-005`, `DES-007`) | `ALG-005` (`TV-024`) | `API-018` (`getAnalyticsOverview`), `API-019` (`getLinkAnalytics`), `EVT-003` | `#17` | `TST-006` |
| **REQ-010** Append-only hash-chained audit trail | P0 | `UI-001`, `UI-004`, `UI-010` | `TBL-019`, `TBL-020` | `PERM-023..025`, `RLS-019`, `RLS-020` | `ALG-004` | `API-023` (`listAuditEvents`), `API-024` (`verifyAuditChain`), `EVT-001..006` | `#18` | `TST-007` |
| **REQ-011** No-SSH deployment artifact & `/buka` routing | P0 | `UI-010` | `TBL-022` (`app_settings`, `ops_heartbeats`) | `PERM-057`, `RLS-022` | — | `API-058` (`getSystemHealth`) | `#1`, `#21`, `#22`, `#24`, `#43` | `TST-008` |
| **REQ-012** Accessible public error states (`404`/`410`/`503`) | P0 | `UI-009` | `TBL-014` (`public_resolvable_links`) | `PERM-001` | `ALG-003` (`TV-018..020`) | `GET /buka/{slug}`, `GET /buka/`, `POST /buka/laporan` | `#20`, `#34` | `TST-009` |
| **REQ-013** Approval workflow & separation of duties | P1 (SoD in P0 per `DES-009`) | `UI-003`, `UI-004`, `UI-007` | `TBL-015`, `TBL-018` | `PERM-005..008`, `RLS-015`, `RLS-018`, `POL-LINK-SOD` | `ALG-002`, `ALG-004` | `API-010` (`submitLink`), `API-011` (`approveLink`), `API-012` (`rejectLink`), `API-016` (`listPendingReviews`) | `#27` | `TST-010` |
| **REQ-014** Campaigns & channel grouping | P1 | `UI-003`, `UI-006` | `TBL-021`, `TBL-022` (`campaigns`) | `PERM-019..022`, `RLS-021`, `RLS-022` | `ALG-005` | `API-021` (`listCampaigns`), `API-022` (`createCampaign`) | `#28` | `TST-006` |
| **REQ-015** Safe CSV bulk import/export | P1 | `UI-002`, `UI-006` | `TBL-014`, `TBL-015`, `TBL-019` | `PERM-011`, `PERM-018`, `PERM-058`, `PERM-059`, `RLS-014` | `ALG-001`, `ALG-002` | `API-020` (`exportAnalyticsAggregate`) | `#29` | `TST-011` |
| **REQ-016** Scoped REST API credentials | P1 (internal P0 per `DES-015`) | `UI-018` | `TBL-022` (`api_credentials`) | `PERM-053`, `PERM-054`, `RLS-022` | — | `API-001..058` | `#8`, `#30` | `TST-012` |
| **REQ-017** SSRF-safe destination health checker | P1 | `UI-010` | `TBL-015`, `TBL-022` (`link_health_checks`) | `PERM-060`, `RLS-022` | `ALG-002` | `API-058` (`getSystemHealth`) | `#31`, `#32` | `TST-013` |
| **REQ-018** Analytics retention & scheduled reporting | P1 | `UI-006`, `UI-010` | `TBL-021` (`link_daily_stats`) | `PERM-018`, `RLS-021` (`DPIA-006`) | `ALG-005` | `API-020` (`exportAnalyticsAggregate`) | `#32`, `#33` | `TST-014` |
| **REQ-019** Public program directory / link-in-bio | P2 | `UI-009` | `TBL-014` | `PERM-001`, `RLS-014` | `ALG-003` | `GET /buka/` (`x-non-api-routes`) | `#20`, `#36` | `TST-009` |
| **REQ-020** Multi-domain & contextual rules | P2 | Future ADR | `TBL-014` (`namespace`) | `PERM-055` | `ALG-001`, `ALG-003` | Deferred P2 ADR | `#35`, `#37` | Deferred P2 |
| **REQ-021** PostgreSQL-only database architecture | P0 | `UI-010` | `TBL-001..022` | `PERM-057`, `RLS-001..022` | `ALG-003..005` | `API-058` (`getSystemHealth`) | `#1`, `#5`, `#12`, `#38`, `#43` | `TST-017`, `TST-018` |
| **REQ-022** Managed user, unit & session lifecycle | P0 | `UI-008`, `UI-011`, `UI-015`, `UI-017`, `UI-018` | `TBL-001..005` (`PII-001..004`) | `PERM-026..036`, `PERM-062`, `RLS-001..005`, `POL-PRIV-MFA` | — | `API-025..038`, `API-055..057`, `EVT-006` | `#11`, `#19`, `#39` | `TST-015`, `TST-019` |
| **REQ-023** Managed RBAC roles, permission matrix & ABAC policies | P0 | `UI-012`, `UI-013`, `UI-014`, `UI-015` | `TBL-006..013` (`PII-005`, `PII-006`) | `PERM-037..051`, `RLS-006..013`, `POL-PRIV-MFA` | — | `API-039..053`, `EVT-004`, `EVT-005` | `#6`, `#40`, `#41` | `TST-015`, `TST-016` |
| **REQ-024** Mandatory PostgreSQL RLS & transaction-local context | P0 | `UI-010`, `UI-016` | `TBL-001..022` | `RLS-001..022` | `ALG-003`, `ALG-004` | `API-054`, `API-058` | `#12`, `#38`, `#42` | `TST-017`, `TST-018` |
| **REQ-025** Effective Access Inspector | P0 | `UI-016` | `TBL-020` (`access_decision_audit`) | `PERM-052`, `RLS-020` | — | `API-054` (`inspectEffectivePermissions`) | `#42` | `TST-019` |

---

## 2. Screen → API Contract & Permission Completeness (`UI-001..018`)

Verified automatically by `node design/mock-server/verify-contract.mjs` (zero screens without a contract data source):

| Screen ID | Screen Title | Bound Contract Operations (`operationId` / Route) | Required Permissions (`x-permission`) |
| --- | --- | --- | --- |
| **UI-001** | Overview Dashboard | `API-001` (`listLinks`), `API-016` (`listPendingReviews`), `API-018` (`getAnalyticsOverview`), `API-023` (`listAuditEvents`), `API-025` (`listUnits`) | `links.list_internal`, `links.approve`, `analytics.view`, `audit.view`, `units.read` |
| **UI-002** | Short Links List | `API-001` (`listLinks`), `API-015` (`archiveLink`), `API-025` (`listUnits`) | `links.list_internal`, `links.archive`, `units.read` |
| **UI-003** | Create / Edit Link | `API-002` (`createLink`), `API-003` (`checkSlugAvailability`), `API-004` (`validateDestination`), `API-005` (`getLink`), `API-006` (`updateLinkDraft`), `API-008` (`proposeDestination`), `API-010` (`submitLink`), `API-021` (`listCampaigns`), `API-025` (`listUnits`) | `links.create_draft`, `links.update_draft`, `links.submit`, `destinations.propose`, `campaigns.read`, `units.read` |
| **UI-004** | Link Detail & Version History | `API-005` (`getLink`), `API-007` (`listLinkDestinations`), `API-008` (`proposeDestination`), `API-009` (`rollbackLinkDestination`), `API-010` (`submitLink`), `API-011` (`approveLink`), `API-012` (`rejectLink`), `API-013` (`suspendLink`), `API-014` (`reinstateLink`), `API-015` (`archiveLink`), `API-017` (`downloadLinkQr`), `API-019` (`getLinkAnalytics`), `API-023` (`listAuditEvents`) | `links.list_internal`, `destinations.view_history`, `destinations.propose`, `destinations.rollback`, `links.submit`, `links.approve`, `links.reject`, `links.suspend`, `links.reinstate`, `links.archive`, `qr.generate_public`, `analytics.view`, `audit.view` |
| **UI-005** | QR Code Export | `API-017` (`downloadLinkQr`) | `qr.generate_public`, `qr.generate_draft` |
| **UI-006** | Analytics & Campaigns | `API-018` (`getAnalyticsOverview`), `API-019` (`getLinkAnalytics`), `API-020` (`exportAnalyticsAggregate`), `API-021` (`listCampaigns`), `API-022` (`createCampaign`) | `analytics.view`, `analytics.export`, `campaigns.read`, `campaigns.create` |
| **UI-007** | Review Queue & Destination Approval | `API-004` (`validateDestination`), `API-007` (`listLinkDestinations`), `API-011` (`approveLink`), `API-012` (`rejectLink`), `API-013` (`suspendLink`), `API-014` (`reinstateLink`), `API-016` (`listPendingReviews`) | `links.approve`, `links.reject`, `links.suspend`, `links.reinstate`, `destinations.view_history` |
| **UI-008** | Admin Sign-In, MFA & Session Guard | `API-055` (`getMe`), `API-056` (`listMySessions`), `API-057` (`revokeMySession`) | `workspace.self.manage` |
| **UI-009** | Public Resolver, Landing & Error Pages (`404`/`410`/`503`) | `GET\|HEAD /buka/{slug}`, `GET /buka/`, `POST /buka/laporan` (`x-non-api-routes`) | `links.read_public` (anonymous public gateway) |
| **UI-010** | System, PostgreSQL RLS & Scheduler Status | `API-024` (`verifyAuditChain`), `API-058` (`getSystemHealth`) | `ops.health.view`, `audit.verify_chain` |
| **UI-011** | User Management | `API-025` (`listUnits`), `API-029` (`addMembership`), `API-030` (`revokeMembership`), `API-031` (`listManagedUsers`), `API-032` (`inviteUser`), `API-033` (`getManagedUser`), `API-034` (`updateManagedUser`), `API-035` (`suspendUser`), `API-036` (`reinstateUser`), `API-037` (`disableUser`), `API-038` (`revokeUserSessions`), `API-039` (`listUserRoleAssignments`) | `users.read`, `users.invite`, `users.update`, `users.suspend`, `users.disable`, `users.revoke_sessions`, `units.memberships.manage`, `roles.read` |
| **UI-012** | Role Management | `API-044` (`listManagedRoles`), `API-045` (`createManagedRole`) | `roles.read`, `roles.create` |
| **UI-013** | Permission Matrix | `API-044` (`listManagedRoles`), `API-046` (`listPermissionCatalog`), `API-047` (`replaceRolePermissions`) | `roles.read`, `permissions.read`, `roles.permissions.update` |
| **UI-014** | ABAC Policy Manager & Simulator | `API-048` (`listAbacPolicies`), `API-049` (`createAbacPolicyDraft`), `API-050` (`simulateAbacPolicy`), `API-051` (`submitAbacPolicyVersion`), `API-052` (`publishAbacPolicyVersion`), `API-053` (`rollbackAbacPolicy`) | `policies.read`, `policies.create`, `policies.simulate`, `policies.submit`, `policies.publish`, `policies.rollback` |
| **UI-015** | Scoped User Role Assignment & Dual Control | `API-025` (`listUnits`), `API-031` (`listManagedUsers`), `API-033` (`getManagedUser`), `API-039` (`listUserRoleAssignments`), `API-040` (`assignUserRole`), `API-041` (`revokeUserRole`), `API-042` (`listAccessChangeRequests`), `API-043` (`decideAccessChangeRequest`), `API-044` (`listManagedRoles`) | `user_roles.assign`, `user_roles.revoke`, `user_roles.approve_request`, `users.read`, `roles.read`, `units.read` |
| **UI-016** | Effective Access Inspector | `API-031` (`listManagedUsers`), `API-054` (`inspectEffectivePermissions`) | `access.inspect`, `users.read` |
| **UI-017** | Unit Hierarchy & Membership | `API-025` (`listUnits`), `API-026` (`createUnit`), `API-027` (`moveUnit`), `API-028` (`listUnitMemberships`), `API-029` (`addMembership`), `API-030` (`revokeMembership`) | `units.read`, `units.create`, `units.move`, `units.memberships.manage` |
| **UI-018** | Authenticated Staff Workspace / Profile | `API-034` (`updateManagedUser`), `API-055` (`getMe`), `API-056` (`listMySessions`), `API-057` (`revokeMySession`) | `workspace.self.manage`, `users.update` |

---

## 3. Threats (`THR-001..021`) → Requirements, Algorithms, RLS & Tests

| Threat ID | Primary Controls | REQ ID | Algorithm / Policy / RLS | Issue(s) | Test ID(s) |
| --- | --- | --- | --- | --- | --- |
| **THR-001** Open redirect / phishing | `ALG-002` canonicalizer, allowlist, SoD approval, immediate suspend | `REQ-004`, `REQ-007`, `REQ-013` | `ALG-002`, `POL-LINK-SOD`, `RLS-015`, `RLS-017` | `#13`, `#14`, `#27` | `TST-003`, `TST-010` |
| **THR-002** Cross-unit edit / IDOR | Unit-scoped RBAC + `POL-UNIT-SCOPE` + PostgreSQL RLS + 404 concealment | `REQ-006`, `REQ-024` | `RLS-001..022`, `POL-UNIT-SCOPE` | `#19`, `#38` | `TST-004`, `TST-017` |
| **THR-003** Stolen credentials / replay | TOTP MFA (`DES-006`), `POL-PRIV-MFA`, 30m/8h sessions (`DES-012`), hashed tokens | `REQ-005`, `REQ-016`, `REQ-022` | `POL-PRIV-MFA`, `RLS-003`, `RLS-004` | `#11`, `#30`, `#39` | `TST-012`, `TST-019` |
| **THR-004** PII / token leakage in URL or logs | `ALG-002` sensitive query blocker, `no-referrer`, zero raw click storage (`DES-007`) | `REQ-004`, `REQ-009`, `REQ-018` | `ALG-002`, `ALG-005`, `DPIA-004..006` | `#13`, `#17`, `#33` | `TST-003`, `TST-006` |
| **THR-005** SSRF in health checker | Zero network fetch on redirect; isolated P1 checker with public-IP check | `REQ-001`, `REQ-017` | `ALG-002`, `ALG-003` | `#14`, `#31` | `TST-001`, `TST-013` |
| **THR-006** DoS / bot click floods | Single indexed view lookup, post-response `shortlink.record_click` (`DES-011`) | `REQ-001`, `REQ-009` | `ALG-003`, `ALG-005` | `#14`, `#17` | `TST-001`, `TST-006` |
| **THR-007** Slug collision / reuse | `UNIQUE(namespace, slug_normalized)` + permanent `reserved_slugs` tombstone | `REQ-002`, `REQ-003` | `ALG-001`, `ALG-004`, `RLS-016` | `#12`, `#15` | `TST-002` |
| **THR-008** Exposed `.env` / vendor / backup | Private app outside webroot, immutable artifact, `SystemStatus` redaction | `REQ-011` | `HOST-06`, `HOST-08` | `#21`, `#22` | `TST-008` |
| **THR-009** CSV formula / XSS / SVG injection | Blade escaping, deterministic QR SVG generator, CSV `=+-@` prefixing | `REQ-008`, `REQ-015` | `ALG-001` | `#16`, `#29` | `TST-005`, `TST-011` |
| **THR-010** Lost or altered audit events | Same-transaction `AuditWriter` + SHA-256 `prev_hash`/`row_hash` chain, no UPDATE/DELETE grant | `REQ-010` | `ALG-004`, `RLS-019`, `RLS-020` | `#18` | `TST-007` |
| **THR-011** Shared-host cron pile-up | Request-time expiry/grant evaluation, bounded locked jobs | `REQ-007`, `REQ-018` | `ALG-003` | `#14`, `#32` | `TST-001`, `TST-014` |
| **THR-012** Supply-chain compromise | Tracked `composer.lock`, `composer audit`, CycloneDX SBOM, SHA-256 manifest | `REQ-011` | — | `#21`, `#23` | `TST-008` |
| **THR-013** Small-cohort citizen identification | No IP/geo stored (`DES-007`) + $k=10$ small-cohort masking (`DES-005`) | `REQ-009`, `REQ-018` | `ALG-005`, `DPIA-005` | `#17`, `#33` | `TST-006`, `TST-014` |
| **THR-014** Host header / rewrite poisoning | Trusted hosts/proxies, canonical `APP_URL`, `/buka` route isolation | `REQ-001`, `REQ-011` | `ALG-003` | `#14`, `#22` | `TST-001`, `TST-008` |
| **THR-015** Self-approval of risky destination | `POL-LINK-SOD` (`actor.id != resource.creator_id` for `medium`/`high` risk, `DES-009`) | `REQ-006`, `REQ-013` | `POL-LINK-SOD`, `RLS-018` | `#19`, `#27`, `#41` | `TST-010`, `TST-016` |
| **THR-016** Self-grant / privilege escalation | Delegation ceiling check, `CHECK (granted_by <> user_id)`, dual-control `access_change_requests` | `REQ-022`, `REQ-023` | `RLS-008`, `RLS-009`, `RLS-013` | `#40` | `TST-015` |
| **THR-017** Missing RLS context / BYPASSRLS | `ENABLE` + `FORCE ROW LEVEL SECURITY`, non-owner `awshortlink_app`, NULL context → deny | `REQ-021`, `REQ-024` | `RLS-001..022` | `#12`, `#38` | `TST-017` |
| **THR-018** Connection pool context leak | `set_config(..., true)` inside explicit transaction only | `REQ-021`, `REQ-024` | `RLS-001..022` | `#38`, `#42` | `TST-018` |
| **THR-019** Malicious ABAC rule injection | Declarative JSON Schema allowlist, dry-run simulation, independent approval, rollback | `REQ-023` | `RLS-010..012` | `#41` | `TST-016` |
| **THR-020** Lingering access / last-owner lockout | Immediate session/token revocation, per-decision validity check, last `platform_owner` guard | `REQ-022`, `REQ-025` | `RLS-003`, `RLS-004`, `RLS-009` | `#39`, `#42` | `TST-019` |
| **THR-021** RLS-filtered incomplete backup | Dedicated `awshortlink_backup` identity (`DES-010`) + row-count & `pg_policies` restore verification | `REQ-011`, `REQ-021` | `RLS-001..022` | `#38`, `#43` | `TST-008`, `TST-017` |

---

## 4. Gate 9 Acceptance Sign-Off Block
- **Technical Cross-Spec Verification (`verify-contract.mjs` & Traceability Audit):** PASS (2026-11-01 — 25 REQs, 18 UI screens, 22 tables, 7 PII fields, 62 permissions, 22 RLS policies, 5 algorithms, 24 test vectors, 58 OpenAPI operations, 6 AsyncAPI events, 19 acceptance test suites, 15 design decisions locked in ADR-0007).
- **Human Sign-Off Status:**
  - Product & Technical Owner: project owner — **APPROVED (GO)** (`2026-11-01`)
  - Local/CI Target Environment: PostgreSQL 18.4 + PHP >=8.3 (Topology A/C per `DEC-018`); production host cutover gated at Gate 15 (`#25`, `#43`).
  - **Gate 9 Decision:** **GO — Phase II Implementation (`#10`–`#43`) Unlocked (2026-11-01)**
