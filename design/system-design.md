# System Design — AW Shortlink

**Version:** v1.0.0-draft | **Date:** 2026-10-31 | **Status:** draft specification, **not implemented; Gate 9 NO-GO**
**Workflow coverage:** step 1 (architecture/C4/NFR), step 5 (physical data design), step 6 (RBAC/ABAC/RLS isolation), step 7 (algorithms/state machines), step 8 (API conventions and contract gaps).
**Canonical language:** English. Indonesian UI copy lives in the UX documents.

> **Nothing in this document is implemented.** It is a design proposal derived from the existing specifications. Class names, directory layout, DDL and SQL below are *illustrative and proposed, pending Gate 9* ([#9](https://github.com/ahliweb/awshortlink-laravel/issues/9)). Where this document adds a decision not already present in an ADR it is marked **(proposed, pending Gate 9)** and listed in [§15 Open decisions](#15-open-design-decisions-gate-9). If this document conflicts with an ADR, the ADR wins and this document is a defect.

## Sources (read first)
| Source | Used for |
| --- | --- |
| [master-blueprint.md](../docs/master-blueprint.md) | Vision, C4 context, topology A/B/C, SLO proposals |
| [prd.md](../docs/prd.md) | REQ-001..025, business rules, five canonical flows |
| [threat-model-privacy.md](../docs/threat-model-privacy.md) | THR-001..021, classification, retention defaults |
| [ui-ux.md](../docs/ui-ux.md) | UI-001..018 screen inventory |
| [data-model.md](../docs/data-model.md) | Logical ERD and dictionary |
| [postgresql-rls-design.md](../docs/postgresql-rls-design.md) | DB roles, RLS, transaction-local context |
| [identity-rbac-abac.md](../docs/identity-rbac-abac.md) | Account levels, roles, ABAC lifecycle |
| [access-control.md](../docs/access-control.md) | Role × permission matrix, negative tests |
| [redirect-algorithm.md](../docs/redirect-algorithm.md) | Resolver algorithm and HTTP decision table |
| [api/openapi.yaml](../docs/api/openapi.yaml), [api/asyncapi.yaml](../docs/api/asyncapi.yaml) | Contract drafts |
| [deployment-no-ssh.md](../docs/deployment-no-ssh.md), [operations-runbook.md](../docs/operations-runbook.md) | Release and operations |
| [testing-quality.md](../docs/testing-quality.md), [traceability.md](../docs/traceability.md) | TST-001..019 and trace matrix |
| [issue-roadmap.md](../docs/issue-roadmap.md) | Issues #1–#43 and execution DAG |
| ADRs | [0001](../docs/adr/0001-laravel-no-ssh-and-path-prefix.md) Laravel/no-SSH/prefix · [0002](../docs/adr/0002-approved-destination-and-immutable-slug.md) approved destination/immutable slug/302 · [0003](../docs/adr/0003-privacy-first-aggregate-analytics.md) aggregate analytics · [0004](../docs/adr/0004-db-driver-portability.md) (superseded) · [0005](../docs/adr/0005-postgresql-only-and-mandatory-rls.md) PostgreSQL-only + RLS · [0006](../docs/adr/0006-managed-rbac-abac-and-rls.md) managed RBAC+ABAC |

---

## 1. Summary
AW Shortlink is a **single Laravel 13 modular monolith** (PHP ≥ 8.3, Filament 5, Livewire, Blade, Tailwind) served under `/buka/*` beside the existing the organisation website, backed exclusively by **PostgreSQL with mandatory RLS**. It has three entry points sharing one codebase but separated by route group, middleware stack, DB role and policy:

1. **Public resolver** — `GET|HEAD /buka/{slug}` → 302 to an approved destination, or a safe 404/410/503. Reads only a sanitized view through a dedicated read-only DB role. No outbound network I/O.
2. **Admin panel** — Filament at `/buka/admin` for link, QR, analytics, audit and **managed IAM** (users, roles, permission matrix, scoped grants, ABAC policies, Effective Access Inspector).
3. **REST API** — `/buka/api/v1` (P1 for external clients; the same application services back Filament in P0).

Every protected decision = **active identity ∧ RBAC permission ∧ ABAC predicate ∧ Laravel Policy ∧ PostgreSQL RLS**, with deny-by-default at each layer and transactional audit.

---

## 2. Architecture drivers

### 2.1 Quality attributes (mapped to ISO/IEC 25010:2023)
| ISO/IEC 25010 characteristic | Driver | Design response | Evidence (TST) |
| --- | --- | --- | --- |
| Security — integrity, non-repudiation | Printed QR must never be hijacked; every privileged write attributable | Permanent slug reservation, approved-version pointer, append-only hash-chained audit in same transaction | TST-002, TST-007 |
| Security — confidentiality, accountability | Cross-unit isolation, no PII leakage | RBAC+ABAC+Policy+RLS, sanitized resolver view, aggregate-only analytics | TST-004, TST-006, TST-017 |
| Security — authenticity / resistance | Stolen credentials, phishing via .go.id | MFA, session revocation, destination risk policy + approval | TST-003, TST-019 |
| Performance efficiency — time behaviour | Redirect p95 ≤ 300 ms (proposed SLO) | One indexed lookup on a narrow view, no outbound I/O, bounded counter UPSERT | Load test (testing-quality.md) |
| Reliability — fault tolerance, recoverability | Analytics/DB failure modes; no-SSH restore | Fail-closed 503, analytics best-effort, rehearsed pg_dump/pg_restore | TST-001, TST-008 |
| Interaction capability — accessibility, error protection | Public citizens and staff on 360 px phones | WCAG 2.2 AA, explicit error pages, typed-intent confirmations | TST-009 |
| Maintainability — modularity, testability | Small team, long life | Domain modules with explicit public services; contract-first API | Static analysis, contract tests |
| Flexibility — installability, adaptability | Shared hosting without SSH | Immutable artifact, no daemon, cron optional | TST-008 |
| Safety (25010:2023) — fail safe | Unknown states must not redirect | Every resolver branch not explicitly "active" ends in non-redirect | TST-001 |

### 2.2 Constraints (binding, from ADRs/AGENTS.md)
- **C-01** No developer SSH; Composer/Node run on a trusted build machine; immutable artifact uploaded via SFTP/FTPS/panel (ADR-0001).
- **C-02** Shared/PHP hosting, no mandatory Redis, Supervisor, Docker, Node server or persistent worker in production.
- **C-03** PostgreSQL **only** in every environment; `pdo_pgsql` required; no SQLite/MySQL/MariaDB even in tests (ADR-0005).
- **C-04** Mandatory RLS (ENABLE + FORCE) on scoped private and IAM tables; runtime DB role non-owner, no BYPASSRLS, no DDL.
- **C-05** Public namespace `/buka/{slug}` only after proving the parent web server can delegate `/buka/*` safely; never overwrite parent `.htaccess` (#22).
- **C-06** Livewire asset/update endpoints must live under the tested `/buka` prefix (e.g. `/buka/livewire/*`).
- **C-07** No web-exposed installer, artisan route or migration endpoint.
- **C-08** Redirects are 302 (never 301/308) with `Cache-Control: no-store` (ADR-0002, DEC-009).
- **C-09** No raw IP/UA/fingerprint storage by default (ADR-0003).
- **C-10** Human Gate 9 before any implementation; Gate 15 before production.

### 2.3 Key architecture risks
| Risk | Impact | Mitigation in design | Owner issue |
| --- | --- | --- | --- |
| Host lacks PostgreSQL / RLS DDL rights | Project NO-GO | Hard host gate, topology C (separate host) | #1, #43 |
| Parent site cannot delegate `/buka/*` | Public URL unavailable | Topology B (reverse proxy to subdomain) keeps external URL | #22 |
| RLS context leak via pooled connections | Cross-unit disclosure | `set_config(..., true)` inside explicit transaction only; pool tests | #38, TST-018 |
| ABAC misconfiguration locks everyone out or over-grants | Outage or escalation | Restricted DSL, simulation, independent approval, rollback, protected break-glass role | #41 |
| No cron on host | Retention/expiry jobs absent | Expiry enforced at request time; retention purge manual fallback with evidence | #32, #33 |
| Shared-host CPU/DB connection limits | Latency/SLO breach | Lean resolver middleware stack, connection budget, measured baseline before SLO commit | #23, #24 |

---

## 3. C4 model

### 3.1 Level 1 — System context
~~~mermaid
flowchart LR
    citizen["Citizen / QR scanner (anonymous)"]
    staff["Organisation staff (editor, approver, analyst, auditor, unit admin)"]
    secadm["Platform owner / central admin"]
    operator["Hosting operator"]
    sys["AW Shortlink (Laravel 13 + Filament 5, PostgreSQL + RLS)"]
    parent["Existing organisation website / web server"]
    dest["Approved destinations (go.id + reviewed external sites)"]
    mail["Institutional SMTP (invites, alerts) — to verify"]
    citizen -->|"GET /buka/slug"| parent
    parent -->|"delegates /buka/*"| sys
    sys -->|"302 Location"| citizen
    citizen -.->|"follows redirect"| dest
    staff -->|"HTTPS /buka/admin"| sys
    secadm -->|"IAM, policies, emergency suspend"| sys
    operator -->|"SFTP/panel artifact, DB console"| sys
    sys -.->|"optional"| mail
~~~
The system never fetches `dest` during a redirect. The optional P1 health checker (#31) is the only component allowed outbound HTTP, under SSRF controls.

### 3.2 Level 2 — Containers
~~~mermaid
flowchart TB
    subgraph host["PHP host (no SSH)"]
      fc["public/index.php front controller under /buka"]
      subgraph app["Laravel modular monolith"]
        res["Public resolver route group (stateless, no session)"]
        pub["Public pages: landing, 404/410/503, misuse report"]
        adm["Filament panel /buka/admin (session, CSRF, MFA)"]
        api["REST API /buka/api/v1 (token, P1)"]
        cli["Artisan CLI (operator-run only, via panel cron or PHP CLI)"]
      end
      store["storage/ outside webroot (logs, QR cache)"]
    end
    subgraph db["PostgreSQL 17/18 (version pinned after audit)"]
      rview["view public_resolvable_links"]
      priv["private + IAM tables (RLS ENABLE+FORCE)"]
    end
    fc --> res & pub & adm & api
    res -->|"role awshortlink_resolver (SELECT view, counter fn)"| rview
    adm -->|"role awshortlink_app (DML, RLS)"| priv
    api -->|"role awshortlink_app"| priv
    cli -->|"role awshortlink_migrator (DDL, direct conn)"| priv
    backup["Backup identity awshortlink_backup (pg_dump)"] --> db
    cron["Optional panel cron: schedule:run, database queue"] -.-> cli
~~~

| Container | Tech | Auth | DB role | Notes |
| --- | --- | --- | --- | --- |
| Public resolver | Laravel route, minimal middleware (no session, no cookies, no CSRF) | none | `awshortlink_resolver` | SELECT on `public_resolvable_links`, EXECUTE on `record_click()` only |
| Public pages | Blade, static-cacheable | none | `awshortlink_resolver` | Landing/directory only if approved (#20) |
| Filament admin | Filament 5 + Livewire, `/buka/admin`, Livewire `/buka/livewire/*` | session + MFA | `awshortlink_app` | All writes via domain Actions |
| REST API | Laravel controllers, Sanctum-style hashed tokens (P1) | bearer token, scopes ⊆ user rights | `awshortlink_app` | Same Actions as Filament |
| Artisan CLI | PHP CLI via panel cron or operator | operator | `awshortlink_migrator` (migrations) / `awshortlink_app` (jobs) | Never exposed over HTTP |
| PostgreSQL | 17 or 18 | DB roles | — | Runtime ≠ owner, no BYPASSRLS |
| Database queue | `jobs` table + cron | — | `awshortlink_app` | P1 only, if cron verified (#32) |

**Database roles (from postgresql-rls-design.md; names proposed):**
| Role | LOGIN | Owner | BYPASSRLS | Privileges |
| --- | --- | --- | --- | --- |
| `awshortlink_owner` | no | yes (schema/table owner, NOLOGIN) | no | owns objects; nobody logs in as it |
| `awshortlink_migrator` | yes | member of owner, used only by operator over direct connection | no | DDL, GRANT, policy creation |
| `awshortlink_app` | yes | no | no | SELECT/INSERT/UPDATE on private tables subject to RLS; no DELETE on audit tables; no DDL |
| `awshortlink_resolver` | yes | no | no | SELECT on `public_resolvable_links`; EXECUTE `shortlink.record_click(uuid, smallint)` |
| `awshortlink_backup` | yes | no | **see DES-010** | pg_dump of all rows; RLS must not silently omit rows (THR-021) |

### 3.3 Level 3 — Components (modules of the monolith)
Each module exposes **Actions** (write use cases), **Queries** (read models) and **Policies**; modules talk through these public classes only. Namespaces are *proposed*.

| Module | Responsibility | Key classes (proposed) | Owned tables | Routes / Filament | Permissions | Issues | REQ / UI / TST |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Resolver** | Slug canonicalization, single lookup, decision table, headers, best-effort counter | `Domain\Resolver\SlugCanonicalizer`, `ResolveSlug`, `ResolutionDecision`, `Http\Controllers\Public\ResolveSlugController`, `Middleware\PublicResolverStack` | none (reads view) | `GET|HEAD /buka/{slug}` | public | #14 | REQ-001/007 · UI-009 · TST-001 |
| **Links (Catalog)** | Link aggregate, slug reservation, destination versions, lifecycle | `Domain\Links\Actions\CreateLinkDraft`, `UpdateLinkDraft`, `ProposeDestination`, `SubmitLink`, `PublishLink`, `ArchiveLink`, `SuspendLink`, `Models\Link`, `LinkDestination`, `ReservedSlug` | links, link_destinations, reserved_slugs | `Filament\Resources\LinkResource` (+ `DestinationsRelationManager`, `AuditRelationManager`) | links.* | #12, #15 | REQ-002/003/005/007 · UI-002/003/004 · TST-002/004 |
| **DestinationPolicy** | URL parse/canonicalize, risk classification, allowlist | `Domain\DestinationPolicy\UrlCanonicalizer`, `DestinationRiskClassifier`, `DomainAllowlist`, `PolicyVerdict` | destination_domain_rules | `DomainRuleResource` (settings) | settings.domain_rules.manage | #13 | REQ-004 · UI-003/007 · TST-003 |
| **Approval** (P1; P0 uses publish-by-authorized-role) | Review queue, separation of duties, emergency suspend | `Domain\Approval\Actions\ApproveDestination`, `RejectDestination`, `EmergencySuspend`, `ReviewQueueQuery` | link_approvals | `Filament\Pages\ReviewQueue` | links.approve, links.suspend | #27 | REQ-013 · UI-007 · TST-010 |
| **QR** | Deterministic SVG/PNG of the canonical short URL, branding template | `Domain\Qr\RenderQr`, `QrTemplate`, `QrAssetStore` | link_qr_assets | `GET /buka/admin/links/{id}/qr.{svg|png}` (authenticated) | qr.generate_public | #16 | REQ-008 · UI-005 · TST-005 |
| **Analytics** | Bounded daily counters, bot class, cohort suppression, reports | `Domain\Analytics\RecordClick`, `BotClassifier`, `DailyStatsQuery`, `CohortSuppressor` | link_daily_stats, (link_click_events optional) | `Filament\Pages\Analytics`, widgets | analytics.view, analytics.export | #17, #33 | REQ-009/018 · UI-001/006 · TST-006/014 |
| **Audit** | Append-only hash-chained events, verification | `Domain\Audit\AuditWriter`, `AuditChainVerifier`, `AuditQuery` | link_audit_events, access_decision_audit | `AuditEventResource` (read-only) | audit.view | #18 | REQ-010 · UI-004 · TST-007 |
| **Identity** | Users, invites, MFA, sessions, units, memberships | `Domain\Identity\Actions\InviteUser`, `ActivateUser`, `SuspendUser`, `DisableUser`, `RevokeSessions`, `AddMembership`, `Models\User`, `Unit` | users, units, unit_closure, user_unit_memberships, sessions | `UserResource`, `UnitResource`, `Pages\MyWorkspace` | users.*, units.* | #11, #39 | REQ-022 · UI-008/011/017/018 · TST-015/019 |
| **AccessControl** | Permission catalog, roles, scoped grants, ABAC engine, change requests, inspector, DB context | `Domain\AccessControl\PermissionCatalog`, `Actions\CreateRole`, `ReplaceRolePermissions`, `AssignRole`, `RevokeRole`, `Abac\PolicyEvaluator`, `Abac\RuleSchemaValidator`, `Abac\Simulator`, `EffectiveAccessInspector`, `Database\RlsContext`, `Gate\AuthorizationPipeline` | roles, permissions, role_permissions, user_role_assignments, abac_policy_definitions, abac_policy_versions, abac_policy_approvals, access_change_requests | `RoleResource`, `Pages\PermissionMatrix`, `AbacPolicyResource`, `Pages\AccessInspector`, `AccessChangeRequestResource` | roles.*, user_roles.*, policies.*, access.inspect | #19, #38, #40, #41, #42 | REQ-006/023/024/025 · UI-012..016 · TST-015..018 |
| **Campaigns** (P1) | Grouping, channel variants, campaign report | `Domain\Campaigns\Actions\CreateCampaign`, `CampaignReportQuery` | campaigns | `CampaignResource` | campaigns.* | #28 | REQ-014 |
| **Public** | Landing, directory (if approved), error pages, misuse report form | `Http\Controllers\Public\LandingController`, `ErrorPageRenderer`, `MisuseReportController` (P1) | abuse_reports (P1) | `/buka/`, error views | public | #20, #34 | REQ-012 · UI-009 · TST-009 |
| **Ops / Health** | Build info, DB/RLS self-check, scheduler heartbeat, synthetic check | `Domain\Ops\HealthReport`, `RlsIntrospection`, `SchedulerHeartbeat` | app_settings, ops_heartbeats | `Filament\Pages\SystemStatus` (admin-only) | settings.security, ops.health.view | #21, #32, #43 | REQ-011/021 · UI-010 · TST-008 |

---

## 4. Proposed source layout (proposed, pending Gate 9)
~~~text
app/
  Domain/
    Resolver/        SlugCanonicalizer.php ResolveSlug.php ResolutionDecision.php
    Links/           Actions/ Models/ Policies/LinkPolicy.php Queries/ Events/
    DestinationPolicy/ UrlCanonicalizer.php DestinationRiskClassifier.php DomainAllowlist.php
    Approval/        Actions/ Queries/
    Qr/              RenderQr.php QrTemplate.php
    Analytics/       RecordClick.php BotClassifier.php CohortSuppressor.php Queries/
    Audit/           AuditWriter.php AuditChainVerifier.php
    Identity/        Actions/ Models/ Policies/
    AccessControl/   PermissionCatalog.php Abac/ Actions/ Database/RlsContext.php Gate/AuthorizationPipeline.php
    Campaigns/       (P1)
    Ops/             HealthReport.php RlsIntrospection.php
  Filament/
    Resources/       LinkResource.php UserResource.php RoleResource.php UnitResource.php AbacPolicyResource.php AuditEventResource.php ...
    Pages/           Dashboard.php Analytics.php ReviewQueue.php PermissionMatrix.php AccessInspector.php SystemStatus.php MyWorkspace.php
    Widgets/
  Http/
    Controllers/Public/ResolveSlugController.php LandingController.php
    Controllers/Api/V1/...
    Middleware/WithRlsContext.php PublicResolverStack.php
config/permissions.php           # source-controlled permission catalog
database/
  migrations/                    # Laravel migrations (run by operator as awshortlink_migrator)
  sql/rls/                       # 0001_roles.sql 0010_enable_rls.sql 0020_policies_links.sql 0030_policies_iam.sql 0040_resolver_view.sql
  seeders/ (catalog + protected roles only; no real personal data)
tests/
  Unit/ Feature/ Contract/ Rls/  # Rls/ runs as awshortlink_app against real PostgreSQL
  Browser/                       # E2E on staging under /buka
resources/views/public/          # 404/410/503/landing Blade
~~~

---

## 5. Request flows

### 5.1 Public resolver `GET /buka/{slug}`
~~~mermaid
sequenceDiagram
    autonumber
    participant V as Visitor
    participant W as Parent web server
    participant R as ResolveSlugController
    participant C as SlugCanonicalizer
    participant DB as PostgreSQL (awshortlink_resolver)
    V->>W: GET /buka/EVENT62?x=1
    W->>R: delegate /buka/* (trusted host, HTTPS)
    R->>R: method in {GET, HEAD}? else 405
    R->>C: canonicalize("EVENT62")
    C-->>R: "event62" or REJECT (reserved / malformed)
    alt rejected
        R-->>V: 404 safe page (no lookup)
    else canonical
        R->>DB: SELECT status, target_url, expires_at FROM public_resolvable_links WHERE namespace=$1 AND slug=$2
        alt DB error / timeout (bounded, e.g. 1 s)
            R-->>V: 503 safe page + alert
        else row active, published, not expired
            R->>R: defensive URL re-validation (scheme https, no userinfo, no IP literal)
            R-->>V: 302 Location target, Cache-Control no-store
            R--)DB: after response: SELECT shortlink.record_click(link_id, bot_class)
        else retired with tombstone
            R-->>V: 410 retired page
        else none / suspended / scheduled
            R-->>V: 404 (suspended mapping per DES-003)
        end
    end
~~~
**Response headers on 302:** `Location: <canonical approved URL>`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`; HSTS at host level. No `Set-Cookie`. The incoming query string is **not** forwarded (redirect-algorithm.md).

**Counter:** executed after the response is flushed (`terminable` middleware / `dispatch()->afterResponse()`), as a single statement:
~~~sql
INSERT INTO link_daily_stats (link_id, date_utc, channel_code, valid_clicks, suspected_bot)
VALUES ($1, (now() AT TIME ZONE 'UTC')::date, '', CASE WHEN $2 = 0 THEN 1 ELSE 0 END, CASE WHEN $2 > 0 THEN 1 ELSE 0 END)
ON CONFLICT (link_id, date_utc, channel_code)
DO UPDATE SET valid_clicks = link_daily_stats.valid_clicks + EXCLUDED.valid_clicks,
              suspected_bot = link_daily_stats.suspected_bot + EXCLUDED.suspected_bot;
~~~
wrapped in `shortlink.record_click()` (SECURITY DEFINER **only** for this narrow function, `SET search_path = shortlink, pg_temp`, owned by a dedicated non-login owner, input validated) so the resolver role has no table privileges. Failure increments an in-process "dropped" metric/log line and never changes the HTTP result (ADR-0003). HEAD requests are not counted. Hot-row contention is acceptable at expected volume; if measured otherwise, switch to a bounded `link_click_buffer` table flushed by cron (DES-011).

### 5.2 Authenticated write with authorization pipeline and transaction-local RLS context
~~~mermaid
sequenceDiagram
    autonumber
    participant U as Staff (Filament / API)
    participant MW as Middleware (auth, MFA, WithRlsContext)
    participant A as Action (e.g. ProposeDestination)
    participant P as AuthorizationPipeline
    participant DB as PostgreSQL (awshortlink_app)
    U->>MW: POST (session+CSRF or bearer token)
    MW->>MW: authenticated? account active? session not revoked? MFA satisfied for action class?
    MW->>A: invoke with Actor (server-resolved)
    A->>DB: BEGIN
    A->>DB: SELECT set_config('app.actor_id', $actor, true), set_config('app.unit_ids', $units, true), set_config('app.scope', $scope, true)
    A->>P: authorize(actor, "links.update_draft", resource)
    P->>P: 1 RBAC: active grant with permission covering resource.unit_id (valid_from..valid_until)
    P->>P: 2 ABAC: evaluate active policy version (deny-overrides)
    P->>P: 3 Laravel Policy: status/ownership invariants
    alt any deny
        P->>DB: INSERT access_decision_audit (deny, reason_code, policy_version)
        A->>DB: COMMIT (only the denial audit)
        A-->>U: 403 problem+json (or 404 to avoid existence leak)
    else allow
        A->>DB: SELECT ... FOR UPDATE WHERE id=$1 AND version=$expected (RLS USING applies)
        A->>DB: INSERT link_destinations v(n+1) (RLS WITH CHECK applies)
        A->>DB: INSERT link_audit_events (prev_hash chain)
        alt audit insert fails or 0 rows (RLS / stale version)
            A->>DB: ROLLBACK
            A-->>U: 409 stale / 404 not found
        else
            A->>DB: COMMIT
            A-->>U: 200/201 with new ETag
        end
    end
~~~
`app.unit_ids` is the **server-computed** set of unit IDs (descendants expanded via `unit_closure`) for which the actor holds *some* active grant; `app.scope` is `unit` or `global`. Context is set with `is_local = true` and therefore vanishes at COMMIT/ROLLBACK, which is safe for PgBouncer transaction pooling (TST-018). Laravel's DB transaction wrapper (`DB::transaction`) is used for every protected request; Filament list queries run inside a request-scoped transaction opened by `WithRlsContext` (proposed; verify Livewire request lifecycle at #38).

### 5.3 Link lifecycle flow (EVENT62 canonical flow)
~~~mermaid
sequenceDiagram
    autonumber
    participant E as Editor (Unit A)
    participant S as System
    participant AP as Approver (scope Unit A)
    participant CZ as Citizen
    E->>S: CreateLinkDraft(slug=event62, title, unit A) — reserves slug (unique), status draft
    E->>S: ProposeDestination(url v1) — canonicalize + classify risk (low: example.org)
    E->>S: SubmitLink(expected_version)
    AP->>S: ApproveDestination(v1) — approver ≠ creator if risk ≥ medium
    S->>S: PublishLink — current_destination_id = v1, published_at = now, slug reservation becomes permanent
    CZ->>S: GET /buka/event62 → 302 v1
    E->>S: ProposeDestination(url v2) — v1 stays live while v2 pending
    AP->>S: ApproveDestination(v2) — atomic pointer swap v1 → v2, audit
    CZ->>S: GET /buka/event62 → 302 v2 (no cache, immediate)
    AP->>S: SuspendLink(reason) on abuse report — next request 404/410, audit, alert
~~~
In P0 (before #27 approval workflow) "approve" is performed by a holder of `links.approve`, and the self-approval prohibition for medium/high risk already applies through ABAC policy `POL-LINK-SOD` (§8.3).

### 5.4 ABAC policy version lifecycle flow
~~~mermaid
sequenceDiagram
    autonumber
    participant SO as Security owner (policies.create)
    participant S as System
    participant RV as Independent reviewer (policies.publish)
    SO->>S: createAbacPolicyDraft(definition, rule_jsonb) — JSON Schema validation, allowlisted attributes/operators
    SO->>S: simulateAbacPolicy(draft, test vectors + sampled real grants) — diff allow→deny / deny→allow
    S-->>SO: report: N decisions change, privilege expansions flagged
    SO->>S: submit (checksum frozen, status submitted)
    RV->>S: publishAbacPolicyVersion(version, expected checksum) — requires MFA, reviewer ≠ author
    S->>S: transaction: supersede active version, activate new, audit, bump policy cache epoch
    RV->>S: rollback → re-activate previous approved version (new audit entry, no edit of history)
~~~

### 5.5 Role assignment with delegation ceiling
~~~mermaid
sequenceDiagram
    autonumber
    participant UA as Unit admin (Branch A)
    participant S as System
    participant AD as Central admin
    UA->>S: assignUserRole(user X, role editor, scope unit A, valid_until)
    S->>S: ceiling check: role.permissions ⊆ grantor's grantable permissions at scope ⊆ grantor scope
    S->>S: role.sensitivity = normal → apply directly, audit
    UA->>S: assignUserRole(user X, role org_admin, global)
    S-->>UA: 403 exceeds delegation ceiling (THR-016), denial audited
    UA->>S: assignUserRole(user Y, role approver, unit A)
    S->>S: role.sensitivity = sensitive → create access_change_request (pending)
    AD->>S: approve request (≠ requester, MFA) → assignment active, audit
~~~
Invariants: nobody grants to themselves; nobody grants permissions they don't hold as *grantable*; protected roles (`platform_owner`) only via dual control; the last active `platform_owner` cannot be revoked/disabled (THR-020).

### 5.6 No-SSH release pipeline
~~~mermaid
flowchart LR
    dev["Signed commit on main"] --> ci["Trusted build machine / CI: composer install --no-dev, npm ci && vite build"]
    ci --> qa["Quality gates: Pint, PHPStan/Larastan, Pest on PostgreSQL+RLS, composer audit, secret scan"]
    qa --> pkg["Artifact: app + vendor + public/build, no .env, SBOM, SHA-256"]
    pkg --> stg["Staging upload (SFTP/panel) + operator migration (awshortlink_migrator)"]
    stg --> uat["E2E + UAT + parent-site regression"]
    uat --> g15{"Gate 15 human Go/No-Go"}
    g15 -->|"Go"| bk["Backup + restore point"]
    bk --> prod["Upload new release dir, switch pointer (release dir swap)"]
    prod --> smoke["Smoke: /buka/health-probe slug, admin login, resolver 302"]
    smoke -->|"fail"| rb["Rollback: previous release dir, restore DB if contract changed"]
~~~

---

## 6. State machines

### 6.1 Link lifecycle and public HTTP mapping
~~~mermaid
stateDiagram-v2
    [*] --> draft: CreateLinkDraft
    draft --> submitted: SubmitLink
    submitted --> draft: RejectDestination / withdraw
    submitted --> scheduled: Approve (published_at in future)
    submitted --> active: Approve (published_at <= now)
    scheduled --> active: time reaches published_at
    active --> expired: time reaches expires_at
    active --> suspended: SuspendLink / EmergencySuspend
    suspended --> active: Reinstate (approval required)
    expired --> active: extend expiry (approval)
    active --> archived: ArchiveLink
    expired --> archived: ArchiveLink
    suspended --> archived: ArchiveLink
    draft --> discarded: delete never-published draft
    archived --> [*]
    discarded --> [*]
~~~
| State | Stored as | Public result | Slug reservation |
| --- | --- | --- | --- |
| draft / submitted | `status` | 404 | held while draft; released if discarded **and never published** |
| scheduled | `active` + `published_at > now()` (derived) | 404 | permanent |
| active | `active`, published, not expired | **302** | permanent |
| expired | `active` + `expires_at <= now()` (derived at request time, no cron needed) | 410 (tombstone) | permanent |
| suspended | `suspended` | 404 or 410 (DES-003) | permanent |
| archived | `archived` | 410 with retired message | permanent, never reused |
| unknown / malformed / reserved | — | 404 | — |
| DB unavailable | — | 503 | — |

Destination changes do **not** move the link out of `active`; they create a pending destination version (6.2).

### 6.2 Destination version lifecycle
~~~mermaid
stateDiagram-v2
    [*] --> proposed: ProposeDestination (policy verdict stored)
    proposed --> blocked: verdict = forbidden
    proposed --> pending_review: SubmitLink
    pending_review --> approved: ApproveDestination
    pending_review --> rejected: RejectDestination
    approved --> current: pointer swap (atomic)
    current --> superseded: newer version becomes current
    superseded --> current: rollback to previous approved version (new audit event)
    blocked --> [*]
    rejected --> [*]
~~~
A version row is immutable after `proposed` except its status; URL text never changes in place.

### 6.3 ABAC policy version lifecycle
~~~mermaid
stateDiagram-v2
    [*] --> draft
    draft --> simulated: simulate (report stored)
    simulated --> draft: edit (new checksum)
    simulated --> submitted: submit (checksum frozen)
    submitted --> rejected: reviewer rejects
    submitted --> approved: independent reviewer approves (MFA)
    approved --> active: activate (supersedes current)
    active --> superseded: newer version activated
    superseded --> active: rollback (approved versions only)
    active --> revoked: emergency revoke (falls back to previous active or deny)
    rejected --> [*]
~~~

### 6.4 User account lifecycle
~~~mermaid
stateDiagram-v2
    [*] --> invited: InviteUser (signed, expiring token)
    invited --> expired_invite: token TTL elapsed
    invited --> active: accept + set password + enrol MFA
    active --> suspended: SuspendUser (sessions + tokens revoked)
    suspended --> active: Reinstate (reason, audit)
    active --> disabled: DisableUser (offboarding)
    suspended --> disabled
    disabled --> [*]
~~~
`disabled` is terminal (identity kept for audit attribution; no login, no grants). Last active `platform_owner` cannot leave `active`.

### 6.5 Role assignment lifecycle
~~~mermaid
stateDiagram-v2
    [*] --> requested: sensitive role (change request)
    [*] --> active: normal role within ceiling
    requested --> active: independent approval
    requested --> denied
    active --> pending_start: valid_from in future (derived)
    active --> expired: valid_until reached (derived at evaluation time)
    active --> revoked: RevokeRole / user suspended
    expired --> [*]
    revoked --> [*]
    denied --> [*]
~~~
Expiry is evaluated at every authorization decision (`now() BETWEEN valid_from AND coalesce(valid_until,'infinity')`), so it works without cron.

---

## 7. Physical data design (PostgreSQL only)

### 7.1 Conventions (proposed, pending Gate 9)
- Schema `shortlink` for application objects; `public` schema not used by the app; `search_path` pinned per role.
- Primary keys: **UUIDv7** generated in the application (time-ordered, non-enumerable) — alternative BIGINT identity, see DES-001.
- Timestamps `timestamptz` stored UTC; UI renders `Asia/Pontianak` (WIB) — consistent with data-model.md.
- Every mutable aggregate has `version integer NOT NULL DEFAULT 1` for optimistic locking (`If-Match`).
- Enumerations as `text` + `CHECK` (cheaper migrations than PG enums).
- Soft delete only where data-model.md allows; audit/approval tables are append-only (no UPDATE/DELETE grant).

### 7.2 Unit hierarchy: closure table (proposed, pending Gate 9)
Units form a tree (the organisation → Bidang → branch/unit). Options: recursive CTE, `ltree`, closure table. **Proposal: closure table `unit_closure(ancestor_id, descendant_id, depth)`**, because:
1. RLS predicates stay non-recursive and index-friendly; recursive CTEs inside policies are fragile and slow (postgresql-rls-design.md warns against recursive policy queries).
2. The application expands an actor's descendant units **once per request** and passes them in `app.unit_ids`; policies then do a simple `= ANY(...)`.
3. `ltree` requires an extension that the shared host may not provide (HOST audit #1); the closure table needs no extension.
Maintenance (insert/move unit) is an operator/central-admin Action that rewrites closure rows in one transaction with audit.

### 7.3 DDL sketch (illustrative — not a migration)
~~~sql
-- Context helpers: STABLE, SECURITY INVOKER, fixed search_path; missing context => NULL => deny.
CREATE FUNCTION shortlink.ctx_actor() RETURNS uuid LANGUAGE sql STABLE
  SET search_path = pg_catalog AS
$$ SELECT NULLIF(current_setting('app.actor_id', true), '')::uuid $$;

CREATE FUNCTION shortlink.ctx_unit_ids() RETURNS uuid[] LANGUAGE sql STABLE
  SET search_path = pg_catalog AS
$$ SELECT CASE WHEN coalesce(current_setting('app.unit_ids', true), '') = '' THEN ARRAY[]::uuid[]
              ELSE string_to_array(current_setting('app.unit_ids', true), ',')::uuid[] END $$;

CREATE FUNCTION shortlink.ctx_is_global() RETURNS boolean LANGUAGE sql STABLE
  SET search_path = pg_catalog AS
$$ SELECT coalesce(current_setting('app.scope', true), '') = 'global'
          AND NULLIF(current_setting('app.actor_id', true), '') IS NOT NULL $$;

CREATE TABLE shortlink.units (
  id uuid PRIMARY KEY, parent_id uuid REFERENCES shortlink.units(id) ON DELETE RESTRICT,
  code text NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9_]{2,32}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 2 AND 160),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  version int NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.unit_closure (
  ancestor_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
  descendant_id uuid NOT NULL REFERENCES shortlink.units(id) ON DELETE RESTRICT,
  depth smallint NOT NULL CHECK (depth >= 0),
  PRIMARY KEY (ancestor_id, descendant_id));
CREATE INDEX ON shortlink.unit_closure (descendant_id);

CREATE TABLE shortlink.users (
  id uuid PRIMARY KEY, name text NOT NULL, email text NOT NULL CHECK (email = lower(email)) UNIQUE,  -- stored lowercased; citext avoided (extension may be unavailable)
  password_hash text, status text NOT NULL DEFAULT 'invited'
    CHECK (status IN ('invited','active','suspended','disabled')),
  mfa_enrolled_at timestamptz, last_login_at timestamptz, disabled_at timestamptz,
  is_protected_owner boolean NOT NULL DEFAULT false,
  version int NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.user_unit_memberships (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES shortlink.users(id),
  unit_id uuid NOT NULL REFERENCES shortlink.units(id),
  valid_from timestamptz NOT NULL DEFAULT now(), valid_until timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by uuid NOT NULL REFERENCES shortlink.users(id), reviewed_by uuid REFERENCES shortlink.users(id),
  CHECK (valid_until IS NULL OR valid_until > valid_from),
  CHECK (created_by <> user_id));                                -- cannot self-add

CREATE TABLE shortlink.roles (
  id uuid PRIMARY KEY, key text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{2,48}$'),
  label text NOT NULL, is_protected boolean NOT NULL DEFAULT false,
  sensitivity text NOT NULL DEFAULT 'normal' CHECK (sensitivity IN ('normal','sensitive','protected')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  owner_unit_id uuid REFERENCES shortlink.units(id), version int NOT NULL DEFAULT 1,
  created_by uuid REFERENCES shortlink.users(id), created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.permissions (
  id uuid PRIMARY KEY, key text NOT NULL UNIQUE CHECK (key ~ '^[a-z_]+(\.[a-z_]+)+$'),
  description text NOT NULL, risk text NOT NULL CHECK (risk IN ('low','medium','high','critical')),
  catalog_version int NOT NULL);                                -- seeded from config/permissions.php only

CREATE TABLE shortlink.role_permissions (
  role_id uuid NOT NULL REFERENCES shortlink.roles(id), permission_id uuid NOT NULL REFERENCES shortlink.permissions(id),
  grantable boolean NOT NULL DEFAULT false,                     -- may holder delegate this permission?
  granted_by uuid NOT NULL REFERENCES shortlink.users(id), reason text NOT NULL, granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_id, permission_id));

CREATE TABLE shortlink.user_role_assignments (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES shortlink.users(id), role_id uuid NOT NULL REFERENCES shortlink.roles(id),
  scope_type text NOT NULL CHECK (scope_type IN ('global','unit','unit_descendants','owned')),
  unit_id uuid REFERENCES shortlink.units(id),
  valid_from timestamptz NOT NULL DEFAULT now(), valid_until timestamptz,
  granted_by uuid NOT NULL REFERENCES shortlink.users(id), approved_by uuid REFERENCES shortlink.users(id),
  reason text NOT NULL, revoked_at timestamptz, revoked_by uuid REFERENCES shortlink.users(id),
  CHECK ((scope_type = 'global') = (unit_id IS NULL)),
  CHECK (granted_by <> user_id), CHECK (approved_by IS NULL OR approved_by <> granted_by),
  CHECK (valid_until IS NULL OR valid_until > valid_from));
CREATE INDEX ON shortlink.user_role_assignments (user_id) WHERE revoked_at IS NULL;

CREATE TABLE shortlink.abac_policy_definitions (
  id uuid PRIMARY KEY, key text NOT NULL UNIQUE, resource text NOT NULL, action text NOT NULL,
  current_version_id uuid, owner_unit_id uuid REFERENCES shortlink.units(id),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')));

CREATE TABLE shortlink.abac_policy_versions (
  id uuid PRIMARY KEY, definition_id uuid NOT NULL REFERENCES shortlink.abac_policy_definitions(id),
  version int NOT NULL, rule jsonb NOT NULL, checksum text NOT NULL,          -- sha256 of canonical JSON
  status text NOT NULL CHECK (status IN ('draft','simulated','submitted','approved','active','superseded','rejected','revoked')),
  simulation_report jsonb, authored_by uuid NOT NULL REFERENCES shortlink.users(id),
  approved_by uuid REFERENCES shortlink.users(id), activated_at timestamptz,
  CHECK (approved_by IS NULL OR approved_by <> authored_by),
  UNIQUE (definition_id, version));
CREATE UNIQUE INDEX one_active_policy ON shortlink.abac_policy_versions (definition_id) WHERE status = 'active';

CREATE TABLE shortlink.campaigns (
  id uuid PRIMARY KEY, unit_id uuid NOT NULL REFERENCES shortlink.units(id), code text NOT NULL,
  name text NOT NULL, status text NOT NULL CHECK (status IN ('planned','running','ended')),
  owner_id uuid NOT NULL REFERENCES shortlink.users(id), start_at timestamptz, end_at timestamptz,
  UNIQUE (unit_id, code));

CREATE TABLE shortlink.links (
  id uuid PRIMARY KEY, namespace text NOT NULL DEFAULT 'buka',
  unit_id uuid NOT NULL REFERENCES shortlink.units(id), creator_id uuid NOT NULL REFERENCES shortlink.users(id),
  campaign_id uuid REFERENCES shortlink.campaigns(id),
  slug_normalized text NOT NULL CHECK (slug_normalized ~ '^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$'
                                       AND position('--' IN slug_normalized) = 0),
  display_slug text NOT NULL, title text NOT NULL CHECK (length(title) BETWEEN 3 AND 160),
  current_destination_id uuid,                                  -- FK added below (same-link check)
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','submitted','active','suspended','archived')),
  visibility text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','unlisted')),
  published_at timestamptz, expires_at timestamptz, retired_public_message boolean NOT NULL DEFAULT true,
  version int NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at IS NULL OR published_at IS NULL OR expires_at > published_at),
  CHECK (status NOT IN ('active','suspended','archived') OR published_at IS NOT NULL),
  UNIQUE (namespace, slug_normalized), UNIQUE (id, unit_id));
CREATE INDEX ON shortlink.links (unit_id, created_at DESC);
CREATE INDEX ON shortlink.links (status, expires_at);

CREATE TABLE shortlink.link_destinations (
  id uuid PRIMARY KEY, link_id uuid NOT NULL, unit_id uuid NOT NULL,
  url_canonical text NOT NULL CHECK (url_canonical ~ '^https://' AND length(url_canonical) <= 2048),
  host_canonical text NOT NULL, risk_class text NOT NULL CHECK (risk_class IN ('low','medium','high','forbidden')),
  policy_verdict jsonb NOT NULL, status text NOT NULL
    CHECK (status IN ('proposed','blocked','pending_review','approved','rejected','current','superseded')),
  version int NOT NULL, proposed_by uuid NOT NULL REFERENCES shortlink.users(id),
  approved_by uuid REFERENCES shortlink.users(id), approved_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (link_id, unit_id) REFERENCES shortlink.links (id, unit_id),
  UNIQUE (link_id, version), UNIQUE (id, link_id));
ALTER TABLE shortlink.links ADD CONSTRAINT current_dest_same_link
  FOREIGN KEY (current_destination_id, id) REFERENCES shortlink.link_destinations (id, link_id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE shortlink.reserved_slugs (
  namespace text NOT NULL, slug_normalized text NOT NULL, initial_link_id uuid REFERENCES shortlink.links(id),
  reason text NOT NULL CHECK (reason IN ('system','published','policy')), reserved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (namespace, slug_normalized));                   -- never deleted for 'published'

CREATE TABLE shortlink.link_approvals (
  id uuid PRIMARY KEY, link_id uuid NOT NULL REFERENCES shortlink.links(id), unit_id uuid NOT NULL,
  destination_id uuid NOT NULL REFERENCES shortlink.link_destinations(id),
  actor_id uuid NOT NULL REFERENCES shortlink.users(id),
  action text NOT NULL CHECK (action IN ('submit','approve','reject','suspend','reinstate','emergency_suspend')),
  risk text NOT NULL, reason text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.link_audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,            -- monotonic order for the hash chain
  unit_id uuid, link_id uuid, actor_id uuid, action text NOT NULL, subject_type text NOT NULL, subject_id uuid,
  subject_version int, before_hash text, after_hash text, reason text, request_id uuid NOT NULL,
  policy_version_id uuid, occurred_at timestamptz NOT NULL DEFAULT now(),
  prev_hash text NOT NULL, row_hash text NOT NULL);              -- row_hash = sha256(prev_hash || canonical(row))
CREATE INDEX ON shortlink.link_audit_events (actor_id, occurred_at);
CREATE INDEX ON shortlink.link_audit_events (link_id, occurred_at);

CREATE TABLE shortlink.access_decision_audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor_id uuid, unit_id uuid, permission text NOT NULL,
  resource_type text NOT NULL, verdict text NOT NULL CHECK (verdict IN ('allow','deny')),
  reason_code text NOT NULL, policy_version_id uuid, occurred_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.link_daily_stats (
  link_id uuid NOT NULL REFERENCES shortlink.links(id), unit_id uuid NOT NULL, date_utc date NOT NULL,
  channel_code text NOT NULL DEFAULT '', valid_clicks bigint NOT NULL DEFAULT 0 CHECK (valid_clicks >= 0),
  suspected_bot bigint NOT NULL DEFAULT 0 CHECK (suspected_bot >= 0), rejected bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (link_id, date_utc, channel_code));

CREATE TABLE shortlink.link_qr_assets (
  id uuid PRIMARY KEY, link_id uuid NOT NULL REFERENCES shortlink.links(id), unit_id uuid NOT NULL,
  style_version int NOT NULL, output_format text NOT NULL CHECK (output_format IN ('svg','png')),
  encoded_url text NOT NULL, checksum text NOT NULL, generated_by uuid NOT NULL REFERENCES shortlink.users(id),
  created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE shortlink.api_credentials (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES shortlink.users(id), prefix text NOT NULL UNIQUE,
  secret_hash text NOT NULL, scopes text[] NOT NULL, expires_at timestamptz NOT NULL,
  last_used_at timestamptz, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());

-- Public resolver surface: only what a redirect needs.
CREATE VIEW shortlink.public_resolvable_links WITH (security_barrier = true) AS
SELECT l.id AS link_id, l.namespace, l.slug_normalized AS slug,
       CASE WHEN l.status = 'active' AND l.published_at <= now()
                 AND (l.expires_at IS NULL OR l.expires_at > now()) THEN 'active'
            WHEN l.status = 'archived' OR (l.status = 'active' AND l.expires_at <= now()) THEN 'retired'
            ELSE 'unavailable' END AS status,
       CASE WHEN l.status = 'active' AND l.published_at <= now()
                 AND (l.expires_at IS NULL OR l.expires_at > now()) THEN d.url_canonical END AS target_url,
       l.expires_at
FROM shortlink.links l
LEFT JOIN shortlink.link_destinations d ON d.id = l.current_destination_id AND d.status = 'current'
WHERE l.published_at IS NOT NULL;                                -- drafts never visible
~~~
The view is owned by a dedicated non-login role so that the resolver needs only `SELECT` on the view; RLS on `links` contains an explicit `TO awshortlink_resolver` SELECT policy limited to `published_at IS NOT NULL` as a second barrier (exact owner/invoker mechanics to be verified in #38 against the pinned PostgreSQL version; `security_invoker` views are available from PG 15).

### 7.4 RLS policy matrix (proposed)
Legend: **U** = `unit_id = ANY(ctx_unit_ids()) OR ctx_is_global()`; **A** = `user_id = ctx_actor()`; **—** = no policy ⇒ denied; *append* = INSERT only, no UPDATE/DELETE grant. All tables: `ENABLE` + `FORCE ROW LEVEL SECURITY`; missing context ⇒ zero rows.

| Table | Classification | app SELECT | app INSERT (WITH CHECK) | app UPDATE (USING / WITH CHECK) | app DELETE | resolver |
| --- | --- | --- | --- | --- | --- | --- |
| units | internal | U (on id) | global only | global only | — | — |
| unit_closure | internal | U (ancestor) | global only | — | global only (move) | — |
| users | internal/confidential (hash) | A or member of U units | global or unit admin (via Action) | A (profile cols via column GRANT) or U | — | — |
| user_unit_memberships | internal | A or U | U and `created_by = ctx_actor()` | U / U (unit_id immutable) | — | — |
| roles | sensitive internal | any authenticated actor | global | global | — | — |
| permissions | internal | any authenticated actor | — (migrator seeds) | — | — | — |
| role_permissions | sensitive | any authenticated actor | global | — (replace = delete+insert by global) | global | — |
| user_role_assignments | sensitive | A or U | U and `granted_by = ctx_actor()` and `user_id <> ctx_actor()` | U (revocation columns only) | — | — |
| abac_policy_definitions / versions | sensitive | actor with policies.read (global context) | global | global (status only) | — | — |
| access_change_requests | sensitive | A (requester/target) or U | U | U (decision cols) | — | — |
| links | internal (slug public) | U | U | U / U (unit_id immutable) | — | SELECT where `published_at IS NOT NULL` |
| link_destinations | internal (may hold sensitive URL) | U | U | U (status only) | — | via view only |
| reserved_slugs | public metadata | all authenticated | U-scoped Action | — | draft-only via Action | — |
| link_approvals | restricted | U | U, *append* | — | — | — |
| link_audit_events | restricted | U or auditor global | *append* | — | — | — |
| access_decision_audit | restricted | global (auditor/security) | *append* | — | — | — |
| link_daily_stats | aggregate internal | U | via `record_click()` only | via `record_click()` only | — | EXECUTE fn |
| link_qr_assets | internal | U | U | — | — | — |
| campaigns | internal | U | U | U | — | — |
| api_credentials | confidential | A or global | A | A (revoke) | — | — |

"global" means `ctx_is_global()`; the application sets `app.scope = 'global'` **only** after RBAC+ABAC confirm an active global grant for the requested permission — never as a blanket superuser flag (postgresql-rls-design.md forbids `OR true` policies). Fine-grained permission checks remain in Laravel; RLS guarantees the row boundary.

Illustrative policies:
~~~sql
ALTER TABLE shortlink.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE shortlink.links FORCE ROW LEVEL SECURITY;
CREATE POLICY links_sel ON shortlink.links FOR SELECT TO awshortlink_app
  USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY links_ins ON shortlink.links FOR INSERT TO awshortlink_app
  WITH CHECK ((unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
              AND creator_id = shortlink.ctx_actor());
CREATE POLICY links_upd ON shortlink.links FOR UPDATE TO awshortlink_app
  USING (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global())
  WITH CHECK (unit_id = ANY (shortlink.ctx_unit_ids()) OR shortlink.ctx_is_global());
CREATE POLICY links_resolver ON shortlink.links FOR SELECT TO awshortlink_resolver
  USING (published_at IS NOT NULL);
REVOKE ALL ON shortlink.links FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON shortlink.links TO awshortlink_app;   -- no DELETE
~~~
CI introspection (TST-017): every table in schema `shortlink` except an explicit allowlist must have `relrowsecurity AND relforcerowsecurity`, ≥1 policy per granted command, and `awshortlink_app` must not own any object nor have `rolbypassrls`.

---

## 8. ABAC rule DSL and evaluation

### 8.1 Design principles
Declarative JSON (stored in `abac_policy_versions.rule jsonb`), validated by a versioned JSON Schema; **no PHP, SQL, regex or template execution**; attributes and operators come from a source-controlled allowlist; effects `permit` / `deny` with **deny-overrides**; ABAC can only **restrict** what RBAC grants (an ABAC permit never creates a permission the actor lacks) — consistent with identity-rbac-abac.md "ALLOW only when … matching RBAC permission, valid ABAC constraints".

### 8.2 Schema (abridged JSON Schema 2020-12)
~~~json
{
  "$id": "https://awshortlink.local/schemas/abac-rule-v1.json",
  "type": "object",
  "required": ["schema_version", "target", "rules"],
  "properties": {
    "schema_version": { "const": 1 },
    "target": { "type": "object", "required": ["permissions"],
      "properties": { "permissions": { "type": "array", "items": { "type": "string", "pattern": "^[a-z_]+(\\.[a-z_]+)+$" }, "minItems": 1 } } },
    "rules": { "type": "array", "minItems": 1, "maxItems": 20, "items": { "$ref": "#/$defs/rule" } }
  },
  "$defs": {
    "rule": { "type": "object", "required": ["id", "effect", "condition", "reason_code"],
      "properties": {
        "id": { "type": "string", "pattern": "^[A-Z0-9-]{3,40}$" },
        "effect": { "enum": ["permit", "deny"] },
        "reason_code": { "type": "string", "pattern": "^[A-Z_]{3,60}$" },
        "condition": { "$ref": "#/$defs/expr" } } },
    "expr": { "oneOf": [
      { "type": "object", "required": ["all"], "properties": { "all": { "type": "array", "items": { "$ref": "#/$defs/expr" }, "maxItems": 10 } } },
      { "type": "object", "required": ["any"], "properties": { "any": { "type": "array", "items": { "$ref": "#/$defs/expr" }, "maxItems": 10 } } },
      { "type": "object", "required": ["not"], "properties": { "not": { "$ref": "#/$defs/expr" } } },
      { "type": "object", "required": ["op", "attr"],
        "properties": {
          "op": { "enum": ["eq", "neq", "in", "not_in", "lt", "lte", "gt", "gte", "is_true", "is_false"] },
          "attr": { "enum": ["actor.id", "actor.mfa_verified", "actor.account_status", "actor.unit_ids", "actor.role_keys",
                              "resource.unit_id", "resource.status", "resource.creator_id", "resource.risk_class",
                              "resource.sensitivity", "action", "env.now_hour_wib", "env.weekday", "env.emergency_mode",
                              "request.channel", "credential.scopes"] },
          "value": {}, "value_attr": { "type": "string" } } } ] }
  }
}
~~~
Max nesting depth 4 (validator-enforced). `value_attr` compares two attributes (e.g. `actor.id` neq `resource.creator_id`).

### 8.3 Example policies
~~~json
{ "schema_version": 1, "target": { "permissions": ["links.approve"] },
  "rules": [
    { "id": "SOD-1", "effect": "deny", "reason_code": "SELF_APPROVAL_FORBIDDEN",
      "condition": { "all": [ { "op": "eq", "attr": "actor.id", "value_attr": "resource.creator_id" },
                              { "op": "in", "attr": "resource.risk_class", "value": ["medium", "high"] } ] } },
    { "id": "SOD-2", "effect": "deny", "reason_code": "HIGH_RISK_REQUIRES_MFA",
      "condition": { "all": [ { "op": "eq", "attr": "resource.risk_class", "value": "high" },
                              { "op": "is_false", "attr": "actor.mfa_verified" } ] } } ] }
~~~
| Policy key | Target permissions | Rule (plain language) | Source |
| --- | --- | --- | --- |
| POL-LINK-SOD | links.approve | deny if approver = creator and risk ≥ medium; deny high risk without MFA | identity-rbac-abac.md scenario 4, THR-015 |
| POL-PRIV-MFA | users.disable, user_roles.assign, roles.permissions.update, policies.publish, links.suspend | deny when `actor.mfa_verified` is false | ADR-0006 |
| POL-UNIT-SCOPE | links.*, analytics.view | deny when `resource.unit_id` not in `actor.unit_ids` (defense-in-depth beside RLS) | THR-002 |
| POL-ARCHIVED-RO | links.update_draft, links.submit | deny when `resource.status` in [archived, suspended] | redirect-algorithm.md |
| POL-EMERGENCY | links.suspend | permit only (narrowing) when `env.emergency_mode` or role key ∈ [org_admin, approver] | threat-model abuse response |
| POL-OFFHOURS-EXPORT (example, optional) | analytics.export | deny outside 06–20 WIB | illustrates env attributes; adopt only if stakeholders want it |

### 8.4 Evaluation algorithm
~~~text
decide(actor, permission, resource, env):
  1. if actor.account_status != 'active' or session revoked        -> DENY(ACCOUNT_INACTIVE)
  2. grants = active assignments (now within validity, not revoked)
     matching = grants whose role holds `permission` and whose scope covers resource.unit_id
     if matching is empty                                            -> DENY(NO_RBAC_GRANT)
  3. policies = active ABAC versions whose target includes permission (cached per policy epoch)
     for each rule in each policy: evaluate condition (missing attribute => condition false for permit, TRUE for deny = fail closed)
     if any deny rule matches                                        -> DENY(rule.reason_code, policy_version)
  4. Laravel Policy method (state invariants, e.g. version match)    -> DENY(POLICY_<x>) on failure
  5. ALLOW(grant used, policy versions consulted)
  (6. PostgreSQL RLS enforces row boundary independently at query time.)
~~~
Decision object returned to callers and to the **Effective Access Inspector** (UI-016, `inspectEffectivePermissions`):
~~~json
{ "verdict": "deny", "permission": "links.approve", "resource": { "type": "link", "unit": "BRANCH-A", "id_redacted": true },
  "steps": [
    { "layer": "account", "result": "pass" },
    { "layer": "rbac", "result": "pass", "grant": "approver@unit:BRANCH-A (until 2027-01-31)" },
    { "layer": "abac", "result": "deny", "policy": "POL-LINK-SOD v3", "rule": "SOD-1", "reason_code": "SELF_APPROVAL_FORBIDDEN" },
    { "layer": "policy", "result": "skipped" } ],
  "evaluated_at": "2026-10-31T09:00:00+07:00" }
~~~
The inspector never returns resource titles/URLs from units the inspecting admin cannot see; it runs inside the inspector's own RLS context.

---

## 9. Permission catalog (source-controlled `config/permissions.php`)
| Resource | Actions |
| --- | --- |
| links | read_public, list_internal, create_draft, update_draft, submit, approve, reject, suspend, reinstate, archive, export |
| destinations | propose, view_history, rollback |
| qr | generate_public, generate_draft |
| analytics | view, export |
| campaigns | read, create, update, archive |
| audit | view, verify_chain, export |
| users | read, invite, update, suspend, disable, revoke_sessions |
| units | read, create, update, move, memberships.manage |
| roles | read, create, update, archive, permissions.update |
| permissions | read |
| user_roles | assign, revoke, approve_request |
| policies | read, create, simulate, submit, publish, rollback |
| access | inspect |
| api_keys | manage_own, manage_scoped |
| settings | security, domain_rules.manage |
| ops | health.view |

Default role grants (summary; authoritative matrix is [access-control.md](../docs/access-control.md), signed at Gate 9):
| Role | Core grants | Scope |
| --- | --- | --- |
| platform_owner (protected) | roles.*, permissions.read, policies.publish/rollback, settings.security, user_roles.approve_request, access.inspect | global, dual-control |
| org_admin | links.* , destinations.*, users.*, units.*, user_roles.assign/revoke (ceiling), analytics.*, audit.view, ops.health.view | global (mandate) |
| unit_admin | links.* except approve (P1 delegation), users.invite/read/suspend in own unit, units.memberships.manage, user_roles.assign (normal roles only), analytics.view, audit.view (unit) | unit_descendants |
| editor | links.create_draft/update_draft/submit, destinations.propose, qr.generate_draft, analytics.view (own links, DES-004) | unit / owned |
| approver | links.list_internal/approve/reject/suspend (delegated), destinations.view_history, qr.generate_public | unit |
| analyst | analytics.view/export (aggregate), campaigns.read | unit or global |
| auditor | audit.view/verify_chain, links.list_internal (read), access.inspect (read-only, scoped) | unit or global |
| authenticated_user | own profile, own sessions/MFA, api_keys.manage_own | self |

---

## 10. API design

### 10.1 Conventions (proposed, pending SPEC-08 #8)
- Base path **`/buka/api/v1`** (behind the same `/buka` delegation); JSON only; UTF-8; `Accept: application/json`.
- Errors: **RFC 9457** `application/problem+json` with `type`, `title`, `status`, `detail`, `instance`, plus `code` (stable machine code) and `errors[]` for field validation. Unauthorized cross-unit access returns **404** (not 403) to avoid existence leakage, per access-control.md.
- Concurrency: responses carry `ETag: "v{version}"`; mutations require `If-Match`; mismatch ⇒ **409** (`code: STALE_VERSION`); missing ⇒ **428**.
- Idempotency: `POST` that creates or transitions accepts `Idempotency-Key` (UUID, 24 h window, stored hashed per actor).
- Pagination: cursor-based `?cursor=&limit=` (max 100), `Link: <…>; rel="next"`.
- Rate limits (proposed initial values): API token 60 req/min/token; login 5/min/IP+account; resolver unknown-slug 404s throttled at web/WAF layer if available. Headers `RateLimit-Policy`/`RateLimit` (IETF draft) or `Retry-After` on 429.
- Every operation has `x-permission`; bearer token scopes may only narrow user rights.
- Audit: every non-GET call writes an audit event with `request_id` (`X-Request-Id` echoed).

### 10.2 Endpoint mapping (existing operationIds in openapi.yaml)
| Method & path | operationId | x-permission | UI | Issue |
| --- | --- | --- | --- | --- |
| GET /links | listLinks | links.list_internal | UI-002 | #15 |
| POST /links | createLink | links.create_draft | UI-003 | #15 |
| GET /links/{id} | getLink | links.list_internal | UI-004 | #15 |
| PATCH /links/{id} | updateLinkDraft | links.update_draft | UI-003 | #15 |
| POST /links/{id}/submit | submitLink | links.submit | UI-003/007 | #15, #27 |
| POST /links/{id}/approve | approveLink | links.approve | UI-007 | #27 |
| POST /links/{id}/suspend | suspendLink | links.suspend | UI-004/007 | #14, #27, #34 |
| GET /links/{id}/analytics | getLinkAnalytics | analytics.view | UI-006 | #17 |
| GET /links/{id}/qr | downloadLinkQr | qr.generate_public | UI-005 | #16 |
| GET /campaigns | listCampaigns | campaigns.read | UI-006 | #28 |
| GET /access/users | listManagedUsers | users.read | UI-011 | #39 |
| POST /access/users | inviteUser | users.invite | UI-011 | #39 |
| POST /access/users/{id}/roles | assignUserRole | user_roles.assign | UI-015 | #40 |
| GET /access/roles | listManagedRoles | roles.read | UI-012 | #40 |
| POST /access/roles | createManagedRole | roles.create | UI-012 | #40 |
| GET /access/permissions | listPermissionCatalog | permissions.read | UI-013 | #40 |
| PUT /access/roles/{id}/permissions | replaceRolePermissions | roles.permissions.update | UI-013 | #40 |
| GET /access/policies | listAbacPolicies | policies.read | UI-014 | #41 |
| POST /access/policies | createAbacPolicyDraft | policies.create | UI-014 | #41 |
| POST /access/policies/{id}/simulate | simulateAbacPolicy | policies.simulate | UI-014 | #41 |
| POST /access/policies/{id}/publish | publishAbacPolicyVersion | policies.publish | UI-014 | #41 |
| GET /access/effective-permissions | inspectEffectivePermissions | access.inspect | UI-016 | #42 |

### 10.3 Contract gaps to close in SPEC-08 [#8](https://github.com/ahliweb/awshortlink-laravel/issues/8)
| Gap | Needed by | Proposed operation |
| --- | --- | --- |
| Units & hierarchy, memberships | UI-017, #39 | `listUnits`, `createUnit`, `moveUnit`, `listUnitMemberships`, `addMembership`, `revokeMembership` |
| User lifecycle | UI-011, #39 | `suspendUser`, `reinstateUser`, `disableUser`, `revokeUserSessions`, `getManagedUser` |
| Role assignment revoke/list | UI-015, #40 | `listUserRoleAssignments`, `revokeUserRole`; access change requests `listAccessChangeRequests`, `decideAccessChangeRequest` |
| Policy lifecycle completeness | UI-014, #41 | `submitAbacPolicyVersion`, `rejectAbacPolicyVersion`, `rollbackAbacPolicy`, `listAbacPolicyVersions` |
| Link lifecycle completeness | UI-004, #15 | `archiveLink`, `reinstateLink`, `rejectLink`, `listLinkDestinations`, `proposeDestination`, `checkSlugAvailability` |
| Audit | UI-004/UI-001, #18 | `listAuditEvents`, `verifyAuditChain` |
| Analytics overview | UI-001/006, #17 | `getAnalyticsOverview` (unit/date filters, suppression flags) |
| Own workspace | UI-018 | `getMe`, `listMyGrants`, `listMySessions`, `revokeMySession` |
| Public landing / directory | UI-009, #20 | Not an API — public Blade routes; document as non-API in openapi `x-non-api-routes` note |
| Ops health | UI-010, #43 | `getSystemHealth` (admin-only, no secrets) |
| Destination pre-validation | UI-003, #13 | `validateDestination` (server-authoritative verdict + problem codes; no network fetch) |
| Review queue (P1) | UI-007, #27 | `listPendingReviews`, `requestLinkChanges` (reject covered by `rejectLink`) |
| Aggregate export (P1) | UI-006, #33 | `exportAnalyticsAggregate` (CSV-injection-safe, suppression applied) |
| Misuse report (P1) | UI-009, #34 | public `POST /buka/laporan` form route (rate-limited, CSRF) — non-API |
| Common components | all | Problem schema (RFC 9457), `ETag`/`If-Match`, `Idempotency-Key`, 401/403/404/409/412/422/428/429 examples |

---

## 11. Security architecture

### 11.1 URL canonicalization and destination policy pipeline (`UrlCanonicalizer` → `DestinationRiskClassifier`)
1. Reject input > 2048 chars, control characters, whitespace inside, backslashes.
2. Parse with a WHATWG/RFC 3986-compliant parser (library choice at #13), **not regex**; require absolute URL.
3. Scheme must be `https` (an `http` exception only for an approved institutional host — DES-008).
4. Reject userinfo (`user:pass@`), IP literals (v4/v6, including decimal/octal/hex forms), non-default ports, empty host, single-label hosts, `localhost`, `.local`, `.internal`.
5. Host → lowercase, IDNA UTS-46 to A-label (punycode); reject mixed-script/confusable labels or flag them `high`.
6. Normalize path percent-encoding (decode unreserved only), remove dot-segments, drop fragment.
7. Query: reject keys/values matching sensitive patterns — `token`, `access_token`, `sig`, `signature`, `password`, `session`, `nik`, `no_rm`, `rm`, 16-digit numerics (NIK-like), e-mail addresses — and any query whose total length > 512 (THR-004).
8. Classify risk:
   | Rule | Risk | Workflow |
   | --- | --- | --- |
   | Host on institutional allowlist (e.g. `example.org` and its subdomains, list owned by the organisation) | **low** | publish by holder of links.approve (may be the editor's supervisor) |
   | Other `*.go.id` / `*.ac.id` / approved government platform (e.g. survey service approved by DPO) | **medium** | approver ≠ creator |
   | Any other public host | **high** | approver ≠ creator, MFA, reason, optional expiry ≤ campaign end; listed in Review Queue |
   | Denylisted host, URL shortener, data/javascript/file schemes, credential patterns | **forbidden** | blocked, cannot be submitted |
9. Re-run the full pipeline on draft save, submit, approve and on every destination change; resolver re-checks invariants defensively (§5.1).
10. **No DNS/HTTP fetch** during canonicalization; the optional checker (#31) runs separately with SSRF controls (public-IP-only resolution, per-hop re-validation, egress allowlist, timeouts).

### 11.2 Web/session controls
- Admin: HTTPS only; `Secure; HttpOnly; SameSite=Lax` cookies under path `/buka`; session lifetime 30 min idle / 8 h absolute (proposed); session ID rotation at login and privilege change; **MFA** required for all staff (TOTP baseline, WebAuthn optional — DES-006); re-authentication (step-up) for privileged actions.
- Login throttling, generic error messages, account lockout with unlock by admin, password policy aligned with NIST SP 800-63B (length ≥ 12, breach-list check offline where feasible).
- CSP for admin: `default-src 'self'; script-src 'self' 'nonce-…'; style-src 'self' 'unsafe-inline'` (Livewire/Alpine compatibility to verify), `frame-ancestors 'none'`, `form-action 'self'`; public pages: strict CSP, no third-party scripts.
- Output escaping by Blade; titles stripped of control characters; QR SVG produced by generator, never from user SVG input.
- CSV export (P1) prefixes cells starting with `= + - @ \t \r` (THR-009).

### 11.3 Abuse and emergency suspend
`EmergencySuspend` (permission links.suspend, MFA) takes effect on the next request because the resolver reads authoritative DB state with no positive cache; it records reason, notifies security contact, and surfaces in the Review Queue for post-incident review. Misuse report form (#34) creates a triage item; it never auto-suspends without a human (to avoid denial-of-service by false reports) unless the reporter is a verified staff account with suspend rights.

### 11.4 Audit integrity
`row_hash = sha256(prev_hash ‖ canonical_json(row without hashes))`; `prev_hash` of the first row = sha256 of a deployment genesis constant. Rows are written by `AuditWriter` in the same transaction as the mutation (serialized by `SELECT … FOR UPDATE` on a single `audit_chain_head` row, acceptable at expected write volume). `AuditChainVerifier` (ops page + CLI) recomputes the chain; periodic export of the head hash to an off-system location (e.g. signed e-mail/report) gives tamper evidence even against DB admins. The runtime role has no UPDATE/DELETE on audit tables.

### 11.5 Secrets
`.env` outside webroot, created by operator on host (never in artifact or Git); `APP_KEY`, DB passwords per role, SMTP credentials; rotation procedure in operations-runbook.md; API tokens stored as SHA-256 hashes with visible prefix; no secrets in logs (Monolog processor redacts `password`, `token`, `authorization`, `cookie`).

### 11.6 Threat → control mapping
| THR | Threat (short) | Primary controls (this design) | Section |
| --- | --- | --- | --- |
| 001 | Open redirect / phishing via .go.id | Canonicalization, risk classes, approval, suspend | 11.1, 5.3 |
| 002 | Cross-unit edit | RBAC scope + POL-UNIT-SCOPE + RLS U policies | 5.2, 7.4 |
| 003 | Stolen credentials / token replay | MFA, step-up, hashed scoped tokens, revocation | 11.2 |
| 004 | PII/token leakage | Sensitive query rejection, no-referrer, no raw logging | 11.1, 12 |
| 005 | SSRF in checker | No fetch on resolve; P1 checker isolation | 11.1 |
| 006 | DoS / bot floods | Lean resolver, single indexed lookup, rate limits, bounded counters | 5.1, 10.1 |
| 007 | Slug reuse | `reserved_slugs` permanent, unique constraints | 7.3 |
| 008 | Exposed backups/.env | Artifact layout, webroot contains only public/ | 13 |
| 009 | CSV/XSS/SVG | Escaping, generated SVG only, CSV prefixing | 11.2 |
| 010 | Lost/altered audit | Same-transaction audit, hash chain, no UPDATE grant | 11.4 |
| 011 | Cron pile-up | Locks, bounded jobs, request-time expiry | 13 |
| 012 | Supply chain | composer.lock, audit, SBOM, checksums | 5.6 |
| 013 | Geolocation identifies citizen | No IP/geo storage | 12 |
| 014 | Host header poisoning | Trusted hosts/proxies, canonical APP_URL | 5.1 |
| 015 | Self-approval | POL-LINK-SOD, DB CHECK approved_by ≠ authored_by | 8.3 |
| 016 | Self/over-grant | Delegation ceiling, `granted_by <> user_id`, change requests | 5.5, 7.3 |
| 017 | Missing context / BYPASSRLS | Deny on NULL context, FORCE RLS, role introspection CI | 7.4 |
| 018 | Pool context leak | `set_config(…, true)` within transaction only | 5.2 |
| 019 | ABAC injection | Schema-validated DSL, no code, simulation + approval | 8 |
| 020 | Lingering access after disable | Session/token revocation, validity evaluated per decision, last-owner invariant | 6.4, 6.5 |
| 021 | Backup misses RLS rows | Dedicated backup identity (DES-010), row-count verification | 13 |

---

## 12. Analytics design
- **Event model:** none persisted per click by default. One atomic UPSERT per resolved GET increments `valid_clicks` or `suspected_bot` for `(link, UTC date, channel)` (§5.1). `channel_code` comes only from the *slug variant* (e.g. `campaign-ig`, `campaign-poster` linked to one campaign), never from visitor-supplied query params (P1 #28).
- **Bot classification in memory only:** request evaluated against (a) known crawler/preview UA tokens (e.g. link-preview fetchers of messaging apps, search bots), (b) missing `Accept-Language` + non-browser `Accept`, (c) HEAD/prefetch headers (`Purpose: prefetch`, `Sec-Purpose`). Result is a small integer class; the UA string, IP and headers are discarded after classification and never logged by the app. Classification is an **estimate** and labelled as such in UI-006.
- **Small-cohort suppression:** any displayed cell (link × day × channel) with value 1–9 shows "<10" in UI and exports; totals are computed from raw counts but shown only when ≥ 10 or when the viewer has `analytics.export` with DPO-approved purpose (DES-005). Zero is shown as 0.
- **Freshness:** counters are real-time; dashboards show "data as of" timestamp; dropped-counter events are counted in an ops metric and surfaced as a data-gap banner, never back-filled with fabricated values (ADR-0003).
- **Retention (proposed, DPO approval pending):** daily aggregates ≤ 13 months, then rolled into monthly totals; purge via scheduled job if cron exists, otherwise a documented manual operator task with evidence (#33).
- **Language:** UI says "klik valid (perkiraan)" / "dugaan bot" / "total permintaan" (as in the prototype UI-006), never "pengunjung unik" or "orang".

---

## 13. Deployment and operations

### 13.1 Topology options (from master-blueprint.md; selection at #1/#22)
| Option | Description | When | Key verification |
| --- | --- | --- | --- |
| A (preferred) | Laravel app outside webroot; `/buka/` directory in parent webroot contains only Laravel `public/` contents (index.php adjusted to app path); web server delegates `/buka/*` to it | Host supports per-directory front controller and rewrite | Parent `.htaccess` untouched; `/buka/livewire/*`, `/buka/build/*` reachable; other paths unchanged |
| B | Reverse proxy maps `/buka/*` to a dedicated subdomain/app host, external URL unchanged | Parent server is nginx/proxy-capable | `X-Forwarded-*` trusted only from proxy; Host header canonical |
| C | Separate approved host (VM/managed) serving `/buka` via B | Shared host lacks PHP 8.3/pgsql/rights | Institutional approval, cost |

### 13.2 Artifact structure
~~~text
awshortlink-<semver>-<sha>.zip
  app/ bootstrap/ config/ database/ resources/ routes/ vendor/ (no dev deps)
  public/            -> deployed to webroot /buka/ (index.php, build/, robots.txt, favicon)
  storage/ skeleton  -> outside webroot, writable
  RELEASE.json       version, git sha, build time, PHP/PG versions tested, migration list, checksum list
  SBOM.cdx.json      CycloneDX
  SHA256SUMS
(no .env, no tests, no node_modules, no .git)
~~~
Release directories are versioned (`releases/<version>`), with the webroot `index.php` pointing at the active release path; rollback = point back (no symlink assumption; a one-line PHP include path or panel directory switch, verified at #21).

### 13.3 Migration operator procedure (no SSH)
1. Backup (provider snapshot or `pg_dump -Fc` by `awshortlink_backup`), record checksum.
2. Operator runs migrations through the approved channel (panel PHP CLI cron job one-shot, pgAdmin/psql from operator workstation, or managed DB console) using `awshortlink_migrator` over a **direct** connection; never via HTTP.
3. Apply `database/sql/rls/*.sql` in order; run introspection query (`ops:rls-check` command or SQL script) and record output.
4. Expand/contract: additive migrations first; destructive changes only in a later release after backup-restore proof (AGENTS.md).

### 13.4 Backup / restore
Daily full `pg_dump -Fc` + provider PITR if available (RPO ≤ 15 min is aspirational); weekly restore rehearsal into staging verifying row counts per table, audit chain verification, `pg_policies` and GRANTs restored (THR-021). Backups encrypted, stored off-host, never under webroot.

### 13.5 Health, observability and SLOs
- `SystemStatus` page (UI-010, admin-only, `ops.health.view`): app version/sha, PHP version and extensions, DB reachable, PG version, RLS introspection result, scheduler heartbeat age, queue depth (if enabled), last backup timestamp entered by operator, audit chain head. No secrets, no env dump.
- External synthetic probe: a dedicated published probe slug (e.g. reserved `__probe`-style slug under policy) checked from Indonesian networks for 302 + latency; does not count in analytics (bot class `probe`).
- Logs: structured JSON to `storage/logs` (daily rotation, 14 days), request_id, route name, status, latency; slug logged, query string never.
- SLOs (proposed, baseline measurement first): resolver p95 ≤ 300 ms server time; availability ≥ 99.9 %/month; suspend effective on next request; zero cross-unit leakage findings.

### 13.6 Capacity estimate (assumptions, to be replaced by measurement)
Assumptions: ≤ 2 000 links, ≤ 200 staff accounts, campaign peak 50 redirects/s for 10 min (poster/QR + WhatsApp broadcast), ~30 000 redirects/day average. Each redirect = 1 indexed view lookup + 1 UPSERT ⇒ ~100 short statements/s at peak, well inside a modest PostgreSQL but potentially limited by shared-host PHP workers and DB connection caps (verify `max_connections` and PHP-FPM children at #1). Storage: daily stats ≈ 2 000 × 400 days × ~60 B ≈ 50 MB/year; audit ≈ < 1 GB/year.

---

## 14. Issue mapping and delivery plan

### 14.1 All issues → design sections
| # | Title (short) | Design sections | Expected deliverable |
| --- | --- | --- | --- |
| [#1](https://github.com/ahliweb/awshortlink-laravel/issues/1) | SPEC-01 Host audit PostgreSQL/pgsql/RLS/no-SSH | 2.2, 2.3, 13.1, 13.6 | HOST evidence, topology choice |
| [#2](https://github.com/ahliweb/awshortlink-laravel/issues/2) | SPEC-02 User research | 3.1 personas, 9 roles | Validated personas/JTBD |
| [#3](https://github.com/ahliweb/awshortlink-laravel/issues/3) | SPEC-03 STRIDE/DPIA | 11, 12 | Signed risk register, retention |
| [#4](https://github.com/ahliweb/awshortlink-laravel/issues/4) | SPEC-04 UI/UX prototype | 3.3 UI IDs, 6, 8.4 inspector | Validated prototype |
| [#5](https://github.com/ahliweb/awshortlink-laravel/issues/5) | SPEC-05 ERD PostgreSQL + IAM | 7 | Final DDL/dictionary |
| [#6](https://github.com/ahliweb/awshortlink-laravel/issues/6) | SPEC-06 RBAC/ABAC/units/RLS approval | 7.2, 7.4, 8, 9 | Signed matrix and policies |
| [#7](https://github.com/ahliweb/awshortlink-laravel/issues/7) | SPEC-07 Algorithms | 5.1, 6, 11.1 | Decision tables, test vectors |
| [#8](https://github.com/ahliweb/awshortlink-laravel/issues/8) | SPEC-08 OpenAPI/AsyncAPI | 10 | Gaps closed, mock server |
| [#9](https://github.com/ahliweb/awshortlink-laravel/issues/9) | SPEC-09 Gate 9 | 15 | Human decision record |
| [#10](https://github.com/ahliweb/awshortlink-laravel/issues/10) | P0-01 Scaffold Laravel 13 + Filament 5 | 4 | Skeleton, CI on PostgreSQL |
| [#11](https://github.com/ahliweb/awshortlink-laravel/issues/11) | P0-02 Filament /buka/admin auth/MFA | 3.2, 11.2 | Panel, MFA, sessions |
| [#12](https://github.com/ahliweb/awshortlink-laravel/issues/12) | P0-03 Migrations users/roles/ABAC/RLS/slug | 7.3 | Migrations + SQL |
| [#13](https://github.com/ahliweb/awshortlink-laravel/issues/13) | P0-04 URL canonicalization policy | 11.1 | `UrlCanonicalizer`, test corpus |
| [#14](https://github.com/ahliweb/awshortlink-laravel/issues/14) | P0-05 Resolver 302 fail-closed | 5.1, 6.1 | Resolver + view |
| [#15](https://github.com/ahliweb/awshortlink-laravel/issues/15) | P0-06 Link CRUD + versions | 3.3 Links, 5.3, 6.2 | LinkResource |
| [#16](https://github.com/ahliweb/awshortlink-laravel/issues/16) | P0-07 QR SVG/PNG | 3.3 QR | RenderQr |
| [#17](https://github.com/ahliweb/awshortlink-laravel/issues/17) | P0-08 Privacy analytics | 12 | Counters, dashboard |
| [#18](https://github.com/ahliweb/awshortlink-laravel/issues/18) | P0-09 Audit integrity | 11.4 | AuditWriter, verifier |
| [#19](https://github.com/ahliweb/awshortlink-laravel/issues/19) | P0-10 RBAC/ABAC enforcement | 5.2, 8.4 | AuthorizationPipeline |
| [#20](https://github.com/ahliweb/awshortlink-laravel/issues/20) | P0-11 Public landing/errors | 6.1, 3.3 Public | Error pages |
| [#21](https://github.com/ahliweb/awshortlink-laravel/issues/21) | P0-12 Immutable artifact | 5.6, 13.2 | Build script, SBOM |
| [#22](https://github.com/ahliweb/awshortlink-laravel/issues/22) | P0-13 /buka routing + Livewire prefix | 2.2 C-05/06, 13.1 | Routing proof |
| [#23](https://github.com/ahliweb/awshortlink-laravel/issues/23) | P0-14 Security CI/E2E/a11y | 7.4 CI, 11 | Pipelines |
| [#24](https://github.com/ahliweb/awshortlink-laravel/issues/24) | P0-15 Staging + UAT | 13 | Staging evidence |
| [#25](https://github.com/ahliweb/awshortlink-laravel/issues/25) | P0-16 Gate 15 | 5.6 | Signed Go/No-Go |
| [#26](https://github.com/ahliweb/awshortlink-laravel/issues/26) | P0-17 Production + ops | 13.5 | Live monitoring |
| [#27](https://github.com/ahliweb/awshortlink-laravel/issues/27) | P1-01 Approval workflow + emergency suspend | 5.3, 6.2, 11.3 | Review Queue |
| [#28](https://github.com/ahliweb/awshortlink-laravel/issues/28) | P1-02 Campaigns/channels | 12 | Campaign module |
| [#29](https://github.com/ahliweb/awshortlink-laravel/issues/29) | P1-03 CSV import/export | 11.2 | Dry-run importer |
| [#30](https://github.com/ahliweb/awshortlink-laravel/issues/30) | P1-04 REST API credentials | 10 | Token API |
| [#31](https://github.com/ahliweb/awshortlink-laravel/issues/31) | P1-05 Health checker (SSRF-safe) | 11.1 step 10 | Isolated checker |
| [#32](https://github.com/ahliweb/awshortlink-laravel/issues/32) | P1-06 Scheduler/queue | 3.2, 13.5 | Cron integration |
| [#33](https://github.com/ahliweb/awshortlink-laravel/issues/33) | P1-07 Reports/retention/export | 12 | Retention jobs |
| [#34](https://github.com/ahliweb/awshortlink-laravel/issues/34) | P1-08 Anti-abuse | 11.3 | Misuse report flow |
| [#35](https://github.com/ahliweb/awshortlink-laravel/issues/35) | P2-01 Multi-domain | `namespace` column, 7.3 | Feasibility ADR |
| [#36](https://github.com/ahliweb/awshortlink-laravel/issues/36) | P2-02 Link-in-bio / directory | 3.3 Public | Feasibility ADR |
| [#37](https://github.com/ahliweb/awshortlink-laravel/issues/37) | P2-03 Contextual redirects | 5.1 (deferred) | Feasibility ADR |
| [#38](https://github.com/ahliweb/awshortlink-laravel/issues/38) | P0-18 RLS DDL, DB roles, context | 3.2 roles, 5.2, 7.3, 7.4 | SQL + RLS tests |
| [#39](https://github.com/ahliweb/awshortlink-laravel/issues/39) | P0-19 User management | 6.4, 3.3 Identity | UserResource, UnitResource |
| [#40](https://github.com/ahliweb/awshortlink-laravel/issues/40) | P0-20 Roles/matrix/grants | 5.5, 6.5, 9 | RoleResource, matrix |
| [#41](https://github.com/ahliweb/awshortlink-laravel/issues/41) | P0-21 ABAC builder/simulation | 5.4, 6.3, 8 | Policy manager |
| [#42](https://github.com/ahliweb/awshortlink-laravel/issues/42) | P0-22 Access inspector + E2E security | 8.4 | Inspector, test suite |
| [#43](https://github.com/ahliweb/awshortlink-laravel/issues/43) | P0-23 PostgreSQL no-SSH ops acceptance | 13.3, 13.4 | Restore rehearsal evidence |

### 14.2 Vertical slices (after Gate 9 only; each slice = 11.1 frontend against mock → 11.2 backend/DB/security → 11.3 integration/E2E → PR review)
| Slice | Scope | Issues | Exit evidence |
| --- | --- | --- | --- |
| 0 Foundation | Scaffold, PostgreSQL-only CI, DB roles, RLS baseline, Filament auth+MFA, permission catalog, AuthorizationPipeline skeleton, audit writer | #10, #11, #12, #38, #19 (core), #18 (core) | No-context deny tests, role introspection green |
| 1 Secure redirect | Canonicalizer, resolver view, decision table, error pages | #13, #14, #20 (errors) | TST-001/003, latency baseline |
| 2 Link management | Link CRUD, destination versions, publish (P0 approval by role), suspend, audit UI | #15, #18 | TST-002/004/007 |
| 3 Managed IAM | Users/units, roles/matrix/grants, ABAC builder/simulation, inspector | #39, #40, #41, #42 | TST-015..019 |
| 4 QR + analytics | QR render/export, counters, dashboard with suppression | #16, #17 | TST-005/006 |
| 5 Public pages | Landing/directory (if approved), a11y pass | #20 | TST-009 |
| 6 Release | Artifact, routing proof, CI security/E2E, staging UAT, ops acceptance, Gate 15, production | #21, #22, #23, #24, #43, #25, #26 | TST-008, signed Gate 15 |
Slices 1 and 3 may proceed in parallel after slice 0; slice 6 work on #21/#22 should start early as spikes because they carry the largest hosting risk.

---

## 15. Design decisions (`DES-001..015` — locked in [ADR-0007](../docs/adr/0007-resolved-design-decisions-des-001-015.md) for Gate 9)
| ID | Decision needed | Options | Locked baseline ([ADR-0007](../docs/adr/0007-resolved-design-decisions-des-001-015.md)) |
| --- | --- | --- | --- |
| DES-001 | Primary key type | UUIDv7 / BIGINT identity | **Locked:** UUIDv7 (non-enumerable, merge-safe); audit tables (`link_audit_events`, `access_decision_audit`) `BIGINT GENERATED ALWAYS AS IDENTITY` for hash-chain ordering |
| DES-002 | Unit hierarchy model | closure table / ltree / adjacency + CTE | **Locked:** Closure table `shortlink.unit_closure` (§7.2) |
| DES-003 | Public response for suspended link | 404 / 410 | **Locked:** 404 (no signal to attacker); archived/expired → 410 |
| DES-004 | Editor access to analytics | own links / unit / none | **Locked:** Own links within assigned unit (access-control.md) |
| DES-005 | Small-cohort threshold | k = 5 / 10 / none | **Locked:** $k = 10$ |
| DES-006 | MFA method | TOTP / WebAuthn / both | **Locked:** TOTP mandatory baseline, WebAuthn optional |
| DES-007 | Raw click events | off / ≤ 30 days minimal | **Locked:** Off (ADR-0003) |
| DES-008 | `http://` institutional exception | allow / never | **Locked:** Never unless a named host lacks TLS and DPO approves with expiry |
| DES-009 | P0 approval model before #27 | role-based publish / full queue | **Locked:** Role-based publish + SoD ABAC policy (`POL-LINK-SOD`) |
| DES-010 | Backup identity vs RLS | BYPASSRLS backup role / owner-run dump / provider snapshot | **Locked:** Dedicated `awshortlink_backup` role with `BYPASSRLS` (operator window only) or verified provider snapshot + mandatory row-count & `pg_policies` restore check |
| DES-011 | Counter write path | direct UPSERT / buffer table + cron | **Locked:** Direct UPSERT via `shortlink.record_click(uuid, smallint)`; buffer only if load test shows contention |
| DES-012 | Admin session lifetimes | — | **Locked:** 30 min idle / 8 h absolute |
| DES-013 | Slug length/charset | 3–64 `[a-z0-9-]` (current) | **Locked:** Lowercase ASCII `[a-z0-9-]`, length 3–64; no Unicode slugs in MVP |
| DES-014 | Allowlist ownership | Organisation IT | **Locked:** Organisation IT with the communications office |
| DES-015 | API exposure in P0 | internal only / external | **Locked:** Internal service contract in P0 (Filament + contract tests); external API tokens P1 (#30) |

---

## 16. References
- Laravel 13 documentation — https://laravel.com/docs/13.x (authorization, database, deployment)
- Filament 5 documentation — https://filamentphp.com/docs/5.x
- PostgreSQL Row Security Policies — https://www.postgresql.org/docs/current/ddl-rowsecurity.html ; CREATE POLICY — https://www.postgresql.org/docs/current/sql-createpolicy.html ; `set_config` — https://www.postgresql.org/docs/current/functions-admin.html
- OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-162, Guide to ABAC — https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- NIST SP 800-63B, Digital Identity Guidelines — https://pages.nist.gov/800-63-4/
- RFC 9110 HTTP Semantics — https://www.rfc-editor.org/rfc/rfc9110
- RFC 9457 Problem Details for HTTP APIs — https://www.rfc-editor.org/rfc/rfc9457
- RFC 3986 URI Generic Syntax — https://www.rfc-editor.org/rfc/rfc3986 ; WHATWG URL — https://url.spec.whatwg.org/
- UTS #46 IDNA Compatibility Processing — https://www.unicode.org/reports/tr46/
- ISO/IEC 25010:2023 Product quality model — https://www.iso.org/standard/78176.html
- C4 model — https://c4model.com/
- JSON Schema 2020-12 — https://json-schema.org/draft/2020-12
- CycloneDX SBOM — https://cyclonedx.org/
- UU No. 27/2022 PDP — https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022

*Document status: draft for SPEC review (#5, #6, #7, #8) and Gate 9 (#9). No implementation, deployment or validation is claimed.*
