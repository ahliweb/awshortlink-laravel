# GitHub Backlog & Release Roadmap — 2026-10-31

**43 issues created and verified as of 2026-10-31.** This is a planning backlog, not a claim of implementation. Per [workflow-gates.md](workflow-gates.md), implementation issues are **blocked until #9 Gate 9 GO**. Human Go/No-Go for production at #25. All issue numbers below are real GitHub issues.

## 1 — Discovery/specification (work can start)
| Step | Issue | Objective |
| --- | --- | --- |
| 1 / host prerequisite | [#1 SPEC-01](https://github.com/ahliweb/awshortlink-laravel/issues/1) | Host compatibility and official domain operator permission |
| 2 | [#2 SPEC-02](https://github.com/ahliweb/awshortlink-laravel/issues/2) | Research users and PRD |
| 3 | [#3 SPEC-03](https://github.com/ahliweb/awshortlink-laravel/issues/3) | Threat model, DPIA, classification and retention |
| 4 | [#4 SPEC-04](https://github.com/ahliweb/awshortlink-laravel/issues/4) | Clickable UX prototype, human usability validation |
| 5 | [#5 SPEC-05](https://github.com/ahliweb/awshortlink-laravel/issues/5) | ERD + data dictionary + DB portability |
| 6 | [#6 SPEC-06](https://github.com/ahliweb/awshortlink-laravel/issues/6) | Roles, ABAC and isolation |
| 7 | [#7 SPEC-07](https://github.com/ahliweb/awshortlink-laravel/issues/7) | Deterministic resolver and URL safety algorithms |
| 8 | [#8 SPEC-08](https://github.com/ahliweb/awshortlink-laravel/issues/8) | OpenAPI/AsyncAPI mocks and review |
| 9 | [#9 SPEC-09](https://github.com/ahliweb/awshortlink-laravel/issues/9) | Human Definition of Ready (hard gate) |

## 2 — MVP P0 (blocked until Gate 9)
| Group | Issues | Dependencies |
| --- | --- | --- |
| Foundation | [#10 Laravel 13](https://github.com/ahliweb/awshortlink-laravel/issues/10), [#11 Filament](https://github.com/ahliweb/awshortlink-laravel/issues/11), [#12 DB](https://github.com/ahliweb/awshortlink-laravel/issues/12) | #9, then #10 |
| Secure redirect | [#13 URL policy](https://github.com/ahliweb/awshortlink-laravel/issues/13), [#14 resolver](https://github.com/ahliweb/awshortlink-laravel/issues/14) | #12, #13 |
| Admin & access | [#15 Link CRUD](https://github.com/ahliweb/awshortlink-laravel/issues/15), [#18 Audit](https://github.com/ahliweb/awshortlink-laravel/issues/18), [#19 RBAC/ABAC enforcement](https://github.com/ahliweb/awshortlink-laravel/issues/19), [#39-42 IAM management](https://github.com/ahliweb/awshortlink-laravel/issues/39) | #11, #12, #13, #38 |
| User features | [#16 QR](https://github.com/ahliweb/awshortlink-laravel/issues/16), [#17 analytics](https://github.com/ahliweb/awshortlink-laravel/issues/17), [#20 public pages](https://github.com/ahliweb/awshortlink-laravel/issues/20) | #14, #15 |
| Release readiness | [#21 artifact](https://github.com/ahliweb/awshortlink-laravel/issues/21), [#22 path/Livewire](https://github.com/ahliweb/awshortlink-laravel/issues/22), [#23 CI/tests](https://github.com/ahliweb/awshortlink-laravel/issues/23) | #10, #14, #11 |
| Staging, release, operations | [#24 staging/UAT](https://github.com/ahliweb/awshortlink-laravel/issues/24), [#25 Gate 15](https://github.com/ahliweb/awshortlink-laravel/issues/25), [#26 production](https://github.com/ahliweb/awshortlink-laravel/issues/26) | #21-23, then signed #25 |

## 3 — P1 enhancement backlog (after stable P0)
- [#27 Approval](https://github.com/ahliweb/awshortlink-laravel/issues/27) — separation of duties and review queue.
- [#28 Campaigns](https://github.com/ahliweb/awshortlink-laravel/issues/28) — reporting by unit/program/channel.
- [#29 CSV](https://github.com/ahliweb/awshortlink-laravel/issues/29) — safe bulk import/export.
- [#30 API](https://github.com/ahliweb/awshortlink-laravel/issues/30) — scoped token endpoints.
- [#31 Checker](https://github.com/ahliweb/awshortlink-laravel/issues/31) — SSRF-hardened safe target monitoring (cron-dependent).
- [#32 Cron](https://github.com/ahliweb/awshortlink-laravel/issues/32) — bounded scheduler and workers.
- [#33 Reports/retention](https://github.com/ahliweb/awshortlink-laravel/issues/33) — role-safe aggregate export and privacy schedule.
- [#34 Anti-abuse](https://github.com/ahliweb/awshortlink-laravel/issues/34) — incident/report abuse response.

## 4 — P2 feasibility only
- [#35 Multi-domain](https://github.com/ahliweb/awshortlink-laravel/issues/35).
- [#36 Link-in-bio](https://github.com/ahliweb/awshortlink-laravel/issues/36).
- [#37 Contextual redirects](https://github.com/ahliweb/awshortlink-laravel/issues/37).

## Critical execution DAG
~~~mermaid
flowchart LR
    HOST["#1 Hosting"] --> SPEC["#2-8 Requirements + UX + Contracts"]
    SPEC --> G9{"#9 Gate 9 Go?"}
    G9 -->|approved| FND["#10-12 Foundation"]
    FND --> SEC["#13-15 URL safety, Resolver, Admin"]
    SEC --> MVP["#16-20 QR, Analytics, Audit, RBAC, Public"]
    MVP --> QA["#21-23 Artifact, Prefix, CI"]
    QA --> STG["#24 Staging / UAT"]
    STG --> G15{"#25 Gate 15 Go?"}
    G15 -->|approved| PROD["#26 Production + Ops"]
    PROD --> ENH["#27-34 P1"]
    ENH --> ADV["#35-37 P2"]
~~~

## Work tracking policy
No implementation before signed Gate 9 despite issues already existing. Every implemented slice follows **11.1 frontend/mock → 11.2 backend → 11.3 integration** with PR/CI review at each slice. Track issue dependencies and acceptance in issue descriptions. At Gate 15 a named human release owner approves and records evidence. Do not mark issue done based solely on a document or a plan.


## 2026-10-31 — Binding PostgreSQL and IAM expansion
PostgreSQL is the sole DB for local/test/staging/production. ADR-0004 was superseded by ADR-0005; RLS is mandatory for unit-scoped and IAM tables. RBAC+ABAC are managed P0 functionality for admin and authenticated user levels—not solely role checks. Existing relevant issues #1-15, #17-30, #33-35 were updated to match. Six **new P0 implementation issues** (blocked until Gate 9):

| Issue | Title | Dependencies |
| --- | --- | --- |
| [#38](https://github.com/ahliweb/awshortlink-laravel/issues/38) | PostgreSQL RLS DDL, roles, context and pool safety | #1,#5,#6,#9,#12,#19 |
| [#39](https://github.com/ahliweb/awshortlink-laravel/issues/39) | User management and organizational membership | #9-12,#19 |
| [#40](https://github.com/ahliweb/awshortlink-laravel/issues/40) | Role/permission management with delegated scoped assignments | #9-12,#19,#39 |
| [#41](https://github.com/ahliweb/awshortlink-laravel/issues/41) | ABAC policy builder, validation, simulation, approval, rollback | #6,#8-12,#19,#40 |
| [#42](https://github.com/ahliweb/awshortlink-laravel/issues/42) | Effective access inspector and end-to-end RBAC/ABAC/RLS tests | #19,#23,#38-41 |
| [#43](https://github.com/ahliweb/awshortlink-laravel/issues/43) | PostgreSQL-only no-SSH migrations/backup/restore operations | #1,#9,#12,#21,#38 |

**Recommended secure P0 sequence:** SPEC #1-9 → #10-12 → #38 (PostgreSQL security base) + #19 (enforcement framework) → #39-41 (managed IAM) → #42 access test → #21-24/#43 staging/infrastructure → #25 human release gate → #26 production. Work per vertical slice with frontend mock → backend → E2E and review. The original DAG above depicts broad phases; this detailed sequence controls access dependencies.
