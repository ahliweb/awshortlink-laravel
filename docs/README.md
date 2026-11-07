# Dokumentasi AW Shortlink

## Metadata

- Version: `v1.1.0`
- Last updated: `2026-11-03`
- Changeset: `Pembaruan rilis minor SemVer v1.1.0: implementasi pelaporan penyalahgunaan publik (/buka/laporan) dengan tombol lapor per hasil pencarian & 5 kategori kendala, triase insiden admin (/buka/admin/reports), toggle visibilitas publik/tersembunyi, analitik detail telemetri per link, dan visualisasi grafik dasbor SVG.`

**Status:** Upstream `v1.1.0` — imported from the first production deployment and generalised for any organisation.

> **Provenance & scope.** These documents were written for the first production deployment and describe the *target* architecture (ADRs mention Laravel 13 / Filament 5). The code in this repository is a dependency-light PHP 8.3 application with a Laravel-style layout (`composer.json` requires only a QR library); migrating onto `laravel/framework` + Filament is roadmap, not current state. Governance records (gates, sign-offs, traceability) are history of the origin deployment — use them as templates for yours. Organisation-specific content (names, hosts, units, staff, officials, operational manuals) has been removed; see `README.md` and `SECURITY.md`.

| Path | Deliverable | Workflow |
| --- | --- | --- |
| master-blueprint.md | Vision, boundary, architecture, NFR, C4 and hosting decision | 1 |
| [../design/system-design.md](../design/system-design.md) | Detailed system design: C4 L1-L3 modules, request flows, state machines, PostgreSQL DDL/RLS sketch, ABAC DSL, API mapping and gaps, security, issue #1-#43 mapping, open decisions DES-* | 1,5-8 |
| prd.md | Personas, JTBD, feature requirements and acceptance criteria | 2 |
| threat-model-privacy.md | STRIDE, DPIA questions, privacy and retention | 3 |
| ui-ux.md | Information architecture, wireframe states, usability protocol | 4 |
| [../design/ui-ux-design-system.md](../design/ui-ux-design-system.md) | Design tokens, components, screen↔API↔permission map, a11y checklist, Filament mapping | 4 |
| data-model.md | PostgreSQL-only schema, RLS and access management entities | 5 |
| postgresql-rls-design.md | PostgreSQL-only, mandatory RLS, roles, pooling, no-SSH migration | 5,6,13 |
| identity-rbac-abac.md | Admin/user management, role/permission matrix, ABAC rule workflow | 4,6,8 |
| access-control.md | RBAC/ABAC/tenant scoping and test matrix | 6 |
| redirect-algorithm.md | Redirect policy, lifecycle invariants, status table | 7 |
| api/openapi.yaml | Contract-first REST API (`API-001..058`, RFC 9457, `x-permission`, `x-ui-screens`) | 8 |
| api/asyncapi.yaml | Domain & security events (`EVT-001..006`, producer/consumers/version) | 8 |
| [../design/mock-server/](../design/mock-server/README.md) | Contract-generated OpenAPI mock server & Gate 9 verifier (`verify-contract.mjs`) | 8, 9 |
| workflow-gates.md | DoR and release Go/No-Go checklists | 9,15 |
| deployment-no-ssh.md | Host audit, packaging, install, migration, rollback | 13-17 |
| testing-quality.md | Test pyramid, security, performance, acceptance | 11-17 |
| operations-runbook.md | Monitor, security response, backup & restore | 18 |
| sop-pengelolaan-tautan.md | Standar Operasional Prosedur (SOP AP) PermenPAN-RB No. 35/2012, SPBE & UU PDP | 18 |
| panduan-sistem-lengkap.md | Manual panduan teknis operasional lengkap v1.1.0 (MD, HTML, PDF) | 18 |
| compliance-standards.md | Indonesian regulation, ISO guidance, source URLs | 3,15 |
| decision-log.md | Open architecture and institutional decisions | all |
| adr/ | Architecture decisions | all |
| issue-roadmap.md | Actual GitHub issue numbers, priorities and execution DAG | 10-18 |
| traceability.md | REQ → UI/API/model/policy → issue → test | 9,15 |

## Scope taxonomy
**P0** usable safely on verified host: secure short link, custom slug, edit destination with versioning, expiration, Filament authentication/authorization, basic QR, aggregate clicks, audit, simple directory, error pages, deployment/backup.
**P1** approvals, campaigns, UTM, CSV, health checks (when cron), analytics breakdown, API tokens, scheduled reporting.
**P2** branded templates, link-in-bio, multiple managed domains, advanced contextual rules and webhooks.

## Quality policy
Requirement IDs REQ-*, threats THR-*, PII-*, UI-*, table names, API operation IDs, tests TST-* and issue links must trace both ways. Unreviewed mockups and hosting assumptions are blockers at Gate 9. Track UI acceptance by **actual** the organisation stakeholders; do not substitute AI-generated illustrations for validation.

## Architecture decisions
See [ADR index](adr/README.md); all ADRs currently proposed and not approved.

## Primary references
- Laravel: https://laravel.com/docs/13.x
- Filament: https://filamentphp.com/docs/5.x
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- Internal cross-portfolio standard process: owner's internal development-flow standard

## Changelog

### 2026-11-03 - v1.1.0

- Pembaruan dokumen indeks dan implementasi minor release v1.1.0 (pelaporan penyalahgunaan, triase admin, toggle visibilitas publik/tersembunyi, analitik telemetri per link, grafik tren kunjungan SVG).

### 2026-10-31 - v1.0.0

- Baseline awal indeks dokumentasi master blueprint dan deliverable AW Shortlink.
