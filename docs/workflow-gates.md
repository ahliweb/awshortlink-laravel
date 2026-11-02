# Delivery Lifecycle, Definition of Ready (Gate 9) & Go/No-Go (Gate 15)

**Authority:** `ahliweb/personal-coding`, `docs/alur-pengembangan-produk.md` version `v2.1.1` as reviewed 2026-11-01.
**Gate 9 Status: APPROVED (GO) — 2026-11-01.**
**Gate 15 Status: APPROVED (GO) — 2026-11-01 (`DEC-021`, `v1.0.0`).** All 43 issues (`#1`–`#43`) are completed, verified, and signed off.

## 18-step workflow
1 Master blueprint/C4/NFR/ADRs; 2 research & PRD; 3 threat/privacy; 4 UI prototype and user validation; 5 ERD/dictionary; 6 RBAC/ABAC/isolation; 7 algorithm decision table; 8 API contracts and mocks; **9 Gate Definition of Ready**; 10 atomic issues; 11.1 frontend with mock -> 11.2 backend -> 11.3 integrations/E2E; 12 PR/review/CI per slice; 13 staging; 14 internal human UAT; **15 release readiness Go/No-Go**; 16 production (authorized human); 17 verification; 18 monitoring/post-release.

---

## Gate 9 — Cross-Spec Review / Definition of Ready ([#9](https://github.com/ahliweb/awshortlink-laravel/issues/9))

### A. Technical Specification & Cross-Spec Consistency Checks (`alur-pengembangan-produk.md` §3) — **VERIFIED PASS (2026-11-01)**
- [x] **Bidirectional Traceability (`REQ-*` → `UI-*` → `TBL-*` → `PERM-*`/`RLS-*` → `ALG-*` → `API-*`/`EVT-*` → `ISS-*` → `TST-*`):** All 25 requirements (`REQ-001..025`) traced in [traceability.md](traceability.md) with zero orphan items.
- [x] **No Screen Without Contract Data Source (`layar_tanpa_sumber_data_kontrak`):** All 18 screens (`UI-001..018`) mapped to `API-001..058` or `x-non-api-routes` in [openapi.yaml](api/openapi.yaml) and [ui-ux-design-system.md](../design/ui-ux-design-system.md).
- [x] **No Endpoint Without Permission (`endpoint_tanpa_permission`):** All 58 OpenAPI operations (`API-001..058`) declare explicit `x-permission` bindings matching `PERM-001..062` in [access-control.md](access-control.md).
- [x] **No Table Without Classification (`tabel_tanpa_klasifikasi`):** All 22 PostgreSQL tables (`TBL-001..022`) have explicit classification, PK type (`UUIDv7` / `BIGINT` per `DES-001`), and `RLS-001..022` policies in [data-model.md](data-model.md) and [postgresql-rls-design.md](postgresql-rls-design.md).
- [x] **No PII Column Without Retention & Subject Rights (`kolom_PII_tanpa_retensi`):** All 7 PII elements (`PII-001..007`) have explicit retention schedules and data-subject rights mechanisms in [data-model.md](data-model.md) and [threat-model-privacy.md](threat-model-privacy.md) (`DPIA-001..008`).
- [x] **AsyncAPI Events Have Producer, Consumers & Schema Version:** All 6 domain/security events (`EVT-001..006`) declare `x-producer`, `x-consumers`, and `schemaVersion: 1` in [asyncapi.yaml](api/asyncapi.yaml).
- [x] **Contract-Driven Mock Server (`design/mock-server/`):** Generated directly from [openapi.yaml](api/openapi.yaml) (`server.mjs`) and verified automatically across all 58 operations + negative `401`/`403`/`404`/`409`/`428` tests (`node design/mock-server/verify-contract.mjs` → `PASS`).
- [x] **Resolver & Security Algorithms + Test Vectors (`SPEC-07`):** `ALG-001..005` and 24 deterministic test vectors (`TV-001..024`) locked in [redirect-algorithm.md](redirect-algorithm.md).
- [x] **Open Design Decisions (`DES-001..015`) & Local/CI Target Environment:** Locked in [ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md) and [decision-log.md](decision-log.md) (`DEC-017`, `DEC-018`).
- [x] **Second-Pass Security & Privacy Re-Review:** Completed over finalized UI, schema, and API contracts in [threat-model-privacy.md](threat-model-privacy.md).
- [x] **WCAG 2.2 AA Design System & 54-Screen Clickable Prototype:** Delivered in [ui-ux-design-system.md](../design/ui-ux-design-system.md), prototype/, and visual/. *(origin-deployment artefact; not included in this upstream)*

### B. Institutional & Human Sign-Off Items (Signed Off for Phase II Implementation — 2026-11-01)
- [x] **UXT-001..014 Prototype & Screen State Acceptance:** 54-screen clickable prototype (design/prototype/) and WCAG 2.2 AA design system ([ui-ux-design-system.md](../design/ui-ux-design-system.md)) accepted as Phase II baseline (`#2`, `#4`); live build UAT scheduled at Step 14 (`#24`) prior to Gate 15. *(origin-deployment artefact; not included in this upstream)*
- [x] **Institutional Governance & DPIA Baseline Sign-Off:** Product & Technical Owner approved `ADR-0001..0003` and `ADR-0005..0007`, `DPIA-001..008` retention rules, and initial `.go.id` destination allowlist (`#3`, `#6`, `#9`).
- [x] **HOST-01..17 Target Environment Baseline:** Per `DEC-018` ([ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md)), local development and CI are approved against **PostgreSQL 18.4 + PHP >=8.3** (Topology A/C), while production host verification (`HOST-01..17` in [hosting-audit.md](hosting-audit.md)) is tracked at `#43` and **Gate 15 (`#25`)** prior to production cutover.

**Gate 9 Signatures:** Product & Technical Owner: project owner (Approved GO) / Date: `2026-11-01` / Evidence links: [traceability.md](traceability.md), [verify-contract.mjs](../design/mock-server/verify-contract.mjs), PR `#47`. **Decision: GO for Phase II Implementation (`#10`–`#43`).**

---

## Gate 15 — REQUIRED HUMAN GO/NO-GO ([#25](https://github.com/ahliweb/awshortlink-laravel/issues/25) — **APPROVED GO 2026-11-01**)
- [x] Gate 9 evidence and re-review of changed specs current (`PR #47`, `PR #48`); PostgreSQL 18.4 verified (`HOST-01..17` operational checklist & probes in [hosting-audit.md](hosting-audit.md)).
- [x] All P0/P1 acceptance tests (`TST-001..019`, `235` assertions across `tests/01..06_*_smoke.php`) pass against PostgreSQL 18.4 with active `ENABLE` + `FORCE ROW LEVEL SECURITY` (`105` policies across `28` tables), least-privilege DB roles (`awshortlink_app`, `awshortlink_resolver`, `awshortlink_migrator`, `awshortlink_backup`), and PHP `pdo_pgsql` + `gd` + `intl`.
- [x] Automated syntax lint, OpenAPI 3.1 (`58` operations) + AsyncAPI 3.0 (`6` events) contract tests, immutable release artifact (`build/awshortlink-release.tar.gz`), CycloneDX 1.5 SBOM (`build/sbom.cdx.json`), and `build/SHA256SUMS` pass (`bash scripts/ci.sh`).
- [x] Security & negative test suite verified: open redirect/scheme/credentials/IP-literal/NIK/shortener-chain block (`TV-006..014`), OWASP SSRF private/loopback/link-local/CGNAT/metadata IP block (`TST-013`), cross-unit IDOR & no-context RLS default-deny (`TST-017`, `TST-018`), optimistic locking `If-Match` `409`/`428` (`TV-023`), scoped API token rate limit `429` & revocation `401` (`TST-011`).
- [x] Accessibility WCAG 2.2 AA markup verified on public & admin templates (`lang="id"`, `#main-content` skip link, landmarks, explicit `<label for>`, `aria-live="polite"`).
- [x] Coexistence routing verified strictly under `/buka/*` and `/buka/livewire/*` without intercepting parent website paths (`#22`).
- [x] PostgreSQL backup (`awshortlink_backup` `pg_dump`) and restore (`pg_restore` into clean DB + RLS policy/row-count verification: `permissions=62`, `rls_policies=105`, `unprotected_tables=0`) rehearsed automatically via `scripts/rehearse-backup-restore.sh` (`#43`).
- [x] Emergency suspend (`POL-EMERGENCY`), SHA-256 hash-chained audit verification & tamper detection (`AuditChainVerifier`), and public abuse reporting/triage (`/buka/laporan`) tested (`#18`, `#27`, `#34`).
- [x] **Human Gate 15 Sign-Off & Post-Deploy Synthetic Verification (`#25`, `#26`):** Product & Technical Owner (project owner) approved Gate 15 GO on `2026-11-01`; `scripts/post-deploy-verify.sh` verified five sample slugs, QR generation, scheduler heartbeat, and audit chain integrity.

**Gate 15 Signatures:** Product & Technical Owner: project owner (Approved GO) / Date: `2026-11-01` / Release version: `v1.0.0` / Evidence: `scripts/ci.sh`, `scripts/post-deploy-verify.sh`, PR `#49`. **Decision: GO (`#25`, `#26`).**

## Issue conventions
Prefixes: `[SPEC]`, `[HOST]`, `[P0]`, `[P1]`, `[P2]`, `[SEC]`, `[OPS]`, `[QA]`. Each issue must say workflow step, dependency, scope, acceptance tests, docs touched, done artifacts. Parent epics reference subordinate issues; do not mark a feature done without evidence. Planning issues may exist in GitHub even though official Step 10 begins **after** Gate 9—clearly tag them *provisional / blocked*.
