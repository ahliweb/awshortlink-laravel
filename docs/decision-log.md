# Architecture & Product Decision Log — 2026-10-31

This document records **proposed decisions**, **not approvals**. Changes to binding architecture should be promoted into repo ADRs and signed off at Gate 9.

| ID | Decision / status | Rationale / unresolved evidence |
| --- | --- | --- |
| DEC-001 | Laravel 13 + Filament 5, proposed | PHP shared hosting without developer SSH; PHP >=8.3 must be proven |
| DEC-002 | Namespace /buka/{slug}, proposed | Existing official .go.id website; parent path delegation not verified |
| DEC-003 | Modular monolith, proposed | No persistent daemon required; simpler operational complexity |
| DEC-004 | SUPERSEDED by ADR-0005 and DEC-013 | Historical host-dependent DB choice withdrawn; do not implement MySQL/MariaDB/SQLite |
| DEC-005 | URL policy allowlist/review + irreversible published slug reservation, proposed | Prevent trusted-domain phishing and printed-QR hijack |
| DEC-006 | No-SSH release artifact and safe migration operator, proposed | Composer/Vite executed off server; backups mandatory |
| DEC-007 | Admin Filament at /buka/admin, proposed | Needs Livewire prefix and parent webserver routing proof |
| DEC-008 | No raw visitor profiling / no health PII, proposed | Default analytics counts only; DPIA approval pending |
| DEC-009 | 302 default for editable links; no permanent cache, proposed | Destination can change and must revoke promptly |
| DEC-010 | Parent MIT LICENSE retained, confirmed from repo | Third-party library licenses and institutional deployment approvals separate |
| DEC-011 | Human Gate 9 and 15 approvals mandatory | Per owner's internal cross-portfolio standard workflow v2.1.1 |
| DEC-012 | Cron optional for P1; critical policies checked at request | Zero-SSH setup cannot presume scheduler availability |

## Known open actions
Obtain hosting inventory and authorization, actual User Research, UI prototype validation, owner/DPO privacy policy, approved domain target allowlist, environment-independent test approach, and change-control plan for live public website.

## External references
Laravel 13 support: https://laravel.com/docs/13.x/releases
Filament 5 install: https://filamentphp.com/docs/5.x/introduction/installation
Laravel deploy: https://laravel.com/docs/13.x/deployment


## Updated product instructions (31 October 2026)
| ID | Decision | Status |
| --- | --- | --- |
| DEC-013 | PostgreSQL is mandatory for local, tests, staging and production, no other database driver | User direction accepted; Gate 9 and host capability pending |
| DEC-014 | PostgreSQL RLS mandatory, least privilege app DB roles, trusted transaction-local context and distinct public resolver | Design in ADR-0005; security/DDL verification pending |
| DEC-015 | System actively **manages** RBAC and ABAC user/admin levels in Filament: roles, permission matrix, assignments, organizational scopes, policy versions/simulation, access inspector | P0 requirement in ADR-0006, not yet coded |
| DEC-016 | No-SSH deployment still requires operator-managed PostgreSQL DDL/migrations and backups; no downgrade | Host audit still NO-GO |
| DEC-017 | Technical design choices `DES-001..015` locked to default proposals in ADR-0007 (UUIDv7 + BIGINT audit PKs, closure table `unit_closure`, HTTP 404 on suspended link, editor own-link analytics, $k=10$ cohort suppression, mandatory TOTP MFA, no raw click events, `https://` only, P0 role-publish + `POL-LINK-SOD`, `awshortlink_backup` with row-count check, direct UPSERT counter, 30m/8h sessions, ASCII 3..64 slugs, the organisation IT allowlist ownership, internal P0 API contract) | Locked in ADR-0007 for Gate 9 review (2026-11-01) |
| DEC-018 | Local development and CI target PostgreSQL 17/18 + PHP >=8.3 under Topology A/C while production `HOST-01..17` remains a hard prerequisite for staging/production release (Gate 15) | Locked in ADR-0007 (2026-11-01) |
| DEC-019 | **Gate 9 (`#9`) Human Approval (GO)** signed by repository owner (project owner) on 2026-11-01 | Unlocks Phase II implementation issues (`#10`–`#43`); production deployment remains gated at Gate 15 (`#25`) |
| DEC-020 | Phase II vertical slices (`#10`–`#24`, `#27`–`#43`) implemented and verified (`v1.0.0-rc.1`) against PostgreSQL 18.4 with compulsory RLS (`105` policies across `28` tables), `235` passing assertions (`TST-001..019`), CycloneDX 1.5 SBOM, and `awshortlink_backup` `pg_dump`/`pg_restore` rehearsal | Merged via PR `#49` (2026-11-01) |
| DEC-021 | **Gate 15 (`#25`) Human Approval (GO) & Release `v1.0.0` (`#26`)** signed by repository owner (project owner) on 2026-11-01 | Closes `#25` and `#26` with automated post-deploy synthetic verification (`scripts/post-deploy-verify.sh`) |
| DEC-022 | **Semantic Versioning 2.0.0 Minor Release `v1.1.0` (2026-11-03)** | Implements backward-compatible feature additions: public search & abuse report workflow (`/buka/laporan`), admin abuse triage management (`/buka/admin/reports`), public vs unlisted link visibility toggle, detailed visitor telemetry analytics (`/buka/admin/links/{id}/analytics`), SVG traffic trend charts, universal table search/paging, and complete @@ORG_SHORT@@ organization units. Adheres to owner's internal cross-portfolio standard (`DL-035`). |
