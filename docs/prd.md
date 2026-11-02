# Product Requirements Document — AW Shortlink v1.0.0-draft

**Sponsor:** @@ORG_SHORT@@ (proposed initial deployment, verify formal project ownership). **Audience:** citizen, program/editor, approver, analyst, auditor, operator. **Product:** self-hosted short links / dynamic QR / privacy-preserving reporting.

## Problem statements / jobs-to-be-done
- Citizens need short, readable institutional links to access current public health information on posters and letters.
- Editors need to change target without replacing printed QR and preserve authorship/change accountability.
- Approvers need to prevent a trusted .go.id prefix from becoming a phishing/open redirect source.
- Analysts need honest campaign engagement trends (not false unique-person counts).
- Operators need no-SSH install and reversible deploy with existing site unharmed.

## Requirements / priority / testable acceptance
| ID | Prio | Requirement | Acceptance |
| --- | --- | --- | --- |
| REQ-001 | P0 | Public route /buka/{slug} resolves only approved active URL | Valid GET returns configured 302 and exact Location; no destination network fetch |
| REQ-002 | P0 | Human-friendly custom slug and random slug | Unicode/encoding policy, collision/unique and reserved namespace tested |
| REQ-003 | P0 | Destination editable with version history | Existing short URL remains stable; authorized changes audited and cache-safe |
| REQ-004 | P0 | URL safety policy | Reject malformed/unsafe schemes, embedded credentials, forbidden hosts; reviewed external domains |
| REQ-005 | P0 | Laravel + Filament admin | Authenticated admin can create/search/filter/edit/archive links with accessible states |
| REQ-006 | P0 | Managed RBAC + ABAC and unit isolation | Admin manages roles/permissions, user grants, unit scopes and ABAC policy versions; enforce deny at API/UI and PostgreSQL RLS |
| REQ-007 | P0 | Expiry, suspension and revoked state | Deterministic HTTP result, immediate authoritative enforcement |
| REQ-008 | P0 | Dynamic QR (SVG/PNG) | Scanning produces same stable short URL, template cannot replace encoded content |
| REQ-009 | P0 | Aggregated analytics | Total valid clicks and daily trends; bot classification disclosed; no patient data |
| REQ-010 | P0 | Audit and traceability | Create/approve/change/suspend/delete recorded actor, reason, before/after hash/version |
| REQ-011 | P0 | No-SSH deployment | Validated build artifact, migration strategy, rollback, staging and parent-site regression |
| REQ-012 | P0 | Accessible error states | 404 unknown, 410 retired, safe error content, WCAG 2.2 AA |
| REQ-013 | P1 | Approval workflow | draft -> submitted -> approved or rejected, separation of duties for risk domains |
| REQ-014 | P1 | Campaign and UTM grouping | Segment by program, unit and channel; preserve validated query policy |
| REQ-015 | P1 | CSV import/export | Dry-run, preview, per-row failures, formula-injection-safe export, idempotent apply |
| REQ-016 | P1 | API integration | OpenAPI contract, scoped credentials, rate limit and audit |
| REQ-017 | P1 | Destination monitoring | Scheduled checks only if safe egress and cron capabilities confirmed |
| REQ-018 | P1 | Reports/retention | Privacy-preserving breakdown, retention deletion, export by role |
| REQ-019 | P2 | Link-in-bio/directories | Approved institutional multi-link pages |
| REQ-020 | P2 | Multi-domain/advanced rule | Explicit policy and routing review for each domain; not required initially |
| REQ-021 | P0 | PostgreSQL-only database | DB_CONNECTION=pgsql, no MySQL/MariaDB/SQLite in any environment; RLS-enabled integration and deployment evidence |
| REQ-022 | P0 | Admin/user account and role management | Filament invites/disables users, manages unit memberships, scoped role grants and session revocation with audit |
| REQ-023 | P0 | Permission matrix and ABAC policy administration | Protected roles/permissions, safe rule builder, version/simulate/approve/revert, no unauthorized privilege escalation |
| REQ-024 | P0 | Mandatory PostgreSQL RLS | Private and IAM tables use deny-default RLS, USING/WITH CHECK, nonowner/no-BYPASSRLS runtime and transaction-scoped context |
| REQ-025 | P0 | Effective access inspector | Authorized admin/auditor can safely explain allow/deny and policy version without exposing private records |

## Business rules
- Public link creation forbidden; only verified staff may author. Published slug permanently reserved.
- Explicit link owner, unit and approval category required; unapproved links cannot redirect externally.
- Destination must pass URL canonicalization and domain policy on every publish/change. Institutionally-owned domains may be allowlisted; external domains subject to review.
- Store sanitized link title/description. No personal/health identifiers in slug, query or target; reject token-bearing destinations.
- Dynamic links use 302 by default with no-store caching policy as appropriate. Never use 301/308 while destination can change.
- Treat clicks as visits/events, not identity, service completion or medical outcomes.

## Five canonical flows
1. EVENT62: staff submits /buka/event62 -> approver reviews destination -> publishes -> QR print -> eventual destination replacement with new approved version.
2. SKM: /buka/skm -> safe public survey; Analytics reports daily referrals without full respondent identity.
3. Public directory: /buka/directory -> official directory; unit owner manages associated link content subject to scopes.
4. Training materials: /buka/materi-pelatihan -> approved public materials; edit destination keeps poster QR stable.
5. Campaign: /buka/campaign with tagged channel variants; aggregate per-channel comparisons without visitor profiling.

## Instrumentation and KPIs
Service uptime, redirect p50/p95/p99, 4xx/5xx, invalid-destination attempts, time to suspension, number of published links, daily valid clicks, suspicious-bot counts, and accuracy of audit, plus accessibility pass/fail. Clearly separate proposed targets from actual measurements.

## User research needed before Gate 9
Interview >=1 admin central, >=2 program editors, >=1 branch unit, >=1 communications user and >=1 IT/hosting operator; test slug creation, bulk retrieval, link approval, printing QR, invalid-link messaging and dashboard comprehension. Record UXT evidence, unresolved tasks and explicit approval. Do not pretend validation is complete.


## Admin and authenticated user account requirements
Public visitors remain anonymous readers. Staff users may hold active unit-scoped, time-bounded roles; admin manages only grants within their delegation ceiling. Sensitive grants and ABAC policy versions require independent approval and auditable rollback. Effective access requires RBAC + ABAC + Laravel Policies + PostgreSQL RLS. See identity-rbac-abac.md. These are requirements, not currently implemented.
