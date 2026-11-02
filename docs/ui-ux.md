# UX/UI Specification and Validation Plan — v1 draft

**Important:** This is a structured wireframe/interaction specification, **not a user-validated prototype**. Visual design system and screen↔API mapping: [ui-ux-design-system.md](../design/ui-ux-design-system.md); clickable (unvalidated) prototype: ../design/prototype/. Gate 9 requires actual clickable prototype and usability study evidence. Style adopts accessible Filament 5 design conventions; the organisation branding subject to approval.

## Information architecture
Filament sidebar: Overview; Short Links; Create Link; QR Codes; Campaigns (P1); Analytics; Review Queue (P1); Organizations/Units; Audit; Settings; Help. Public page /buka/ contains only institutional explanation/search directory **if approved**, never unrestricted short-link creation. Unknown slug is a safe 404.

## Key screens / control-state requirements
| UI ID | Screen | Essential components | States and accessibility |
| --- | --- | --- | --- |
| UI-001 | Overview | Published/queued links, valid clicks, current alert; date/unit filters | Empty, loading, error, no permission; screen-reader labels |
| UI-002 | Link list | Search slug/title, unit filter, status, sortable columns, pagination, CSV P1 | Selection, empty, pagination, denied cross-unit |
| UI-003 | Create/edit link | Safe URL, slug preview, ownership, expiry, destination policy verdict | Input error, conflict, forbidden host, unsaved, submitting, success |
| UI-004 | Detail/history | Current target, versions, QR preview, lifecycle, audit entries | Retired, pending, cannot self-approve |
| UI-005 | QR export | SVG/PNG resolution, quiet zone, logo controls and copy URL | Loading, unsupported format, print preview |
| UI-006 | Analytics | Valid clicks vs total requests, bot estimates, date trend, channel | No data, masked low-count cohorts, export denied |
| UI-007 | Review queue | Before/after target, risk rationale, approve/reject/suspend | Reviewer cannot approve own high-risk change |
| UI-008 | Admin access | Sign-in, MFA, session recovery, role-appropriate nav | Invalid credentials, locked account, expired session |
| UI-009 | Public error | Branded safe 404/410/suspended, report misuse contact | No private destination leakage; accessible copy |
| UI-010 | Hosting status | Build version, scheduler, PostgreSQL/RLS health and synthetic check | Admin only, no secrets |
| UI-011 | User Management | Invite/edit/disable, role, unit, MFA, revoke session | Protected actions and denial states |
| UI-012 | Role Management | Protected system roles, custom roles, version and ownership | No self-escalation, no last-owner deletion |
| UI-013 | Permission Matrix | Resource.action catalogue, role diff, checked grants | Privilege warnings, restricted keys |
| UI-014 | ABAC Rule Builder | Whitelisted condition operators, simulation, version, review | No executable scripts; review/rollback |
| UI-015 | Role Assignment | Scoped grants per unit/descendant/owned/global, validity dates | Revocation and approval, audit |
| UI-016 | Effective Access Inspector | Explain allow/deny with policy version and reason | Scoped diagnostics only; redact private data |
| UI-017 | Unit Hierarchy | Memberships and delegated unit administration | Prevent cross-unit modification |
| UI-018 | User Workspace | Own profile, MFA/sessions and permitted links | No privileged role self-edit |

## Text wireframe: Link editor
~~~
[Link title __________________________________]
[Owner unit ▼] [Campaign ▼] [Active dates ...]
[Public slug] /buka/[_________________] [Check]
[Destination URL ___________________________] [Validate]
[Target domain policy: APPROVED / REVIEW NEEDED]
[Expiry optional] [Access scope public / restricted]
[QR preview] [Copy short URL] [Download SVG]
[Save Draft] [Submit for Review] [Cancel]
~~~

## Navigation and content safety
- Explicitly render full canonical destination hostname on edit/approval screen. No misleading short preview.
- Invalid/expired URLs have distinct accessible messages, no automatic redirect to untrusted fallback.
- Confirm destructive actions with accessible modal and typed intent for emergency policy changes.
- Support keyboard navigation and visible focus, logical heading hierarchy, form error summary, color contrast, 44px-equivalent usable targets where feasible, zoom and mobile width ~360px.

## Prototype and validation protocol (Gate 4)
Build interactive prototype (Figma, static HTML, or equivalent) with all UI IDs and error states. Recruit sample: 1 central admin, 2 editors, 1 approver, 1 unit admin, 1 analyst and 1 hosting/security officer; validate in Indonesian. Tasks: create a safe link, deal with slug conflict, request approval for external domain, export QR, suspend unsafe link, read analytics without misinterpreting unique persons. Measure completion, error rate, observed problems and severity; implement fixes and re-test critical flows. Capture signed UI review evidence with test dates and version. Provide API/mock mapping for every screen before Gate 9.

## A11y verification
WCAG 2.2 AA: automated axe and manual keyboard/screen reader; default language id-ID, correct date/time labels (WIB), responsive tables and link copy controls. Set accessible contrast and save-state notifications. See https://www.w3.org/TR/WCAG22/.


## New UX validation tasks (UI-011..018)
Prototype real user/admin management, role edits, permissions preview, unit delegation, safe ABAC builder, policy simulation, audit and effective-access inspector before Gate 9. Add tasks: unit admin tries assigning global admin role and is denied; revocation instantly removes access; central admin reviews a privilege expansion requiring independent approval; reporter sees only permitted aggregate data; system refuses removal of last protected owner. Distinguish authenticated User workspace from public QR visitor; design with source-backed API contracts.
