# UI/UX Design System & Screen Specification — AW Shortlink

**Version:** v1.0.0-draft | **Date:** 2026-10-31 | **Workflow step:** 4 (UX prototype) — feeds SPEC-04 [#4](https://github.com/ahliweb/awshortlink-laravel/issues/4)
**Status:** professional draft + clickable prototype. **Not user-validated** and **not production code**. Gate 9 ([#9](https://github.com/ahliweb/awshortlink-laravel/issues/9)) remains NO-GO.
**Canonical language:** English for this specification; **UI copy is Bahasa Indonesia (id-ID)**, time zone **WIB (Asia/Pontianak)**.

Companion artefacts:
- [ui-ux.md](../docs/ui-ux.md) — screen inventory UI-001..018 and validation protocol (source of truth for scope).
- [system-design.md](system-design.md) — architecture, data, RLS, ABAC DSL and API mapping the screens depend on.

> Rule from [docs/README.md](../docs/README.md): "Track UI acceptance by **actual** the organisation stakeholders; do not substitute AI-generated illustrations for validation." This document and the prototype are **inputs** to usability testing (UXT-001..014), not evidence that it happened.

---

## 1. Design principles
| # | Principle | What it means on screen | Source |
| --- | --- | --- | --- |
| P1 | **Trust is visible** | The full canonical destination **host** is always shown in large type (never a truncated "preview" title) on create, review, detail and public directory. External hosts carry a risk badge. | ui-ux.md "Navigation and content safety", THR-001 |
| P2 | **Fail closed, explain kindly** | Denied/unknown resources render an explicit state with the missing permission and a request ID; out-of-scope records look identical to "not found" (no existence leak). Menu hiding is cosmetic only. | AGENTS.md, access-control.md |
| P3 | **Honest numbers** | Analytics say *klik valid (perkiraan)* and *dugaan bot*; never "unique visitors/people". Cohorts < 10 are shown as "< 10". | ADR-0003 |
| P4 | **Every mutation is accountable** | Destructive or privileged actions require a reason (≥ 8 chars) and, for emergencies, typed confirmation; results are echoed as audit entries. | REQ-010, THR-010 |
| P5 | **Stable public promise** | The slug field locks after publication; editing a destination creates a new version while the old one keeps serving. QR always encodes the short URL. | ADR-0002, REQ-003/008 |
| P6 | **Filament-native** | Layout, components and density follow Filament 5 conventions so implementation is configuration, not a custom front-end. | DEC-001 |
| P7 | **Accessible by default** | WCAG 2.2 AA; 360 px width; keyboard-complete; Indonesian plain language. | REQ-012, TST-009 |

---

## 2. Design tokens
Tokens are specified in this document (the origin prototype is not included in this upstream) and map 1:1 onto a Filament theme after Gate 9 (see §6). Brand colours are **proposed** and subject to your branding approval.

### 2.1 Colour (contrast measured against the listed background, WCAG 2.x formula)
| Token | Hex | Use | Contrast |
| --- | --- | --- | --- |
| `--brand-600` (primary) | `#0f766e` | Primary buttons, active nav text, links | 5.47:1 on white (AA text) |
| `--brand-700` | `#115e59` | Hover, active nav on `--brand-50` | 7.58:1 on white; 7.11:1 on `#effaf8` |
| `--brand-500` | `#14907f` | Chart fills, non-text graphics only | 3.94:1 (≥ 3:1 non-text, SC 1.4.11) |
| `--gray-900` / `--gray-800` | `#111827` / `#1f2937` | Headings / body text | 13.7:1 on `--gray-50` |
| `--gray-600` | `#4b5563` | Secondary text | 7.56:1 on white |
| `--gray-500` | `#5f6b7a` | Hints, meta text (minimum allowed text grey) | 5.43:1 white · 5.06:1 `--gray-50` · 4.75:1 `--gray-100` |
| `--success-700` on `--success-50` | `#166534` / `#ecfdf3` | "Aktif", low risk, allow | 6.76:1 |
| `--warning-800` on `--warning-50` | `#92400e` / `#fffbeb` | "Menunggu", medium risk, prototype banner | 6.84:1 |
| `--danger-700` on `--danger-50` | `#991b1b` / `#fef2f2` | "Ditangguhkan/Ditolak", high risk, deny | 7.60:1 |
| `--danger-600` | `#b91c1c` | Destructive button background (white text) | 6.47:1 |
| `--info-700` on `--info-50` | `#1e40af` / `#eff6ff` | Informational alerts, "Terjadwal" | 8.01:1 |
| `--violet-700` on `--violet-50` | `#6d28d9` / `#f5f3ff` | "Diarsipkan", P1 tag | 6.48:1 |
| Focus ring | 2 px white + 2 px `#1d4ed8` | All interactive elements (`:focus-visible`) | 6.7:1 vs white |

Status is **never conveyed by colour alone**: every badge has a text label and a dot; risk badges read "Rendah / Sedang / Tinggi / Diblokir".

### 2.2 Typography
System font stack (`Inter`, `Segoe UI`, `system-ui`, …) — **no web-font download**, consistent with the no-internet host constraint; Filament can later bundle Inter locally in the build artifact. Monospace for slugs, codes, hashes.

| Token | Size | Use |
| --- | --- | --- |
| `--text-3xl` | 36 px | KPI numbers (tabular figures) |
| `--text-2xl` | 28 px | Page title `h1` |
| `--text-lg` | 18 px | Card titles `h2` |
| `--text-md` | 16 px | Destination host, public body copy |
| `--text-sm` | 14 px | Admin body (Filament default density) |
| `--text-xs` | 12 px | Hints, meta, table headers |

### 2.3 Spacing, shape, elevation, layout
- 4 px grid (`--sp-1` … `--sp-12`); cards use 20 px padding; page gutter 24 px (16 px ≤ 720 px).
- Radius: 6 / 10 / 14 px; pills 999 px. Elevation: 3 shadow levels (card, popover, dialog).
- Shell: 268 px sidebar + 64 px sticky top bar; content max-width 1320 px.
- Breakpoints: **≤ 1180 px** two-column grids collapse; **≤ 1024 px** sidebar becomes an off-canvas drawer with scrim; **≤ 720 px** tables become stacked label/value cards (`.stack-sm-table`), forms single column. Verified at **360 px**.
- Minimum interactive height 40 px (buttons/inputs), 32 px for compact table actions — above the 24 px minimum of SC 2.5.8.

---

## 3. Component inventory
| Component | Variants / states | Accessibility contract |
| --- | --- | --- |
| Button | primary, secondary, danger, warning, ghost, sm/lg, icon, disabled (`title` explains why) | Native `<button>`/`<a>`; disabled actions keep a tooltip with the missing permission |
| Badge | status (8), risk (4), role, P1 tag | Text + dot; not colour-only |
| Card / Stat tile | header, body, footer; KPI with meta caption | Headings in order; KPI meta explains semantics |
| Table | sortable headers, toolbar filters, pagination, row link, stacked mobile mode | `aria-sort`, `<th>` scope, `aria-busy` while loading, `data-label` for stacked mode |
| Form field | text, url, select, date, textarea, input-group prefix/suffix, radio cards, checkbox | Visible `<label>`, hint via `aria-describedby`, `aria-invalid`, inline error + **error summary** with links (SC 3.3.1/3.3.3) |
| Destination block | single, before → after diff | Host in 16 px bold, path monospace, wraps (no truncation of host) |
| Alert | info, success, warning, danger, neutral | `role="alert"` only for blocking errors; `role="status"` otherwise |
| Modal (native `<dialog>`) | confirm, reason-required, typed-confirm | Focus trapped by `showModal()`, returns focus to trigger, Esc closes |
| Toast | success, warning, danger | `aria-live="polite"` region; never the only place an error is reported |
| Tabs | link detail | `role="tablist"` with URL-addressable tabs (deep-linkable) |
| Stepper | link lifecycle, ABAC policy lifecycle | `aria-current="step"` |
| Timeline | destination versions, audit | Ordered, timestamps in WIB |
| Permission matrix | read-only ✓/lingkup/—; proposal mode with change highlight | Sticky first column; each checkbox labelled "permission for role" |
| Rule builder | ALLOW-ALL group, DENY-ANY override group, attribute/operator/value rows, JSON preview | Only allow-listed attributes/operators; no free code; labelled selects |
| Decision trace | 6 layers pass/fail/skipped + verdict banner | Text verdict "DIIZINKAN/DITOLAK" + reason code |
| Empty / loading / error / denied / not-found states | see §5 | Each has heading, explanation, next action |
| QR preview | public / draft-watermarked | `role="img"` with label; URL caption under QR |
| Chart | stacked daily bars, channel bars | `role="img"` + `aria-label`, **plus a data table** in `<details>` (SC 1.1.1) |

---

## 4. Screen specification (UI-001 … UI-018) with contract mapping
Every screen must have a planned API source and permission before Gate 9 (traceability.md rule). Operation IDs refer to [`docs/api/openapi.yaml`](../docs/api/openapi.yaml); entries marked **GAP** are listed in [system-design.md §10.3](system-design.md) for SPEC-08 [#8](https://github.com/ahliweb/awshortlink-laravel/issues/8).

| UI | Screen (prototype route) | Key decisions | API operation(s) | Permission(s) | Issues |
| --- | --- | --- | --- | --- | --- |
| UI-001 | Dasbor (`#/dashboard`) | 4 KPIs with semantic captions; suspended-link alert; "Perlu tindakan" queue; top links show host | `listLinks`, `getLinkAnalytics`; aggregate summary **GAP** | links.list_internal, analytics.view | #15 #17 |
| UI-002 | Tautan Pendek (`#/links`) | Search/status/unit/risk filters; sortable; host column; state simulator (normal/loading/empty/error) | `listLinks` | links.list_internal | #15 |
| UI-003 | Buat/Ubah (`#/links/new`, `#/links/{id}/edit`) | Sectioned form; slug check with suggestion; destination verdict card; error summary; sticky actions; If-Match conflict dialog | `createLink`, `updateLinkDraft`, `submitLink`; slug availability **GAP**; destination preview-validate **GAP** | links.create_draft, links.update_draft, links.submit | #13 #15 |
| UI-004 | Detail (`#/links/{id}`) | Tabs Ringkasan / Versi / QR / Audit; HTTP outcome shown per status; lifecycle stepper; suspend/archive with reason | `getLink`, `suspendLink`; versions list **GAP**; archive **GAP**; per-link audit **GAP** | links.*, audit.view | #15 #18 |
| UI-005 | Kode QR (`#/qr/{id}`) | SVG/PNG, size, ECC (auto H with logo), quiet zone ≥ 4, caption; draft watermark | `downloadLinkQr` | qr.generate_public | #16 |
| UI-006 | Analitik (`#/analytics`) | Valid vs bot vs total; data completeness; "Cara membaca angka ini"; channel bars with < 10 suppression; export dialog explains CSV escaping | `getLinkAnalytics`; aggregate across links **GAP**; export **GAP** | analytics.view, analytics.export | #17 #28 #33 |
| UI-007 | Antrean Tinjauan (`#/review`) — P1 | Master/detail; before → after host diff; risk rationale; checklist gates "Setujui"; self-approval banner | `approveLink`; reject/request-changes **GAP**; queue list **GAP** | links.approve | #27 |
| UI-008 | Masuk + MFA (`#/login`, `/mfa`, `/locked`) | No self-registration; generic credential error; 6-digit OTP with paste/one-time-code; lockout page | Laravel/Filament auth (not REST) | — | #11 |
| UI-009 | Publik & galat (`#/p/landing`, `/404`, `/410`, `/503`, `/report`, `/privacy`) | Trust message "pastikan alamat diawali …/buka/"; directory shows destination host; 404/410/503 with no auto-redirect; misuse report (P1) | Resolver (non-REST); public directory **GAP**; report **GAP** (#34) | public | #14 #20 #34 |
| UI-010 | Status Hosting (`#/system`) | Checks show "Belum diverifikasi" honestly; build SHA/artifact checksum; no secrets | health endpoint **GAP** | system.health | #1 #38 #43 |
| UI-011 | Pengguna (`#/users/{id}`) | List + side panel; MFA column; revoke sessions; suspend with typed name; **last owner** protection | `listManagedUsers`, `inviteUser`; disable/revoke-sessions **GAP** | users.read, users.invite, users.disable | #39 |
| UI-012 | Peran (`#/roles`) | Protected vs custom draft roles; members/version; invariant note | `listManagedRoles`, `createManagedRole` | roles.read, roles.create | #40 |
| UI-013 | Matriks Izin (`#/permissions`) | Read-only matrix; proposal mode only for custom draft role; sensitive-permission warning; diff summary → independent approval | `listPermissionCatalog`, `replaceRolePermissions` | permissions.read, roles.permissions.update | #40 |
| UI-014 | Kebijakan ABAC (`#/policies/{id}`) | Lifecycle stepper; active versions immutable; ALLOW-ALL + DENY-ANY groups; JSON preview; test vectors must pass before "Ajukan" | `listAbacPolicies`, `createAbacPolicyDraft`, `simulateAbacPolicy`, `publishAbacPolicyVersion`; rollback **GAP** | policies.* | #41 |
| UI-015 | Penugasan Peran (`#/assignments`) | Shows grantor's delegation ceiling; over-ceiling roles listed but denied with policy reference; scope radio cards; validity dates; global = pending dual control | `assignUserRole`; revoke **GAP**; change-request list **GAP** | user_roles.assign, user_roles.revoke | #40 |
| UI-016 | Inspektur Akses (`#/inspector`) | 6-layer decision trace; reason code; policy version; quick scenarios from identity-rbac-abac.md | `inspectEffectivePermissions` | access.inspect | #42 |
| UI-017 | Unit & Hierarki (`#/units/{id}`) | Tree; out-of-scope units visible but locked; members per unit | units CRUD **GAP** | units.read, units.manage | #39 |
| UI-018 | Ruang Kerja Saya (`#/me`) | Own profile, MFA, sessions, effective permissions (scoped marked *), own links; link to inspector | current-user profile **GAP** | authenticated | #39 |

---

## 5. Interaction patterns
### 5.1 Mandatory state set (every data screen)
| State | Pattern | Copy example (id-ID) |
| --- | --- | --- |
| Loading | Skeleton rows, `aria-busy="true"` | — |
| Empty | Icon, heading, why, primary action | "Belum ada tautan di lingkup Anda" |
| No results | Same as empty + "Reset filter" | "Tidak ada hasil" |
| Error (5xx) | Safe message, request ID, retry | "Gagal memuat daftar tautan … ID permintaan: req_…" |
| Denied (403) | Missing permission, role and scope, request ID; links to "Ruang kerja saya" | "Anda tidak memiliki izin untuk halaman ini" |
| Not found / out of scope (404) | Identical for both | "Tautan tidak ditemukan atau di luar lingkup Anda" |
| Conflict (409) | Dialog naming who changed what version; reload action | "Tautan telah diubah orang lain" |
| Validation (422) | Inline error + error summary that focuses first field | "Periksa 2 isian berikut" |

### 5.2 Destructive & privileged actions
- **Suspend link:** danger dialog, shows current destination host, reason required, type `TANGGUHKAN`. Effective on next request (no cache).
- **Archive:** explains 410 and permanent slug reservation; reason required.
- **Suspend user:** type the user's first name in capitals; sessions/tokens revoked; grants frozen, not deleted. Blocked for the last active `platform_owner`.
- **High-risk approval / sensitive grants / policy publish:** step-up MFA (shown as note in prototype), independent approver.

### 5.3 Destination feedback (UI-003)
Client-side preview (`url-policy.js`) mirrors system-design §11.1 so participants see immediate feedback; **the server is authoritative**. Verdicts: *Disetujui kebijakan* (institutional allowlist, low), *Perlu tinjauan* (other go.id = medium; external = high), *Ditolak* (each problem listed with a machine code: `scheme`, `userinfo`, `ip_literal`, `port`, `shortener`, `sensitive_param`, `nik_like`, …).

### 5.4 Navigation & keyboard
Skip link; `/` focuses global search; Esc closes drawer/dialog; focus moves to the page `h1` on route change and the new title is announced via a polite live region; tabs and filters are URL-addressable so browser Back works.

---

## 6. Filament 5 implementation mapping (after Gate 9 only)
| Prototype element | Filament 5 construct (to be verified against current docs at implementation time) |
| --- | --- |
| Brand/semantic tokens | Panel `->colors([...])` with `Color::hex('#0f766e')` etc.; custom theme CSS compiled at build time (no runtime CDN) |
| Sidebar groups | `NavigationGroup` per group; items visible via `canAccess()` **and** policies (visibility is cosmetic) |
| Tables UI-002/011/015 | `Table` with `TextColumn`, `BadgeColumn`/`->badge()`, `SelectFilter`, `->searchable()`, stacked-on-mobile layout |
| Forms UI-003 | `Section` components with `->description()`; `TextInput::make('slug')->prefix('…/buka/')`, live validation via `->live(onBlur: true)` calling the server-side policy service |
| Detail UI-004 | Resource `ViewRecord` + infolist + relation managers (versions, audit) |
| Dialogs | Actions with `->requiresConfirmation()`, `->form([...reason...])`, custom typed-confirm field |
| Stats UI-001/006 | `StatsOverviewWidget` + chart widget (data table fallback must be added for a11y) |
| Matrix UI-013, Rule builder UI-014, Inspector UI-016 | Custom Filament pages (Livewire) — no arbitrary code fields |
| Public pages UI-009 | Plain Blade views outside the panel (no Livewire), strict CSP |

---

## 7. Content & microcopy guide (Bahasa Indonesia)
| Concept | Use | Avoid |
| --- | --- | --- |
| Short link | **tautan pendek** | shortlink, URL pendek (OK only in technical captions) |
| Destination | **destinasi / URL tujuan** | target link |
| Valid clicks | **klik valid (perkiraan)** | pengunjung, pengguna unik, orang |
| Suspected bots | **dugaan bot** | bot (as certainty) |
| Suspend / Archive | **tangguhkan / arsipkan** | hapus (links are never deleted) |
| Approval | **tinjau / setujui / tolak** | acc |
| Scope | **lingkup** (unit, unit + turunan, milik sendiri, global) | akses semua |
| Grant | **hibah peran / penugasan peran** | kasih role |
Tone: formal, short sentences, active voice, explain consequences before the action ("Pengunjung akan segera berhenti dialihkan…"). Dates `31 Okt 2026, 10.00 WIB`; numbers `12.793` (id-ID grouping).

---

## 8. Accessibility checklist (WCAG 2.2 AA) — prototype self-check, not an audit
| SC | Requirement | Prototype status |
| --- | --- | --- |
| 1.1.1 | Text alternatives | Icons `aria-hidden`; charts have label + data table; QR has label |
| 1.3.1 | Info & relationships | Labels, fieldsets/legends, `th`, landmarks (`header/nav/main/aside`) |
| 1.4.3 / 1.4.11 | Contrast text / non-text | Tokens in §2.1 measured ≥ 4.5:1 text, ≥ 3:1 graphics |
| 1.4.10 | Reflow at 320–360 px | Stacked tables, single-column forms, drawer nav |
| 2.1.1 | Keyboard | All controls native; dialog via `showModal()` |
| 2.4.3 / 2.4.7 | Focus order / visible | Route change focuses `h1`; 2-ring focus indicator |
| 2.4.11 | Focus not obscured (new in 2.2) | **Risk:** sticky form footer and sticky top bar — implementation must add `scroll-padding` and test |
| 2.5.8 | Target size (new in 2.2) | ≥ 32 px everywhere |
| 3.3.1 / 3.3.3 | Error identification / suggestion | Inline + summary; slug suggestion; problem codes |
| 3.3.7 | Redundant entry (new in 2.2) | Grant form pre-fills user from context (`?user=`) |
| 3.3.8 | Accessible authentication (new in 2.2) | Password managers allowed (`autocomplete`), OTP accepts paste/`one-time-code` |
| 4.1.3 | Status messages | Toasts and live region (`aria-live`) |
Formal verification: axe + manual NVDA/TalkBack + keyboard tests on staging (TST-009, #23).

---

## 9. Prototype → validation plan
1. The origin deployment validated these screens with an offline clickable prototype that is not included in this upstream; build your own from this specification.
2. Use the **Mode peran** selector to switch between 7 fictitious personas (platform owner, the organisation admin, unit admin Branch A, editor, approver, analyst, auditor). Navigation, data scope, disabled actions and direct-URL denials change accordingly.
3. Run tasks UXT-001..014 listed on the prototype's "Peta Layar" page with the participants defined in [user-research-plan.md](../docs/user-research-plan.md); record completion, time, errors, severity.
4. Feed findings back into this document and the prototype (new version tag), re-test critical flows, obtain product-owner sign-off — then update [traceability.md](../docs/traceability.md) and close SPEC-04.

## 10. Known limitations of the prototype
- QR image is an **illustrative pattern, not scannable**; the real generator (#16) must pass machine-scan test TST-005.
- Authorization, RLS, audit hash chain and conflict handling are **simulated in the browser** to demonstrate UX only.
- Persona switcher exists only for testing; production has no role switching.
- Charts and figures are fictitious deterministic data; names are fictitious (`contoh.invalid` e-mails).
- unit names are used as organisational examples; the real unit list must come from your organisation.

## References
- W3C, *Web Content Accessibility Guidelines (WCAG) 2.2*, 2023 — https://www.w3.org/TR/WCAG22/
- Filament 5 documentation — https://filamentphp.com/docs/5.x/introduction/installation
- ISO/IEC 18004:2024 *QR Code bar code symbology* (quiet zone, error-correction levels)
- ISO 9241-110:2020 *Interaction principles*; ISO 9241-210:2019 *Human-centred design*; ISO/IEC 25010:2023 *Product quality model*
- NIST SP 800-63B *Digital Identity Guidelines — Authentication* — https://pages.nist.gov/800-63-4/
- OWASP Cheat Sheets: Unvalidated Redirects; Authorization; Logging — https://cheatsheetseries.owasp.org/
- Nielsen Norman Group, *10 Usability Heuristics for User Interface Design* — https://www.nngroup.com/articles/ten-usability-heuristics/
- GOV.UK Design System — error summary and confirmation patterns — https://design-system.service.gov.uk/
