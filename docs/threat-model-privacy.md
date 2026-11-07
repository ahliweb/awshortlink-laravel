# Threat Model and Privacy Impact Assessment — Draft

**System boundary:** anonymous GET /buka/{slug}; authenticated Filament/admin and integration API; private DB; package upload and hosting panel; external destination checker jobs optional. **Method:** STRIDE over trust boundaries + privacy impact questions, not a claim of compliance.

## Threat register
| ID | STRIDE | Threat | Severity initial | Required mitigations and test |
| --- | --- | --- | --- | --- |
| THR-001 | Tamper/Spoof | Trusted .go.id short link becomes open redirect or phishing lure | Critical | Destination allowlist/approval, URL parser, preview on noninstitutional sites, suspend; test hostile URLs |
| THR-002 | Elevation | Editor changes another unit's destination | Critical | Policies, scoped queries, negative tests direct-object IDs and nested resources |
| THR-003 | Spoof/Repudiation | Stolen admin credentials or replayed API token | High | MFA, session hardening, scoped hashed tokens, rotation, audit/alerts |
| THR-004 | Information disclosure | Query token, PII, medical identifier leaks to log/analytics/referrer | Critical | Reject private destination patterns, redact query, Referrer-Policy, minimize log retention |
| THR-005 | SSRF | Health checker visits loopback/metadata/private endpoint or DNS rebinding | Critical | Validate initial/redirect URLs, DNS resolution/IP range, restricted egress, timeout, forbid unsafe ports |
| THR-006 | DoS | Huge click burst or bot scan floods app/database | High | WAF/rate limits, index/cache review, bounded writes, low-cost unknown slug handling |
| THR-007 | Tamper | Slug collision/reuse sends printed QR to different resource | High | DB unique constraints, permanent tombstone/reserved slug policy, auditable change history |
| THR-008 | Information disclosure | backup/.env/vendor or logs exposed under /buka | Critical | Private files outside webroot, deny probes, artifact manifest, staging security scan |
| THR-009 | Tamper | malicious CSV formula, XSS in title, unsafe QR SVG | High | CSV escaping, Blade output escaping, safe SVG sanitization/generation, CSP |
| THR-010 | Repudiation | approval and suspend events lost or altered | High | Same-transaction audit for important mutations, append-only records, actor/time/reason |
| THR-011 | DoS | Cron jobs pile up on shared host | Medium | bounded queue, locks, job TTL, failure alerts; degrade feature gracefully |
| THR-012 | Supply chain | compromised Composer/npm dependency or unsigned package | High | lockfiles, SBOM, vulnerability scan, verified artifact checksums, trust CI host |
| THR-013 | Disclosure | click geolocation uniquely identifies citizen | High | coarse/no location as default, suppress small cohorts, do not persist full IP by default |
| THR-014 | Spoof/Tamper | Host header/rewrite poisoning wrong short domain | High | trusted hosts/proxies and canonical origin, URL/route integration tests |
| THR-015 | Tamper | Open approval workflow allows self-approval for risky domains | High | separation of duties by policy; emergency suspend explicitly audited |

## Privacy classification (proposed)
- **Public:** published slug, human title, safe nonsecret destination, public QR.
- **Internal:** organization ownership, approval reason, account ID, operational metrics, audit records.
- **Confidential:** admin login and recovery data, API key material (only hashes stored), secret configs, hosting backups.
- **Prohibited:** patient name/NIK/RME, diagnoses, clinical records, access tokens in URLs or report exports.

### Data minimization and retention defaults — pending institutional DPO approval
- Do not collect raw client IP or fingerprint, user-agent string or precise geolocation in application click store by default.
- Aggregate anonymous counters by day, link, campaign, coarse referrer classification; optional bot counts may be approximate.
- If raw event necessary for security, record only strictly necessary fields with expiry, purpose, legal basis and owner; propose <=30 days raw and <=13 months aggregate subject to legal schedule and approval, NOT unconditional legal retention.
- Audit records: propose >=1 year retention only after records schedule/legal review; access restricted and tamper resistant.
- Logs: truncate URLs/queries before log; suppress bearer tokens, cookies, sessions, passwords.
- No third-party analytics scripts by default; no cross-service identifiable visitor correlation.
- Implement access/export/delete procedure, incident contact and lawful disclosure rules before collection.

## DPIA / UU PDP open assessment questions
Who is pengendali/pemroses? On what processing basis and notice? Is person-level geolocation needed? Which data subjects (including minors) may scan QR? Does target add a third-party processor? Where are backups and servers located? What is access/retention and disposal? What breach notification procedure and impact assessment apply? Document decisions before Gate 9 and before production.

## Abuse response
A report of phishing or bad target creates urgent triage; central authorized admin can suspend immediately, purge controlled caches, verify resolver status from multiple networks, notify site security/communications, preserve least-necessary evidence, review post-incident. Never redirect invalid link to arbitrary user-supplied fallback.

## References
OWASP redirects: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
OWASP SSRF: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
OWASP logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
UU PDP: https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022


## Additional IAM / PostgreSQL threats (P0)
| ID | Severity | Threat | Mitigation and evidence |
| --- | --- | --- | --- |
| THR-016 | Critical | Admin grants themselves or another unit privileged role | Delegated grant ceilings, protected role catalog, independent approval, immutable audit, deny tests |
| THR-017 | Critical | Missing RLS context or owner/BYPASSRLS exposes cross-unit data | Strict nonowner runtime SQL role, mandatory RLS, no-context deny, FORCE where relevant, SQL isolation tests |
| THR-018 | High | Pooled connection leaks previous actor/unit | Transaction-local context, rollback, parallel A/B connection tests |
| THR-019 | High | ABAC editor injects executable rule or silently publishes privilege | Restricted JSONB DSL schema, simulation, review, versioned rollback, no arbitrary SQL/PHP |
| THR-020 | High | Disabled owner/suspended user retains permissions via sessions/queue | Last owner invariant, revoke tokens/sessions, valid-at-time scopes and queue context validation |
| THR-021 | Critical | PostgreSQL maintenance backup loses rows due to RLS | Separate approved backup role, verify row counts, policies/GRANT restored, backup rehearsal |

Identity and access policy data require explicit minimization, ownership, retention and separate security approval; no production secrets or patient data in policy evaluation logs. See identity-rbac-abac.md and postgresql-rls-design.md.

---

## Gate 9 Second-Pass Security & Privacy Re-Review (Workflow Step 3 → Step 9)

Per owner's internal cross-portfolio standard (the development-flow standard §3 Gate 9 checklist), this section records the **second-pass security and privacy review** conducted after UI screens (`UI-001..018`), PostgreSQL schema (`TBL-001..022`), and API contracts (`API-001..050`, `EVT-001..006`) were finalized:

### 1. DPIA Register (`DPIA-001..008` — UU No. 27 Tahun 2022 PDP)
| DPIA ID | Assessment Question | Specification Baseline ([ADR-0007](adr/0007-resolved-design-decisions-des-001-015.md)) | Approval Owner |
| --- | --- | --- | --- |
| **DPIA-001** | Data controller (*Pengendali Data*) & processor (*Pemroses*) | **Controller:** @@ORG_NAME@@. **Processor:** Internal the organisation IT team or its hosting operator. No third-party analytics SaaS processor. | Kepala the organisation / PPID / DPO |
| **DPIA-002** | Lawful basis (*Dasar Pemrosesan* UU PDP Ps. 20) | Public task & official institutional administration (*pelaksanaan tugas untuk kepentingan umum / pelayanan publik* for public links; employment/official mandate for staff IAM accounts). | the organisation Legal / DPO |
| **DPIA-003** | Categories of data subjects & vulnerable groups | (1) Anonymous citizens/patients/minors scanning public QR codes: **zero personal data collected** (no IP, UA, cookie, or device fingerprint stored; `DES-007`). (2) Authorized the organisation/branch staff: official work identity (`name`, `email`, unit membership, role grants, audit actions). | DPO |
| **DPIA-004** | Prohibited health / identity data enforcement | URL canonicalizer (`ALG-002`) rejects query strings/paths containing `nik`, `no_rm`, `rm`, 16-digit NIK patterns, e-mail addresses, and auth tokens (`THR-004`). | Security Owner |
| **DPIA-005** | Small-cohort re-identification risk (`THR-013`) | Threshold locked at **$k = 10$** (`DES-005`). Any daily/channel cell with `1..9` clicks is masked as `"<10"` in UI (`UI-001`, `UI-006`) and standard exports. | DPO / Analyst Lead |
| **DPIA-006** | PII retention & disposal schedule | Staff accounts (`users`): active during employment/mandate; `disabled` status retains minimal `id`, `name`, `email` for immutable audit attribution per government archive schedule, while revoking all sessions/tokens (`sessions`, `api_credentials` purged within 30 days of revocation). Aggregate click stats (`link_daily_stats`): 13 months daily, then rolled to monthly totals. Application logs: 14 days rolling, query strings stripped. | DPO / Arsiparis |
| **DPIA-007** | Data subject rights (*Hak Subjek Data* UU PDP Ps. 5–13) | Staff may inspect their own profile, unit memberships, role grants, and active sessions via `UI-018` (`GET /access/me`, `GET /access/me/grants`, `GET /access/me/sessions`) and request correction or offboarding through `unit_admin` / `org_admin` (`users.update`, `users.disable`). Citizens are not tracked and require no account erasure flow; misuse reports (`UI-009`) allow optional contact info purged after incident closure (≤ 90 days). | DPO |
| **DPIA-008** | Breach notification & emergency containment (UU PDP Ps. 46) | Immediate link suspension (`POST /links/{id}/suspend`, `UI-004`/`UI-007`), account/session revocation (`POST /access/users/{id}/revoke-sessions`, `UI-011`), ABAC policy rollback (`POST /access/policies/{id}/rollback`, `UI-014`), and 3×24 hour statutory notification workflow in `operations-runbook.md`. | Security Owner / DPO |

### 2. Second-Pass UI, Data, and API Security Verification
- **UI-001..018 review:** Every screen state displays canonical destination hostnames (`host_canonical`) without automatic redirect; destructive/high-risk mutations require typed confirmation and step-up MFA (`DES-006`); cross-unit unauthorized lookups return HTTP `404` (`NotFound`) to prevent resource enumeration; Effective Access Inspector (`UI-016`) redacts resource titles/URLs outside the caller's RLS scope.
- **Database & RLS review (`TBL-001..022`):** All 22 tables are assigned explicit data classifications and retention rules in [data-model.md](data-model.md); `shortlink.public_resolvable_links` exposes only `link_id`, `namespace`, `slug`, `status`, `target_url`, and `expires_at` for published links; suspended links resolve to `unavailable` → HTTP `404` (`DES-003`).
- **API & Event review (`API-001..050`, `EVT-001..006`):** Every OpenAPI operation carries an explicit `x-permission` binding; mutations require `If-Match` optimistic locking (`409 Conflict` / `428 Precondition Required`); AsyncAPI events carry `eventId`, `occurredAt`, and redacted payloads with zero PII or secret tokens.
