# Verification & Quality Plan — v1.0.0-draft

## Test layers
**Unit:** slug normalization, reserved names, domain policy canonicalization, TTL/state decision table, HTTP result, version arithmetic and event classification.
**Integration on production DB engine:** migration up/down where safe, constraints, lock/collision concurrency, Eloquent scopes, API permission denials, transactions/audit, Filament auth, expiry boundary, successful DB queue only if host cron.
**Contract:** generate mock from OpenAPI/AsyncAPI, frontend UI-IDs against mock first, then actual backend response schema, errors and pagination; never leave undocumented API routes.
**E2E:** browser at true /buka prefix over HTTPS, Filament/Livewire POST update route, parent website preservation, create->review->activate->click->suspend, QR scan from generated artifact, report export.
**Security:** OWASP ASVS-relevant controls; open redirect, SSRF checker, IDOR, XSS, CSRF, credential/token theft, malformed URL, host spoof, CSV formula, private file probes, rate limiting, abuse report and emergency stop.
**Load and reliability:** realistic Indonesian network probes, p50/p95/p99, throughput vs DB limits, no bottleneck on click logging, DB outage 503, analytics drop not breaking approved redirect. Measure current baseline before accepting p95 <=300ms target.

## Acceptance matrix
| TST ID | Maps | Scenario / pass |
| --- | --- | --- |
| TST-001 | REQ-001/007 | Safe 302 and Location; 404 unknown, 410 retired per policy, 503 when DB fails |
| TST-002 | REQ-002/003 | Concurrent duplicate slug 409, published slug never reassigned, destination approved revision only |
| TST-003 | REQ-004 | Unsafe schemes, credentials, loopback & malicious external hosts rejected, approved external policies traced |
| TST-004 | REQ-005/006 | Cross-unit IDOR and hidden Filament action direct POST denied |
| TST-005 | REQ-008 | QR SVG/PNG machine-scan returns exact short URL; safe artifact path |
| TST-006 | REQ-009 | Count types defined; no patient/IP raw storage; bot filtering not misrepresented |
| TST-007 | REQ-010 | Failed audit append rolls back privileged write; changed-by/source version recorded |
| TST-008 | REQ-011 | Full no-SSH staging package install, migration, rollback, /buka and parent site paths |
| TST-009 | REQ-012 | WCAG 2.2 AA keyboard, labels, contrast, error messages and 360px mobile |
| TST-010 | REQ-013 | Reviewer cannot self-approve high-risk destination, stale version rejected |
| TST-011 | REQ-015 | CSV formula-injection escaping, dry-run diff, duplicate and all-or-nothing apply |
| TST-012 | REQ-016 | API scope, token revocation, rate limiting, 401/403/404/409 documented |
| TST-013 | REQ-017 | No SSRF via redirects/DNS rebinding in P1 checker; no checker when safe egress absent |
| TST-014 | REQ-018 | Aggregation retention enforced only with proven scheduled purge or alternate workflow |

## CI without GitHub Actions requirement
Use local/self-hosted CI or manually invoked trusted pipeline per repository governance: PHP syntax/static analysis (PHPStan/Larastan), PHPUnit/Pest as chosen, composer validate/audit, secret scanner, PHP style (Pint), front end lint/build, integration DB (PostgreSQL production-equivalent major, active RLS and roles), DAST/E2E staging, SBOM and artifact SHA256. GitHub Actions may be added only by conscious policy decision, not required. Never upload secrets or production patient data.

## Definition of Done per issue
Requirements mapped; UX and contracts updated; tests (positive and negative) passing; roles and DB isolation tested; accessibility and security impact reviewed; deploy path & rollback documented; audited evidence links attached. Fail no-documentation rule.


## New critical IAM and DB tests
- TST-015: admin/user management, role/permission CRUD, scoped grants, prohibited escalation and last-owner protection.
- TST-016: ABAC constrained DSL, policy simulation, deny precedence, draft/review/approved/version rollback, MFA and independence checks.
- TST-017: PostgreSQL RLS SELECT/INSERT/UPDATE/DELETE and USING/WITH CHECK direct SQL; no-context deny and public resolver sanitization.
- TST-018: transaction-pool context after user A -> B, exceptions and cron jobs, no role/unit leak; runtime DB no superuser/BYPASSRLS/ownership.
- TST-019: account revocation/token/session invalidation, emergency access and immutable audit.
CI must fail when DB_CONNECTION is sqlite/mysql/mariadb or required relrowsecurity/relforcerowsecurity/policies are missing. Migration runs through privileged operator connection; tests run through restricted app role. Generate evidence after implementation, not before.
