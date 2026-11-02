# Operational Runbook — AW Shortlink (`v1.0.0`)

**Current status:** Active (`v1.0.0` — Gate 15 Approved 2026-11-01). Automated synthetic probe: `bash scripts/post-deploy-verify.sh`; backup/restore rehearsal: `bash scripts/rehearse-backup-restore.sh`; CLI health & audit verification: `php artisan rls:verify` and `php artisan audit:verify`.

## Ownership and service categories
- Product owner / authorised publisher: TBD.
- Technical operator / hosting provider: TBD.
- Information security and privacy point of contact: TBD.
- Service users: citizens scanning QR and authorised editors.
- Public redirect incident is higher priority than inability to view a report.

## Observability (minimal hosting-compatible)
Monitor external synthetic probes: /buka/ homepage, one **synthetic** active test slug, expired slug, revoked slug, static asset, admin login status (not credentials), parent website homepage and key existing paths. Monitor app errors, DB connectivity, average & p95 redirect latency, click write errors, suspicious slug enumeration, failed logins, outbox/queue if enabled, storage usage and last successful backup.

Do not log full destination query, IP if unnecessary, Authorization/Cookie headers, secrets, patient records or request body. Logs redact URLs and use minimal request correlation ID.

## Incident playbooks
### Suspected phishing / unauthorized target
1. Authorized incident handler suspends link immediately and records reason, actor and time.
2. From independent network check URL no longer redirects; invalidate any approved cache paths; publish public warning only if necessary.
3. Preserve redacted evidence: affected slug, approved target/version hash, approval chain and audit correlation.
4. Investigate compromised account / destination; rotate tokens and suspend sessions where indicated.
5. Notify institutional security and privacy owner under applicable incident policy, document restoration authorization and postmortem.

### 5xx / DB unavailable
Check hosting incident status and DB credentials/limits without exposing config. Resolver returns 503 rather than redirecting to stale unsafe destination. Restore DB or previous verified release. Validate key URLs and parent site after remediation.

### Wrong destination / QR printed
Suspend or revert to previously approved destination through new versioned approval transaction. Printed slug remains reserved. Never reassign slug or use permanent redirect; notify communications owners and record issue.

### Analytics/cron failed
Prioritize safe redirect; dashboard displays data freshness and partial count. Repair cron/queue with bounded retry and integrity tests. Do not backfill guessed clicks.

### Broken parent website routing
Roll back only /buka delegation and isolate public app; restore backed-up parent configuration via hosting operator; compare before/after HTTP checks.

## Routine operations
Daily: synthetic tests, error/suspension/abuse alerts and backup success. Weekly: review active links/expired URLs, report privacy counts and dependency advisories, cron health. Monthly: audit privileged access and revoked tokens, backup restore rehearsal sample, uptime/SLO report, broken-link checks if approved. Quarterly: security test, vendor/license review, retention validation, disaster recovery exercise and permission recertification.

## Backup, restore and business continuity
Document DB consistent snapshot method, private secrets protected separately, QR asset reproducibility, backup encryption, target recovery owner, RPO/RTO validated. Restore test must include accounts, links, tombstones, audit integrity, approved target pointer and /buka route. Never publicly assert RPO 15m/RTO 4h until measurement and owner approval. Backups must not be web-accessible.

## Privacy & compliance
Maintain records retention schedule, data incident protocol, privacy notice and request handling. Conditional click event capture must be explicitly approved; default aggregate-only. Service design aligns to ISO 27001/27002/27005, 22301 and 20000-1 as guidance not certification. See compliance-standards.md.


## PostgreSQL and IAM operational controls
Daily verify PostgreSQL connectivity, RLS policy drift, privileged grant events and account suspension alerts; weekly inspect expired time-bound roles and approved ABAC policy changes; monthly recertify role assignments, admin MFA and access to analytics. Backups executed via authorized PostgreSQL backup role must contain RLS-restricted records and restore grants/policies. Verify runtime SQL identity cannot BYPASSRLS and public resolver cannot list accounts. During credential compromise revoke sessions, role assignments and tokens, validate deny without delay, record responsible actor and reason. Never rely on web route for DB migrations. Refer to postgresql-rls-design.md and identity-rbac-abac.md.
