# AW Shortlink — Engineering / AI Working Contract

Source-of-truth priority: this repository's code, tests and ADRs > official framework docs > earlier plans. Do not
claim a module exists unless the code and tests show it. Read `docs/README.md`, `docs/decision-log.md` and the ADRs first.

## Non-negotiables

1. **No secrets or instance data in Git.** No passwords, keys, tokens, TOTP secrets, personal e-mails, hostnames, IPs,
   officials' names or organisation branding in source, tests, docs or scripts. Use environment variables; tests use
   per-run random credentials from `scripts/lib/test-env.sh`. A change that adds a default credential is rejected.
2. **Fail closed.** Authorisation is enforced in the application *and* by PostgreSQL RLS; hiding a menu item is not a control.
   Never trust client-supplied headers (client IP, host, geo) unless the peer is a configured trusted proxy.
3. **PostgreSQL only** (ADR-0005). No SQLite/MySQL/MariaDB paths. Runtime roles are non-owner and `NOBYPASSRLS`; every new
   table needs `ENABLE` + `FORCE` RLS policies and an entry in the RLS tests.
4. **Privacy by default** (ADR-0003). New personal-data fields need a classification, a retention rule and an opt-in switch.
5. **No SSH assumed on production.** Build on a trusted machine, ship an immutable artifact; no web-exposed installer,
   artisan route or migration endpoint. Never serve repository files from the application except `public/assets/*`
   through the confined resolver.
6. **Redirect path is network-free**: no DNS/HTTP/geo lookups or QR rendering on a resolve request.

## Workflow

- Atomic commits, SemVer, update `CHANGELOG.md`; keep PRD/ERD/OpenAPI/ADRs/tests/runbook in sync when a contract changes.
- Every behavioural or security change ships with a test in `tests/` (see `tests/08_security_hardening_smoke.php`).
- Run `bash scripts/ci.sh` before opening a PR. Vulnerability fixes: follow `SECURITY.md` (private first).
- Stop and ask when hosting/ownership assumptions are unverified; do not invent facts.
