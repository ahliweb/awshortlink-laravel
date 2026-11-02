# Security Policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** (*Security* tab → *Report a vulnerability*) on this repository.
Please do not open public issues or pull requests for undisclosed vulnerabilities. Include affected version/commit,
reproduction steps and impact. We aim to acknowledge within 5 working days.

## Supported versions

Only the latest release of the default branch receives security fixes.

## Security model in one page

- **Fail closed.** Missing/invalid configuration (APP_KEY, APP_URL in production, DB credentials) stops the feature
  instead of falling back to a built-in secret. There are **no default passwords, keys or accounts** in this repository.
- **Database.** PostgreSQL only; `ENABLE` + `FORCE` row-level security everywhere; runtime roles are non-owner,
  `NOBYPASSRLS`; the anonymous resolver role is limited to one view and one function; backups use a dedicated read-only role.
- **Identity.** Protected baseline accounts are seeded `invited` with no credentials and activated by an operator with
  `php artisan admin:bootstrap`. TOTP MFA, server-side sessions, brute-force limiter keyed by IP **and** e-mail.
  Demo credentials exist only for the automated tests, behind `SHORTLINK_DEMO_SEED=1`, are random per run, and are
  refused when `APP_ENV=production`.
- **Client IP.** Forwarding headers are honoured **only** when the immediate peer is in `TRUSTED_PROXIES`; otherwise
  `REMOTE_ADDR` is used. Misconfiguring this lets clients spoof their IP and weaken the rate limiter.
- **Redirects.** Destinations are canonicalised and must satisfy the destination policy; the resolver never appends
  incoming query strings and never performs outbound requests on the redirect path.
- **Static files.** Only files inside `public/assets/` with an allowlisted extension are served; the router rejects dot
  segments, backslashes, NULs and percent-encoding. Source, `.env`, docs and config are never served by the application.
- **Privacy.** Aggregate analytics by default. Optional per-visitor telemetry stores a truncated IP, the Referer origin
  only, and is purged after `ANALYTICS_ACCESS_LOG_RETENTION_DAYS`. No patient/NIK/medical-record data in URLs.
- **Supply chain.** `composer.lock` is committed; the SBOM is generated from it; production artifacts contain only
  production dependencies.

## Operator checklist

- [ ] `APP_ENV=production`, `APP_DEBUG=false`, strong `APP_KEY`, https `APP_URL`.
- [ ] Unique, generated passwords for every DB role; `.env` mode 600 and outside the web root where possible.
- [ ] `TRUSTED_PROXIES` set only to proxies you operate (or empty).
- [ ] `SHORTLINK_ALLOWLIST_HOSTS` limited to hosts you control.
- [ ] Protected accounts activated with `admin:bootstrap`; MFA enrolled; the placeholder `*.example.invalid` addresses replaced.
- [ ] `php artisan rls:verify` and `php artisan audit:verify` pass; schedule `php artisan schedule:run` (cron) for retention and session expiry.
- [ ] After install, remove `database_import.sql` and `configure-env.sh` from the server.
- [ ] Probe `…/assets/../.env` and `…/.env` (expect 404/403) after every deployment.
