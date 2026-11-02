# AW Shortlink

[![CI](https://github.com/ahliweb/awshortlink-laravel/actions/workflows/ci.yml/badge.svg)](https://github.com/ahliweb/awshortlink-laravel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Security-first, self-hosted **short URL + dynamic QR + privacy-preserving analytics** for organisations that must
publish trustworthy links: approval workflows, immutable slugs, strict destination policy, managed RBAC + ABAC and
PostgreSQL **mandatory row-level security**.

This repository is the **public upstream** for every AW Shortlink deployment. It was extracted from the first
production deployment (a government health office) and generalised: all organisation-specific names, hosts, units,
staff, credentials and operational manuals were removed, and several issues found during the extraction were fixed
(see [CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md)).

> **Implementation status — please read.** The runtime is a dependency-light **PHP ≥ 8.3** application with a
> Laravel-style layout (`app/`, `config/`, `artisan`, `database/`). `composer.json` requires only a QR library; it does
> **not** (yet) depend on `laravel/framework` or Filament, even though the ADRs and design documents describe Laravel 13 /
> Filament 5 as the target architecture. Treat the documents as the design intent and the code/tests as the truth.

## Highlights

- **PostgreSQL only** (ADR-0005). Row-level security is `ENABLE`d and `FORCE`d on every table; runtime roles are
  non-owner, `NOBYPASSRLS`; the public resolver role can only read one view and call one function.
- **Approved destinations & immutable slugs** (ADR-0002): canonicalisation, HTTPS-only, credentials/unsafe schemes denied,
  sensitive query keys rejected, public shorteners denied, SoD (self-approval blocked) for riskier destinations.
- **Managed RBAC + ABAC** with unit scopes, time-bound grants, versioned policies, independent approval and an access inspector.
- **Tamper-evident audit** (SHA-256 hash chain, verifiable with `php artisan audit:verify`).
- **Aggregate-only analytics by default**; per-visitor telemetry is opt-in, truncated and time-limited (ADR-0003).
- **Admin MFA (TOTP)**, brute-force limiter, self-hosted accessible CAPTCHA + honeypot on public forms.
- **No SSH required on production**: build a package on a trusted machine, upload by SFTP/panel ([docs/deployment-no-ssh.md](docs/deployment-no-ssh.md)).

## Quick start (development / evaluation)

Requirements: Docker with Compose, `openssl`, `node` ≥ 20 and `python3` with PyYAML (contract check only).

```bash
docker build -t awshortlink-php:local docker/php   # PHP 8.3 CLI with pdo_pgsql, gd, intl
bash scripts/ci.sh                                 # PostgreSQL 18 + roles, lint, contract, all suites, artifact, backup/restore
```

`scripts/ci.sh` creates **throw-away random credentials** in `build/.test-env` (git-ignored, mode 600). Nothing secret
or guessable is stored in the repository.

## Deploy

1. Provision PostgreSQL 14+ (18 recommended). With a role-capable host run `database/sql/rls/0001_roles.sql` supplying
   **your own** passwords via `psql -v` (see the header of that file); on shared hosting use the single-user import.
2. `bash scripts/build-release-zip.sh` (or `scripts/build-artifact.sh`) on a trusted machine → upload → run
   `./configure-env.sh` (writes `.env` with mode 600) → import the generated `database_import.sql` → delete both files.
3. `php artisan admin:bootstrap <email>` activates the protected owner (password + TOTP secret, shown once).
4. Verify: slug → 302, unknown slug → 404, `/.env` → 403/404, `/assets/../.env` → 404.

Configuration is entirely environment-driven — see [.env.example](.env.example). Key switches:

| Variable | Purpose | Default |
| --- | --- | --- |
| `APP_URL` | Public base URL incl. prefix (must be https in production) | – |
| `BRAND_ORG_NAME`, `BRAND_ORG_SHORT`, `BRAND_LOGO_PATH` | Identity shown in UI/QR | generic placeholders |
| `SHORTLINK_ALLOWLIST_HOSTS` | Hosts you trust as low-risk destinations | **empty** |
| `TRUSTED_PROXIES` | Proxies whose forwarding headers are believed | **none** |
| `ANALYTICS_RAW_EVENTS_ENABLED` | Per-visitor telemetry | **off** |

The public path prefix is currently fixed to `/buka/*` (see ADR-0001); making it configurable is a good first contribution.

## Documentation

Start with [docs/README.md](docs/README.md), then [docs/master-blueprint.md](docs/master-blueprint.md),
[docs/threat-model-privacy.md](docs/threat-model-privacy.md), [docs/postgresql-rls-design.md](docs/postgresql-rls-design.md)
and the [ADRs](docs/adr/README.md). Read [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before contributing.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for them.

## License

MIT — see [LICENSE](LICENSE). Verify third-party licences (`build/sbom.cdx.json` is generated from `composer.lock`).
