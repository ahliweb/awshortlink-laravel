# Changelog — AW Shortlink

## [Unreleased]

### Changed
- **Admin sidebar menu shortened** so labels are no longer truncated (ellipsis): group titles (`TAUTAN`, `ANALITIK`, `TATA KELOLA`, `IAM & KEAMANAN`, `SISTEM`) and items (`Dasbor`, `Daftar Tautan`, `Buat Tautan`, `Persetujuan`, `Laporan Masuk`, `Analitik Klik`, `Log Audit`, `Pengguna`, `Unit Organisasi`, `Peran & Izin`, `Kebijakan Akses`, `Inspektur Akses`, `Pengaturan`). Full screen titles remain in page headings, the dashboard menu cards and the sidebar link tooltip (`title`).

## [1.1.0] — Upstream import (generalised from the first production deployment)

First public release. Functionality corresponds to the origin deployment's `v1.1.0`; everything specific to that
organisation was removed and the items below were changed on the way in.

### Added
- Environment-driven deployment identity (`BRAND_*`, `APP_URL`), neutral placeholder logo, root-unit seed only.
- `SHORTLINK_ALLOWLIST_HOSTS`, `SHORTLINK_MEDIUM_RISK_SUFFIXES`, `TRUSTED_PROXIES`, `ANALYTICS_*` switches (see `.env.example`).
- `tests/08_security_hardening_smoke.php` regression suite; `SECURITY.md`; real CycloneDX SBOM generated from `composer.lock`.
- `docker/php/Dockerfile` so tests and tooling run without a local PHP install; `scripts/lib/test-env.sh` (random per-workspace test credentials).

### Changed (security & privacy)
- Static asset route confined to `public/assets/` (extension allowlist, dot-segment/encoding rejection, `realpath` containment); the documentation file route was removed.
- Client IP honours forwarding headers only from `TRUSTED_PROXIES`; geo headers are believed only from a trusted peer; no fabricated location defaults.
- Per-visitor telemetry is opt-in (`ANALYTICS_RAW_EVENTS_ENABLED`), IP truncated, Referer reduced to origin, purged by retention; its RLS `SELECT` policy is now unit-scoped and a global-only `DELETE` policy was added.
- No default or embedded credentials: DB defaults, role passwords (`0001_roles.sql` takes `psql -v` variables), CAPTCHA HMAC key (derived from `APP_KEY`, fails closed) and seeded demo accounts (opt-in, random per run, refused in production).
- Protected-owner behaviour is driven by `is_protected_owner`, not by a hard-coded e-mail address.
- Default destination allowlist is empty; public file-sharing hosts are no longer trusted by default.
- Temporary passwords for new/reset accounts are high-entropy (144 bits).
- Auth throttle state lives in a private (0700) directory under `storage/` instead of a shared `/tmp` path.
- `Migrator::resetAllData()` is refused in production and requires `SHORTLINK_ALLOW_DATA_RESET=1`.
- Release tooling: production import SQL is generated from a fresh production-mode migration (not from the test database) and guarded against credentials/test data; release artifacts include production `vendor/`; `configure-env.sh` no longer interpolates secrets into PHP source; deploy scripts have no built-in hosts/accounts.

### Removed
- Organisation-specific documents, manuals, SOPs, screenshots, videos, seed scripts, prototype fixtures and the government logo.
