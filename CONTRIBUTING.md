# Contributing to AW Shortlink

Thank you for helping. This project is security- and privacy-sensitive, so a few rules are strict.

## Ground rules
- Read [AGENTS.md](AGENTS.md): no secrets or instance data in Git, fail-closed authorisation, PostgreSQL only with
  mandatory RLS, privacy by default, no network I/O on the redirect path.
- **Vulnerabilities are reported privately** — see [SECURITY.md](SECURITY.md). Never open a public issue or PR for one.
- Keep changes small and atomic; use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`; add `!` or a `BREAKING CHANGE:` footer for breaking changes).

## Development setup
Requirements: Docker with Compose, `openssl`, Node.js >= 20, Python 3 with PyYAML.

```bash
docker build -t awshortlink-php:local docker/php   # PHP 8.3 CLI (pdo_pgsql, gd, intl)
bash scripts/ci.sh                                 # full gate; creates random throw-away credentials in build/.test-env
```

Useful variables: `TEST_DB_PORT` (default 54328) if that port is taken, `PHP_IMAGE` to use another PHP image.
Run a single suite with: `source scripts/lib/test-env.sh && php_run tests/08_security_hardening_smoke.php`.

## Pull requests
1. Fork and branch from `main`.
2. Add or update tests (`tests/`); behavioural and security changes must be covered.
3. Update `CHANGELOG.md` and any affected docs, OpenAPI/AsyncAPI contracts and ADRs together.
4. Make sure `bash scripts/ci.sh` is green — the same gate runs in GitHub Actions.
5. Fill in the pull-request template. Maintainers squash-merge.

## Good first contributions
- Make the `/buka` path prefix configurable (see ADR-0001).
- One-time (replay-proof) CAPTCHA tokens.
- Additional deployment guides (nginx, shared-hosting variants).
