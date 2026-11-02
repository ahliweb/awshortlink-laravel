#!/usr/bin/env bash
# ==============================================================================
# Generates build/database_import.sql — a clean, PRODUCTION-mode PostgreSQL import for hosts where you cannot run
# `php artisan migrate:rls` (shared hosting, panel-only access).
#
# SECURITY: the file is produced by migrating a FRESH scratch database in production mode, NOT by dumping the test
# database. It therefore contains only the schema, RLS policies, permission/role catalog, your root unit, the
# two protected accounts in 'invited' state with NO credentials, and your destination rules — no demo data, no
# test links, no password hashes, no TOTP secrets. A guard fails the build if any of those slip in.
#
# Your organisation settings come from the environment (same names as .env): BRAND_ORG_NAME, BRAND_ROOT_UNIT_CODE,
# SHORTLINK_ALLOWLIST_HOSTS, SHORTLINK_OWNER_EMAIL, SHORTLINK_APPROVER_EMAIL.
# Needs the docker test database (see scripts/ci.sh) and PHP_IMAGE.
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"
OUT="${ROOT_DIR}/build/database_import.sql"
SCRATCH_DB="awshortlink_import_build"
COMPOSE=(docker compose -f "${ROOT_DIR}/compose.test.yml")
mkdir -p "${ROOT_DIR}/build"

docker compose -f "${ROOT_DIR}/compose.test.yml" up -d --wait >/dev/null
db_psql -d postgres -q -c "DROP DATABASE IF EXISTS ${SCRATCH_DB};" -c "CREATE DATABASE ${SCRATCH_DB};"
apply_roles "${SCRATCH_DB}"

echo "==> Migrating a fresh scratch database in PRODUCTION mode (no demo seed)..."
docker run --rm --network host -v "${ROOT_DIR}:/app" -w /app -u "$(id -u):$(id -g)" \
  -e APP_ENV=production -e "APP_URL=https://placeholder.invalid/buka" \
  -e DB_HOST=127.0.0.1 -e "DB_PORT=${TEST_DB_PORT}" -e "DB_DATABASE=${SCRATCH_DB}" \
  -e DB_MIGRATOR_USERNAME=awshortlink_migrator -e "DB_MIGRATOR_PASSWORD=${TEST_MIGRATOR_PW}" \
  -e DB_USERNAME=awshortlink_app -e "DB_PASSWORD=${TEST_APP_PW}" \
  -e "BRAND_ORG_NAME=${BRAND_ORG_NAME:-Your Organization}" -e "BRAND_ROOT_UNIT_CODE=${BRAND_ROOT_UNIT_CODE:-ROOT}" \
  -e "SHORTLINK_ALLOWLIST_HOSTS=${SHORTLINK_ALLOWLIST_HOSTS:-}" \
  -e "SHORTLINK_OWNER_EMAIL=${SHORTLINK_OWNER_EMAIL:-platform-owner@example.invalid}" \
  -e "SHORTLINK_APPROVER_EMAIL=${SHORTLINK_APPROVER_EMAIL:-security-approver@example.invalid}" \
  "${PHP_IMAGE}" php artisan migrate:rls

TMP_DUMP="${ROOT_DIR}/build/tmp_inserts.sql"
"${COMPOSE[@]}" exec -T -e PGPASSWORD="${POSTGRES_PASSWORD}" postgres-test \
  pg_dump -h 127.0.0.1 -U postgres -d "${SCRATCH_DB}" --schema=shortlink --no-owner --no-privileges --inserts \
  | grep -v -E '^\\(un)?restrict' > "${TMP_DUMP}"

cat > "${OUT}" <<'HDR'
-- AW Shortlink — production database import (schema shortlink). PostgreSQL 14+.
-- Generated from a fresh production-mode migration. Contains NO credentials. Activate the protected accounts with
--   php artisan admin:bootstrap <email>
SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;
CREATE SCHEMA IF NOT EXISTS shortlink;
SET search_path TO shortlink, public;
HDR
sed -E 's/CREATE SCHEMA shortlink;/CREATE SCHEMA IF NOT EXISTS shortlink;/' "${TMP_DUMP}" >> "${OUT}"
cat >> "${OUT}" <<'FTR'

-- Grant runtime privileges to the connecting user (single-user shared hosting), and to dedicated roles if present.
DO $$
BEGIN
    EXECUTE format('GRANT ALL ON SCHEMA shortlink TO %I', CURRENT_USER);
    EXECUTE format('GRANT ALL ON ALL TABLES IN SCHEMA shortlink TO %I', CURRENT_USER);
    EXECUTE format('GRANT ALL ON ALL SEQUENCES IN SCHEMA shortlink TO %I', CURRENT_USER);
    EXECUTE format('GRANT ALL ON ALL FUNCTIONS IN SCHEMA shortlink TO %I', CURRENT_USER);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'awshortlink_app') THEN
        GRANT USAGE ON SCHEMA shortlink TO awshortlink_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shortlink TO awshortlink_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA shortlink TO awshortlink_app;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA shortlink TO awshortlink_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'awshortlink_resolver') THEN
        GRANT USAGE ON SCHEMA shortlink TO awshortlink_resolver;
        GRANT SELECT ON shortlink.public_resolvable_links TO awshortlink_resolver;
        GRANT EXECUTE ON FUNCTION shortlink.record_click(uuid, smallint, text) TO awshortlink_resolver;
    END IF;
END
$$;
SET search_path TO shortlink, public;
FTR
rm -f "${TMP_DUMP}"
db_psql -d postgres -q -c "DROP DATABASE IF EXISTS ${SCRATCH_DB};"

# ---- Guards (fail closed) ---------------------------------------------------------------------------------
fail() { echo "ERROR: $1 — refusing to ship ${OUT}" >&2; rm -f "${OUT}"; exit 1; }
grep -qE '\$2[abxy]\$' "${OUT}" && fail "bcrypt password hash present"
grep -qE "INSERT INTO shortlink\.users VALUES .*'[A-Z2-7]{16,}'" "${OUT}" && fail "TOTP secret present"
grep -qE '^INSERT INTO shortlink\.(links|link_destinations|link_access_logs|abuse_reports) ' "${OUT}" && fail "demo/test link data present"
echo "[OK] Generated ${OUT} ($(wc -l < "${OUT}") lines) — guards passed."
