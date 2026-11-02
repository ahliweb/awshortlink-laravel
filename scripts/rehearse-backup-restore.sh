#!/usr/bin/env bash
# PostgreSQL backup & restore rehearsal (DES-010): pg_dump with the least-privilege `awshortlink_backup` role,
# restore into a clean database, then verify row counts and that compulsory RLS is intact (pg_policies).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"
DUMP_FILE="${ROOT_DIR}/build/awshortlink_backup_rehearsal.dump"
RESTORE_DB="awshortlink_restore_test"
COMPOSE=(docker compose -f "${ROOT_DIR}/compose.test.yml")
mkdir -p "${ROOT_DIR}/build"

# 1. Dump schema shortlink as the BYPASSRLS read-only backup role.
"${COMPOSE[@]}" exec -T -e PGPASSWORD="${TEST_BACKUP_PW}" postgres-test \
  pg_dump -h 127.0.0.1 -U awshortlink_backup -d "${TEST_DB_NAME}" \
  --schema=shortlink --format=custom --no-owner --no-acl > "${DUMP_FILE}"

# 2. Recreate a clean target database and apply role + schema DDL.
db_psql -d postgres -q -c "DROP DATABASE IF EXISTS ${RESTORE_DB};" -c "CREATE DATABASE ${RESTORE_DB};"
apply_roles "${RESTORE_DB}"
"${COMPOSE[@]}" exec -T -e PGPASSWORD="${TEST_MIGRATOR_PW}" postgres-test \
  psql -h 127.0.0.1 -v ON_ERROR_STOP=1 -q -U awshortlink_migrator -d "${RESTORE_DB}" \
  < "${ROOT_DIR}/database/sql/rls/0010_schema_and_tables.sql" >/dev/null

# 3. Restore data, then re-apply RLS policies & resolver surface.
"${COMPOSE[@]}" exec -T -e PGPASSWORD="${POSTGRES_PASSWORD}" postgres-test \
  pg_restore -h 127.0.0.1 --data-only --disable-triggers --no-owner --no-acl -U postgres -d "${RESTORE_DB}" < "${DUMP_FILE}"
for f in 0020_enable_rls_and_policies.sql 0030_resolver_view_and_click_fn.sql; do
  "${COMPOSE[@]}" exec -T -e PGPASSWORD="${TEST_MIGRATOR_PW}" postgres-test \
    psql -h 127.0.0.1 -v ON_ERROR_STOP=1 -q -U awshortlink_migrator -d "${RESTORE_DB}" \
    < "${ROOT_DIR}/database/sql/rls/${f}" >/dev/null
done

# 4. Verify.
q() { db_psql -d "${RESTORE_DB}" -tA -c "$1"; }
RESTORED_PERMS=$(q "SELECT count(*) FROM shortlink.permissions;")
RESTORED_POLICIES=$(q "SELECT count(*) FROM pg_policies WHERE schemaname = 'shortlink';")
RESTORED_UNPROTECTED=$(q "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'shortlink' AND c.relkind = 'r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);")

[[ "${RESTORED_PERMS}" -ge 62 ]] || { echo "ERROR: expected >= 62 restored permissions, got ${RESTORED_PERMS}" >&2; exit 1; }
[[ "${RESTORED_POLICIES}" -ge 60 ]] || { echo "ERROR: expected >= 60 restored RLS policies, got ${RESTORED_POLICIES}" >&2; exit 1; }
[[ "${RESTORED_UNPROTECTED}" -eq 0 ]] || { echo "ERROR: ${RESTORED_UNPROTECTED} tables lack ENABLE+FORCE RLS after restore" >&2; exit 1; }

db_psql -d postgres -q -c "DROP DATABASE IF EXISTS ${RESTORE_DB};"
echo "[OK] Backup & restore rehearsal verified (permissions=${RESTORED_PERMS}, rls_policies=${RESTORED_POLICIES}, unprotected_tables=${RESTORED_UNPROTECTED})"
