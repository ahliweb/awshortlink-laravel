#!/usr/bin/env bash
# ==============================================================================
# Optional convenience: upload the release ZIP to a host over SSH, import the SQL and generate .env.
# Run from a TRUSTED LOCAL machine. Production does not need SSH at all (see docs/deployment-no-ssh.md); use the
# panel/SFTP route if you prefer.
#
# There are NO built-in hosts, paths or accounts: you must provide them.
#   SSH_HOST    ssh config alias or user@host          (required)
#   REMOTE_DIR  absolute-or-home-relative target dir   (required)
#   PUBLIC_URL  https URL of the deployed namespace    (required, e.g. https://links.example.org/buka)
#   SKIP_SQL=1  skip the database import
#
# Secrets are typed locally and sent over the SSH stdin channel — never in argv, history, or Git.
# ==============================================================================
set -euo pipefail

: "${SSH_HOST:?set SSH_HOST}"; : "${REMOTE_DIR:?set REMOTE_DIR}"; : "${PUBLIC_URL:?set PUBLIC_URL (https://...)}"
[[ "${PUBLIC_URL}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] || { echo "PUBLIC_URL must be a clean https URL" >&2; exit 1; }
[[ "${REMOTE_DIR}" =~ ^[A-Za-z0-9._~/-]+$ ]] || { echo "REMOTE_DIR contains unsupported characters" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP="${ROOT_DIR}/build/awshortlink_release.zip"
SSH_OPTS=(-o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
[[ -f "${ZIP}" ]] || bash "${ROOT_DIR}/scripts/build-release-zip.sh"

echo "==> [1/4] Uploading to ${SSH_HOST}:${REMOTE_DIR}"
ssh "${SSH_OPTS[@]}" "${SSH_HOST}" "mkdir -p '${REMOTE_DIR}'"
scp -q "${SSH_OPTS[@]}" "${ZIP}" "${SSH_HOST}:${REMOTE_DIR}/awshortlink_release.zip"
ssh "${SSH_OPTS[@]}" "${SSH_HOST}" "cd '${REMOTE_DIR}' && unzip -oq awshortlink_release.zip && rm -f awshortlink_release.zip && chmod 600 database_import.sql && chmod +x configure-env.sh && chmod -R u+rwX,g+rwX storage"

echo "==> [2/4] Database & application settings (typed here only)"
read -rp "DB host [127.0.0.1]: " DB_HOST; DB_HOST="${DB_HOST:-127.0.0.1}"
read -rp "DB port [5432]: " DB_PORT; DB_PORT="${DB_PORT:-5432}"
read -rp "DB name: " DB_NAME
read -rp "DB user: " DB_USER
read -rsp "DB password: " DB_PASS; echo
read -rp "Organisation name [Your Organization]: " ORG_NAME; ORG_NAME="${ORG_NAME:-Your Organization}"
read -rp "Organisation short name [Your Org]: " ORG_SHORT; ORG_SHORT="${ORG_SHORT:-Your Org}"
read -rp "Allowlisted destination hosts (comma-separated, may be empty): " ALLOWLIST
read -rp "Trusted proxy IPs/CIDRs (comma-separated, empty = none): " PROXIES
[[ -n "${DB_NAME}" && -n "${DB_USER}" && -n "${DB_PASS}" ]] || { echo "DB name/user/password are required." >&2; exit 1; }
for v in "${DB_HOST}" "${DB_PORT}" "${DB_NAME}" "${DB_USER}" "${DB_PASS}" "${ORG_NAME}" "${ORG_SHORT}" "${ALLOWLIST}" "${PROXIES}"; do
  [[ "${v}" != *$'\n'* && "${v}" != *$'\r'* ]] || { echo "Values must be single-line." >&2; exit 1; }
done

# Answers in configure-env.sh ANSWER_ORDER; empty lines mean "same as application user / none".
send_answers() {
  printf '%s\n' "${DB_HOST}" "${DB_PORT}" "${DB_NAME}" "${DB_USER}" "${DB_PASS}" "" "" "" "" \
    "${PUBLIC_URL}" "${ORG_NAME}" "${ORG_SHORT}" "${ALLOWLIST}" "${PROXIES}"
}

if [[ "${SKIP_SQL:-0}" != "1" ]]; then
  echo "==> [3/4] Importing database_import.sql (single transaction; aborts cleanly on error)"
  REMOTE_SCRIPT="$(cat <<'REMOTE'
IFS= read -r H; IFS= read -r P; IFS= read -r D; IFS= read -r U; IFS= read -r W
export PGPASSWORD="$W" LC_ALL=C
cd "$REMOTE_DIR"
PSQL="psql -h $H -p $P -U $U -d $D -v ON_ERROR_STOP=1 -q"
EXISTS=$($PSQL -tAc "select count(*) from pg_namespace where nspname='shortlink'")
if [ "$EXISTS" != "0" ]; then echo "Schema 'shortlink' already exists; refusing to import over it." >&2; exit 3; fi
HAS_ROLE=$($PSQL -tAc "select count(*) from pg_roles where rolname='awshortlink_app'")
if [ "$HAS_ROLE" = "0" ]; then
  echo "Dedicated roles not available -> single-user mode (policies TO PUBLIC; FORCE RLS still applies)"
  sed -E 's/ TO awshortlink_(app|resolver|owner|migrator|backup)\b/ TO PUBLIC/g' database_import.sql | $PSQL -1 -o /dev/null
else
  $PSQL -1 -o /dev/null -f database_import.sql
fi
echo "Import OK: $($PSQL -tAc "select count(*) from shortlink.permissions") permissions"
REMOTE
)"
  { printf '%s\n' "${DB_HOST}" "${DB_PORT}" "${DB_NAME}" "${DB_USER}" "${DB_PASS}"; } \
    | ssh "${SSH_OPTS[@]}" "${SSH_HOST}" "REMOTE_DIR='${REMOTE_DIR}' bash -c $(printf '%q' "${REMOTE_SCRIPT}")" \
    || { echo "Import failed." >&2; exit 1; }
else
  echo "==> [3/4] SQL import skipped (SKIP_SQL=1)"
fi

echo "==> [4/4] Writing .env (mode 600) and verifying"
send_answers | ssh "${SSH_OPTS[@]}" "${SSH_HOST}" "cd '${REMOTE_DIR}' && ./configure-env.sh --stdin" | tail -n 6
unset DB_PASS
echo "Verify (expect: slug 302/404, .env 403/404, assets traversal 404):"
for path in "" "does-not-exist" ".env" "assets/../.env"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --path-as-is --max-redirs 0 "${PUBLIC_URL}/${path}" || true)"
  echo "    ${PUBLIC_URL}/${path} -> HTTP ${code}"
done
echo "Now remove database_import.sql and configure-env.sh from the server, then run: php artisan admin:bootstrap <email>"
