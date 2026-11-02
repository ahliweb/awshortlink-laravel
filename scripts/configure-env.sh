#!/usr/bin/env bash
# ==============================================================================
# AW Shortlink — interactive production .env generator (chmod 600) + DB connection test.
#
#   ./configure-env.sh            interactive prompts
#   ./configure-env.sh --stdin    non-interactive: answers are read from stdin, one per line, in the order
#                                 listed in ANSWER_ORDER below (used by scripts/deploy-ssh.sh so secrets never
#                                 appear in process arguments or shell history).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${SCRIPT_DIR}"
[[ -f "${SCRIPT_DIR}/../config/database.php" ]] && TARGET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${TARGET_DIR}/.env"
STDIN_MODE=0; [[ "${1:-}" == "--stdin" ]] && STDIN_MODE=1

# ask VAR "Prompt" [default] [secret]
ask() {
  local var="$1" prompt="$2" default="${3:-}" secret="${4:-}" val=""
  if [[ "${STDIN_MODE}" == "1" ]]; then
    IFS= read -r val || true
  elif [[ "${secret}" == "secret" ]]; then
    read -rsp "${prompt}: " val; echo
  else
    read -rp "${prompt}${default:+ [${default}]}: " val
  fi
  val="${val:-${default}}"
  if [[ "${val}" == *$'\n'* || "${val}" == *$'\r'* ]]; then echo "Invalid value for ${var}" >&2; exit 1; fi
  printf -v "${var}" '%s' "${val}"
}

# ANSWER_ORDER (stdin mode): host port db user password resolver_user resolver_password migrator_user
#                            migrator_password app_url org_name org_short allowlist trusted_proxies
ask DB_HOST "PostgreSQL host" "127.0.0.1"
ask DB_PORT "PostgreSQL port" "5432"
ask DB_DATABASE "Database name"
ask DB_USERNAME "Application DB user"
ask DB_PASSWORD "Application DB password" "" secret
ask DB_RESOLVER_USER "Resolver DB user (empty = same as application user)" ""
ask DB_RESOLVER_PASS "Resolver DB password (empty = same as application)" "" secret
ask DB_MIGRATOR_USER "Migrator DB user (empty = same as application user)" ""
ask DB_MIGRATOR_PASS "Migrator DB password (empty = same as application)" "" secret
ask APP_URL "Public base URL incl. path prefix, https only (e.g. https://links.example.org/buka)"
ask BRAND_ORG_NAME "Organisation name" "Your Organization"
ask BRAND_ORG_SHORT "Organisation short name" "Your Org"
ask SHORTLINK_ALLOWLIST_HOSTS "Allowlisted destination hosts, comma-separated (e.g. example.org,*.example.org)" ""
ask TRUSTED_PROXIES "Trusted reverse-proxy IPs/CIDRs, comma-separated (empty = none; REMOTE_ADDR is used)" ""

for required in DB_DATABASE DB_USERNAME DB_PASSWORD APP_URL; do
  [[ -n "${!required}" ]] || { echo "${required} is required." >&2; exit 1; }
done
[[ "${APP_URL}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] || { echo "APP_URL must be a clean https URL." >&2; exit 1; }
DB_RESOLVER_USER="${DB_RESOLVER_USER:-${DB_USERNAME}}"; DB_RESOLVER_PASS="${DB_RESOLVER_PASS:-${DB_PASSWORD}}"
DB_MIGRATOR_USER="${DB_MIGRATOR_USER:-${DB_USERNAME}}"; DB_MIGRATOR_PASS="${DB_MIGRATOR_PASS:-${DB_PASSWORD}}"

APP_HOST="$(printf '%s' "${APP_URL}" | sed -E 's#^https://([^/:]+).*#\1#')"
APP_PATH="$(printf '%s' "${APP_URL}" | sed -E 's#^https://[^/]+##')"; APP_PATH="${APP_PATH:-/}"

if command -v php >/dev/null 2>&1; then
  APP_KEY="base64:$(php -r 'echo base64_encode(random_bytes(32));')"
else
  APP_KEY="base64:$(openssl rand -base64 32)"
fi

( umask 077
cat > "${ENV_FILE}" <<ENVEOF
# AW Shortlink production environment — generated $(date -u +%FT%TZ). Never commit or share this file.
APP_NAME="AW Shortlink"
APP_ENV=production
APP_KEY=${APP_KEY}
APP_DEBUG=false
APP_URL=${APP_URL}
APP_TIMEZONE=UTC
BRAND_ORG_NAME=${BRAND_ORG_NAME}
BRAND_ORG_SHORT=${BRAND_ORG_SHORT}
SHORTLINK_ALLOWLIST_HOSTS=${SHORTLINK_ALLOWLIST_HOSTS}
TRUSTED_PROXIES=${TRUSTED_PROXIES}

DB_CONNECTION=pgsql
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_DATABASE=${DB_DATABASE}
DB_USERNAME=${DB_USERNAME}
DB_PASSWORD=${DB_PASSWORD}
DB_SCHEMA=shortlink
DB_SSLMODE=prefer
DB_RESOLVER_USERNAME=${DB_RESOLVER_USER}
DB_RESOLVER_PASSWORD=${DB_RESOLVER_PASS}
DB_MIGRATOR_USERNAME=${DB_MIGRATOR_USER}
DB_MIGRATOR_PASSWORD=${DB_MIGRATOR_PASS}

LOG_CHANNEL=daily
LOG_LEVEL=info
SESSION_DRIVER=database
SESSION_LIFETIME=30
SESSION_PATH=${APP_PATH}
SESSION_DOMAIN=${APP_HOST}
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax
MFA_TOTP_REQUIRED=true

# Privacy: per-visitor telemetry is OFF by default (ADR-0003).
ANALYTICS_RAW_EVENTS_ENABLED=false
ENVEOF
)
chmod 600 "${ENV_FILE}"
echo "[OK] ${ENV_FILE} written (mode 600)."

# Connection test. Credentials travel through the environment, never through interpolated PHP source.
if command -v php >/dev/null 2>&1; then
  RESULT="$(DBT_H="${DB_HOST}" DBT_P="${DB_PORT}" DBT_D="${DB_DATABASE}" DBT_U="${DB_USERNAME}" DBT_W="${DB_PASSWORD}" php -r '
    try {
      $pdo = new PDO("pgsql:host=" . getenv("DBT_H") . ";port=" . getenv("DBT_P") . ";dbname=" . getenv("DBT_D"),
                     getenv("DBT_U"), getenv("DBT_W"), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]);
      $r = $pdo->query("SELECT current_database() AS d, current_user AS u")->fetch(PDO::FETCH_ASSOC);
      echo "SUCCESS|" . $r["d"] . "|" . $r["u"];
    } catch (Throwable $e) { echo "FAIL|" . $e->getMessage(); }
  ' 2>/dev/null || echo "FAIL|php failed")"
  if [[ "${RESULT%%|*}" == "SUCCESS" ]]; then echo "[OK] PostgreSQL connection OK (${RESULT#SUCCESS|})."
  else echo "[WARN] PostgreSQL connection failed: ${RESULT#FAIL|}"; fi
else
  echo "[INFO] php CLI not on PATH; connection test skipped."
fi
