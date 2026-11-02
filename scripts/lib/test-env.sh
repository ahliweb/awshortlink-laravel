#!/usr/bin/env bash
# Sourced by scripts/ci.sh, scripts/smoke.sh and the build helpers.
#
# Produces THROW-AWAY credentials for the local/CI test database and the demo accounts the test-suite logs in
# with. They are generated randomly once per workspace and stored in build/.test-env (mode 600, git-ignored),
# so nothing secret or guessable is ever committed. Never reuse them anywhere real.
set -euo pipefail

_TE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
_TE_FILE="${_TE_ROOT}/build/.test-env"

_te_rand() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-"${1:-32}"; }

if [[ ! -s "${_TE_FILE}" ]]; then
  mkdir -p "${_TE_ROOT}/build"
  ( umask 077
    {
      echo "POSTGRES_PASSWORD=$(_te_rand 32)"
      echo "TEST_APP_PW=$(_te_rand 32)"
      echo "TEST_RESOLVER_PW=$(_te_rand 32)"
      echo "TEST_MIGRATOR_PW=$(_te_rand 32)"
      echo "TEST_BACKUP_PW=$(_te_rand 32)"
      echo "TEST_APP_KEY=base64:$(openssl rand -base64 32)"
      echo "SHORTLINK_DEMO_PASSWORD=Tst-$(_te_rand 28)!"
      echo "SHORTLINK_DEMO_TOTP_SECRET=$(head -c 20 /dev/urandom | base32 | tr -d '=\n')"
    } > "${_TE_FILE}" )
fi
# shellcheck disable=SC1090
set -a; source "${_TE_FILE}"; set +a

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-awshortlink-test}"
export TEST_DB_PORT="${TEST_DB_PORT:-54328}"
export PHP_IMAGE="${PHP_IMAGE:-awshortlink-php:local}"
export TEST_DB_NAME="awshortlink_test"

# Environment handed to the PHP test container (-e flags are built from this list).
TEST_PHP_ENV=(
  "APP_ENV=testing"
  "APP_KEY=${TEST_APP_KEY}"
  "APP_URL=https://links.example.org/buka"
  "BRAND_ORG_NAME=Example Organization"
  "BRAND_ORG_SHORT=Example Org"
  "DB_HOST=127.0.0.1"
  "DB_PORT=${TEST_DB_PORT}"
  "DB_DATABASE=${TEST_DB_NAME}"
  "DB_USERNAME=awshortlink_app"
  "DB_PASSWORD=${TEST_APP_PW}"
  "DB_RESOLVER_USERNAME=awshortlink_resolver"
  "DB_RESOLVER_PASSWORD=${TEST_RESOLVER_PW}"
  "DB_MIGRATOR_USERNAME=awshortlink_migrator"
  "DB_MIGRATOR_PASSWORD=${TEST_MIGRATOR_PW}"
  "SHORTLINK_DEMO_SEED=1"
  "SHORTLINK_DEMO_PASSWORD=${SHORTLINK_DEMO_PASSWORD}"
  "SHORTLINK_DEMO_TOTP_SECRET=${SHORTLINK_DEMO_TOTP_SECRET}"
  "SHORTLINK_ALLOW_DATA_RESET=1"
  "SHORTLINK_ALLOWLIST_HOSTS=example.org,*.example.org"
  "TRUSTED_PROXIES=127.0.0.1"
  "THROTTLE_STORAGE_DIR=/tmp/awshortlink-throttle-test"
)

# php_run <php args...>  -> runs PHP in the test image on the host network with the test environment.
php_run() {
  local args=() e
  for e in "${TEST_PHP_ENV[@]}"; do args+=(-e "$e"); done
  docker run --rm --network host "${args[@]}" \
    -v "${_TE_ROOT}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" php "$@"
}

# db_psql <psql args...> -> psql as the postgres superuser inside the compose test database.
db_psql() {
  docker compose -f "${_TE_ROOT}/compose.test.yml" exec -T -e PGPASSWORD="${POSTGRES_PASSWORD}" postgres-test \
    psql -h 127.0.0.1 -U postgres -v ON_ERROR_STOP=1 "$@"
}

# apply_roles <database> -> (re)creates the least-privilege roles with the throw-away passwords.
apply_roles() {
  db_psql -d "$1" -q \
    -v app_password="${TEST_APP_PW}" -v resolver_password="${TEST_RESOLVER_PW}" \
    -v migrator_password="${TEST_MIGRATOR_PW}" -v backup_password="${TEST_BACKUP_PW}" \
    < "${_TE_ROOT}/database/sql/rls/0001_roles.sql" >/dev/null
}
