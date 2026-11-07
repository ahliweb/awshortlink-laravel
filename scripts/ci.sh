#!/usr/bin/env bash
# Full local/CI gate: PostgreSQL test DB + roles, lint, contract check, smoke & security suites, artifact+SBOM,
# backup/restore rehearsal and post-deploy synthetic verification.
#
# Prerequisites on the build machine: docker (with compose), node >= 20, python3 + PyYAML, openssl.
# The PHP toolchain runs in a container: `docker build -t awshortlink-php:local docker/php` (or set PHP_IMAGE).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"

echo "==> [CI 1/7] Installing locked Composer dependencies..."
if [[ ! -f vendor/autoload.php ]]; then
  docker run --rm -v "${ROOT_DIR}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" \
    composer install --no-interaction --no-progress --prefer-dist
fi

echo "==> [CI 2/7] Starting PostgreSQL 18.6 test service & applying role separation..."
docker compose -f compose.test.yml up -d --wait
apply_roles "${TEST_DB_NAME}"

echo "==> [CI 3/7] PHP syntax lint on app/, config/, bootstrap/, public/, tests/..."
docker run --rm -v "${ROOT_DIR}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" bash -c '
  find app bootstrap config public tests scripts -name "*.php" -print0 | xargs -0 -n1 php -l >/dev/null
  php -l artisan >/dev/null
'
echo "    [OK] PHP syntax lint clean."

echo "==> [CI 4/7] OpenAPI 3.1.0 + AsyncAPI 3.0.0 contract & mock-server verification..."
node design/mock-server/verify-contract.mjs

echo "==> [CI 5/7] PostgreSQL RLS, RBAC/ABAC, resolver, audit, QR, CSV, SSRF, HTTP & security-hardening suites..."
bash scripts/smoke.sh

echo "==> [CI 6/7] Immutable release artifact (real SBOM + SHA256SUMS) & backup/restore rehearsal..."
bash scripts/build-artifact.sh
bash scripts/rehearse-backup-restore.sh

echo "==> [CI 7/7] Post-deployment synthetic verification..."
bash scripts/post-deploy-verify.sh

echo "==> [CI COMPLETE: ALL GATES & SUITES GREEN]"
