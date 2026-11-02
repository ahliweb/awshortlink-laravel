#!/usr/bin/env bash
# Runs the PHP smoke & security suites against the PostgreSQL test database (see scripts/ci.sh to start it).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"

for test_file in tests/0*_*.php; do
  php_run "${test_file}"
done

echo "==> [ALL PHP SMOKE & SECURITY TESTS PASSED]"
