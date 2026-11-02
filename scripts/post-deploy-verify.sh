#!/usr/bin/env bash
# Runs the post-deployment synthetic verification against the disposable test database (see the warning in
# post-deploy-verify.php). Never point this at production data.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"
php_run scripts/post-deploy-verify.php
