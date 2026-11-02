#!/usr/bin/env bash
# Builds an immutable release artifact (runtime files + production vendor/), a CycloneDX SBOM generated from
# composer.lock, and SHA256SUMS. Run on a trusted build machine; production never runs composer.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"
BUILD_DIR="${ROOT_DIR}/build"
STAGE_DIR="${BUILD_DIR}/stage"
ARTIFACT_TAR="${BUILD_DIR}/awshortlink-release.tar.gz"
SBOM_FILE="${BUILD_DIR}/sbom.cdx.json"
SUMS_FILE="${BUILD_DIR}/SHA256SUMS"
VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"

mkdir -p "${BUILD_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

# Runtime files only: no .env, no .git, no tests, no docs, no compose/test tooling.
for d in app bootstrap config database public; do cp -R "${ROOT_DIR}/${d}" "${STAGE_DIR}/${d}"; done
cp "${ROOT_DIR}/artisan" "${ROOT_DIR}/composer.json" "${ROOT_DIR}/composer.lock" "${ROOT_DIR}/.env.example" "${ROOT_DIR}/VERSION" "${STAGE_DIR}/"

# Production dependencies exactly as locked (no dev packages, optimised autoloader).
docker run --rm -v "${STAGE_DIR}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" \
  composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader >/dev/null

for forbidden in ".env" ".git" "tests" "compose.test.yml" "build" "docs"; do
  if [[ -e "${STAGE_DIR}/${forbidden}" ]]; then
    echo "ERROR: forbidden path ${forbidden} found in release stage!" >&2
    exit 1
  fi
done
[[ -f "${STAGE_DIR}/vendor/autoload.php" ]] || { echo "ERROR: vendor/autoload.php missing from stage" >&2; exit 1; }

# Deterministic bundle (fixed mtime, ownership and ordering).
tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner -czf "${ARTIFACT_TAR}" -C "${STAGE_DIR}" .

docker run --rm -v "${ROOT_DIR}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" \
  php scripts/generate-sbom.php composer.lock "build/$(basename "${SBOM_FILE}")" "${VERSION}"

(cd "${BUILD_DIR}" && sha256sum "$(basename "${ARTIFACT_TAR}")" "$(basename "${SBOM_FILE}")" > "${SUMS_FILE}")
rm -rf "${STAGE_DIR}"

echo "[OK] Built immutable artifact: ${ARTIFACT_TAR}"
echo "[OK] Generated CycloneDX SBOM: ${SBOM_FILE}"
echo "[OK] Generated SHA256SUMS: ${SUMS_FILE}"
