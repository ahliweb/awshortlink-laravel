#!/usr/bin/env bash
# ==============================================================================
# Builds a ZIP for panel/SFTP deployment into a sub-path of an existing site (default prefix /buka).
# Includes production vendor/ (the server never runs composer), a clean production-mode SQL import,
# a deny-by-default .htaccess, and configure-env.sh. Run on a trusted build machine.
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/test-env.sh
source "${ROOT_DIR}/scripts/lib/test-env.sh"
BASE_PATH="${BASE_PATH:-/buka}"
BUILD_DIR="${ROOT_DIR}/build"
STAGING_DIR="${BUILD_DIR}/staging"
ZIP_FILE="${BUILD_DIR}/awshortlink_release.zip"

echo "==> 1. Generating clean production-mode PostgreSQL import..."
"${ROOT_DIR}/scripts/generate-shared-hosting-sql.sh"

echo "==> 2. Staging runtime files..."
rm -rf "${STAGING_DIR}" "${ZIP_FILE}"
mkdir -p "${STAGING_DIR}"
for d in app bootstrap config database; do cp -R "${ROOT_DIR}/${d}" "${STAGING_DIR}/${d}"; done
cp "${ROOT_DIR}/artisan" "${ROOT_DIR}/composer.json" "${ROOT_DIR}/composer.lock" "${ROOT_DIR}/.env.example" "${ROOT_DIR}/VERSION" "${STAGING_DIR}/"
docker run --rm -v "${STAGING_DIR}:/app" -w /app -u "$(id -u):$(id -g)" "${PHP_IMAGE}" \
  composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader >/dev/null
cp "${ROOT_DIR}/public/index.php" "${STAGING_DIR}/index.php"
mkdir -p "${STAGING_DIR}/public"; cp -R "${ROOT_DIR}/public/." "${STAGING_DIR}/public/"
cp "${ROOT_DIR}/scripts/configure-env.sh" "${STAGING_DIR}/configure-env.sh"; chmod +x "${STAGING_DIR}/configure-env.sh"
cp "${BUILD_DIR}/database_import.sql" "${STAGING_DIR}/database_import.sql"
mkdir -p "${STAGING_DIR}/storage/logs" "${STAGING_DIR}/storage/framework/cache" "${STAGING_DIR}/storage/framework/throttle"

echo "==> 3. Writing deny-by-default .htaccess guards..."
cat > "${STAGING_DIR}/.htaccess" <<HTACCESS
# AW Shortlink — Apache / LiteSpeed rules for the ${BASE_PATH}/ namespace
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase ${BASE_PATH}/

    # Deny direct HTTP access to configuration, secrets, source and tooling.
    RewriteRule ^(\.env|artisan|composer\.(json|lock)|VERSION|.*\.sql|.*\.sh|.*\.md)\$ - [F,L,NC]
    RewriteRule ^(app|bootstrap|config|database|vendor|storage)/.* - [F,L,NC]

    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/\$
    RewriteRule ^ %1 [L,R=301]

    # Everything else goes to the front controller (static assets are served by it, from public/assets only).
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>

<FilesMatch "^(\.env|\.git|composer\.|artisan|VERSION|.*\.sql|.*\.sh|.*\.md|.*\.log|.*\.json)">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

Options -Indexes
HTACCESS

GUARD='<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
</IfModule>'
for d in app bootstrap config database vendor storage; do printf '%s\n' "${GUARD}" > "${STAGING_DIR}/${d}/.htaccess"; done

echo "==> 4. Creating ${ZIP_FILE}..."
( cd "${STAGING_DIR}" && zip -r -q -X "${ZIP_FILE}" . )
echo "SHA-256: $(sha256sum "${ZIP_FILE}" | cut -d' ' -f1)"
echo "Size   : $(du -h "${ZIP_FILE}" | cut -f1)"
echo "Deploy : extract into the document sub-path for ${BASE_PATH}/ , run ./configure-env.sh, import database_import.sql,"
echo "         then delete database_import.sql and configure-env.sh from the server."
rm -rf "${STAGING_DIR}"
