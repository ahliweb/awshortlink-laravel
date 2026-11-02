#!/usr/bin/env bash
# ==============================================================================
# Activate / reset the protected platform-owner account (password + fresh TOTP secret) on a remote host.
# Run from a TRUSTED LOCAL machine. The password is typed locally and sent over SSH stdin.
#
#   SSH_HOST=alias REMOTE_DIR=path ./scripts/setup-admin-account.sh <email> [--reset]
# ==============================================================================
set -euo pipefail

: "${SSH_HOST:?set SSH_HOST}"; : "${REMOTE_DIR:?set REMOTE_DIR}"
EMAIL="${1:?usage: setup-admin-account.sh <email> [--reset]}"
RESET_FLAG=""; [[ "${2:-}" == "--reset" ]] && RESET_FLAG="--reset"

# The address is interpolated into a remote command line, so allow only a conservative character set.
[[ "${EMAIL}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "Invalid e-mail address." >&2; exit 1; }
[[ "${REMOTE_DIR}" =~ ^[A-Za-z0-9._~/-]+$ ]] || { echo "REMOTE_DIR contains unsupported characters" >&2; exit 1; }

while true; do
  read -rsp "New password (min 12 chars): " PASS1; echo
  [[ ${#PASS1} -ge 12 ]] || { echo "  [!] Too short."; continue; }
  read -rsp "Repeat password: " PASS2; echo
  [[ "${PASS1}" == "${PASS2}" ]] || { echo "  [!] Passwords differ."; continue; }
  break
done

RESULT="$(printf '%s\n' "${PASS1}" | ssh -o ConnectTimeout=15 "${SSH_HOST}" "cd '${REMOTE_DIR}' && php artisan admin:bootstrap '${EMAIL}' --stdin ${RESET_FLAG}")"
unset PASS1 PASS2
echo "${RESULT}"
echo "Add the shown secret to an authenticator app (TOTP, SHA1, 6 digits, 30 s), then sign in at <your-url>/admin/login."
echo "The secret is shown only once; store it securely."
