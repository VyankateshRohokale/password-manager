#!/usr/bin/env bash
# Creates the VAULT role and databases on a locally installed PostgreSQL (e.g. Homebrew),
# and writes a .env file with a freshly generated password. Safe to re-run: it refuses
# to overwrite an existing .env.
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ -f .env ]]; then
  echo ".env already exists; not overwriting. Delete it first to regenerate." >&2
  exit 1
fi

PSQL="${PSQL:-psql}"
ADMIN_DB="${ADMIN_DB:-postgres}"
ROLE="${DB_USERNAME:-vault_app}"
PASSWORD="$(openssl rand -base64 24 | tr -d '/+=')"

"$PSQL" -d "$ADMIN_DB" -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE ${ROLE} LOGIN PASSWORD '${PASSWORD}'" \
  -c "CREATE DATABASE vault OWNER ${ROLE}" \
  -c "CREATE DATABASE vault_test OWNER ${ROLE}"

cat > .env <<ENV
DB_URL=jdbc:postgresql://localhost:5432/vault
DB_USERNAME=${ROLE}
DB_PASSWORD=${PASSWORD}
TEST_DB_URL=jdbc:postgresql://localhost:5432/vault_test
VAULT_PRELOGIN_SECRET=$(openssl rand -base64 32)
PORT=8787
COOKIE_SECURE=false
ENV
chmod 600 .env
echo "Created role ${ROLE}, databases vault and vault_test, and .env"
