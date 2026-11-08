#!/usr/bin/env bash
# =====================================================================
# Creates and seeds BOTH databases from the SQL files in db/.
#   MySQL      : db/mysql/01..07   (schema, functions, views, procedures,
#                                    triggers + event, roles, seed data)
#   PostgreSQL : db/pg/01..03      (pgvector schema, search functions, roles)
# Credentials come from .env.local (see .env.example). Nothing is hard-coded.
# Usage:  npm run db:init            then   npm run db:seed-vectors
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE="${ENV_FILE:-.env.local}"
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE - copy .env.example to .env.local and fill it in." >&2
  exit 1
fi
set -a; . "./$ENV_FILE"; set +a

: "${MYSQL_SETUP_USER:?set MYSQL_SETUP_USER in $ENV_FILE}"
: "${PG_SETUP_USER:?set PG_SETUP_USER in $ENV_FILE}"
MYSQL_SETUP_HOST="${MYSQL_SETUP_HOST:-${MYSQL_HOST:-localhost}}"
MYSQL_SETUP_PORT="${MYSQL_SETUP_PORT:-${MYSQL_PORT:-3306}}"
PG_SETUP_HOST="${PG_SETUP_HOST:-${PG_HOST:-localhost}}"
PG_SETUP_PORT="${PG_SETUP_PORT:-${PG_PORT:-5432}}"
PG_DATABASE="${PG_DATABASE:-zerodayhub_vectors}"
export PG_DATABASE

mysql_run() {
  MYSQL_PWD="${MYSQL_SETUP_PASSWORD:-}" mysql -h "$MYSQL_SETUP_HOST" -P "$MYSQL_SETUP_PORT" \
    -u "$MYSQL_SETUP_USER" --default-character-set=utf8mb4 "$@"
}
pg_run() {
  PGPASSWORD="${PG_SETUP_PASSWORD:-}" psql -v ON_ERROR_STOP=1 -q -h "$PG_SETUP_HOST" \
    -p "$PG_SETUP_PORT" -U "$PG_SETUP_USER" "$@"
}

echo "== MySQL =========================================================="
for f in 01_schema 02_functions 03_views 04_procedures 05_triggers_events; do
  echo "  applying db/mysql/$f.sql"
  mysql_run < "db/mysql/$f.sql"
done
echo "  applying db/mysql/06_roles.sql.tpl (rendered from $ENV_FILE)"
node scripts/render-template.mjs db/mysql/06_roles.sql.tpl | mysql_run
echo "  applying db/mysql/07_seed.sql"
mysql_run < db/mysql/07_seed.sql

echo "== PostgreSQL + pgvector =========================================="
if ! pg_run -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DATABASE}'" | grep -q 1; then
  echo "  creating database ${PG_DATABASE}"
  pg_run -d postgres -c "CREATE DATABASE ${PG_DATABASE}"
fi
for f in 01_schema 02_functions_views; do
  echo "  applying db/pg/$f.sql"
  pg_run -d "$PG_DATABASE" -f "db/pg/$f.sql"
done
echo "  applying db/pg/03_roles.sql.tpl (rendered from $ENV_FILE)"
node scripts/render-template.mjs db/pg/03_roles.sql.tpl | pg_run -d "$PG_DATABASE"

echo
echo "Done. Next:  npm run db:seed-vectors   (embeds advisories into PostgreSQL)"
