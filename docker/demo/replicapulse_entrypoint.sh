#!/usr/bin/env bash
set -euo pipefail

MYSQL_HOST=${MYSQL_HOST:-${HOST:-mysql}}
MYSQL_PORT=${MYSQL_PORT:-${PORT:-3306}}
MYSQL_USER=${MYSQL_USER:-${USER:-root}}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-${PASSWORD:-example}}
SERVER_ID=${SERVER_ID:-7777}
START_BINLOG=${START_BINLOG:-mysql-bin.000001}
START_POS=${START_POS:-4}
OUTPUT_PATH=${OUTPUT_PATH:-/var/lib/replicapulse/output.sql}
CHECKPOINT_FILE=${CHECKPOINT_FILE:-/var/lib/replicapulse/checkpoint}
EXTRA_ARGS=${EXTRA_ARGS:-}

mkdir -p "$(dirname "${OUTPUT_PATH}")"
mkdir -p "$(dirname "${CHECKPOINT_FILE}")"
>"${OUTPUT_PATH}"
>"${CHECKPOINT_FILE}"

for i in {1..30}; do
  if mysql -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  echo "waiting for mysql at ${MYSQL_HOST}:${MYSQL_PORT}..." >&2
  sleep 2
  if [[ "$i" == "30" ]]; then
    echo "mysql not reachable" >&2
    exit 1
  fi
done

exec /usr/local/bin/replicapulse --host "${MYSQL_HOST}" --port "${MYSQL_PORT}" --user "${MYSQL_USER}" --password "${MYSQL_PASSWORD}" \
  --server-id "${SERVER_ID}" --start-binlog "${START_BINLOG}" --start-pos "${START_POS}" \
  --checkpoint-file "${CHECKPOINT_FILE}" --output "${OUTPUT_PATH}" ${EXTRA_ARGS}
