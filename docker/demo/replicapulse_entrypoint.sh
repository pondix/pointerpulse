#!/usr/bin/env bash
set -euo pipefail

HOST=${HOST:-${MYSQL_HOST:-mysql}}
PORT=${PORT:-${MYSQL_PORT:-3306}}
USER=${USER:-root}
PASSWORD=${PASSWORD:-example}
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
  if mysqladmin ping -h"${HOST}" -P"${PORT}" -u"${USER}" -p"${PASSWORD}" --silent; then
    break
  fi
  echo "waiting for mysql at ${HOST}:${PORT}..." >&2
  sleep 2
  if [[ "$i" == "30" ]]; then
    echo "mysql not reachable" >&2
    exit 1
  fi
done

exec /usr/local/bin/replicapulse --host "${HOST}" --port "${PORT}" --user "${USER}" --password "${PASSWORD}" \
  --server-id "${SERVER_ID}" --start-binlog "${START_BINLOG}" --start-pos "${START_POS}" \
  --checkpoint-file "${CHECKPOINT_FILE}" --output "${OUTPUT_PATH}" ${EXTRA_ARGS}
