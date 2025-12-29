#!/usr/bin/env bash
set -euo pipefail
MYSQL_HOST=${MYSQL_HOST:-${HOST:-mysql}}
MYSQL_PORT=${MYSQL_PORT:-${PORT:-3306}}
MYSQL_USER=${MYSQL_USER:-${USER:-root}}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-${PASSWORD:-example}}

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

mysql -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" < /workload/workload.sql
