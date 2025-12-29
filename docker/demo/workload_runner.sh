#!/usr/bin/env bash
set -euo pipefail
MYSQL_HOST=${MYSQL_HOST:-${HOST:-mysql}}
MYSQL_PORT=${MYSQL_PORT:-${PORT:-3306}}
MYSQL_USER=${MYSQL_USER:-${USER:-root}}
MYSQL_PASSWORD=${MYSQL_PASSWORD:-${PASSWORD:-example}}

for i in {1..30}; do
  if mysqladmin ping -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" --silent; then
    break
  fi
  echo "waiting for mysql at ${MYSQL_HOST}:${MYSQL_PORT}..." >&2
  sleep 2
done

mysql -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" < /workload/workload.sql
