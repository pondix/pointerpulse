#!/usr/bin/env bash
set -euo pipefail
HOST=${HOST:-mysql}
PORT=${PORT:-3306}
USER=${USER:-root}
PASSWORD=${PASSWORD:-example}

for i in {1..30}; do
  if mysqladmin ping -h"${HOST}" -P"${PORT}" -u"${USER}" -p"${PASSWORD}" --silent; then
    break
  fi
  echo "waiting for mysql at ${HOST}:${PORT}..." >&2
  sleep 2
done

mysql -h"${HOST}" -P"${PORT}" -u"${USER}" -p"${PASSWORD}" < /workload/workload.sql
