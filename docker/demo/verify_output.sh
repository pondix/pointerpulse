#!/usr/bin/env bash
set -euo pipefail
OUTPUT_PATH=${OUTPUT_PATH:-docker/demo/output/output.sql}

if [[ ! -f "${OUTPUT_PATH}" ]]; then
  echo "missing output file: ${OUTPUT_PATH}" >&2
  exit 1
fi
if [[ ! -s "${OUTPUT_PATH}" ]]; then
  echo "output file is empty: ${OUTPUT_PATH}" >&2
  exit 1
fi

required=(
  "CREATE DATABASE"
  "INSERT INTO demo_db.widgets"
  "UPDATE demo_db.widgets"
  "INSERT INTO demo_db.parts"
  "DELETE FROM demo_db.parts"
  "TRUNCATE TABLE demo_db.parts"
  "ALTER TABLE"
  "DROP INDEX"
)

for pattern in "${required[@]}"; do
  if ! grep -q "${pattern}" "${OUTPUT_PATH}"; then
    echo "missing expected statement containing: ${pattern}" >&2
    exit 1
  fi
done

echo "ReplicaPulse output validated at ${OUTPUT_PATH}" >&2
