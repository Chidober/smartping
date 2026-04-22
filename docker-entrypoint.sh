#!/bin/sh
set -e
if [ ! -f /app/db/database-base.db ]; then
  mkdir -p /app/db
  cp -a /seed/db/. /app/db/
fi
exec /app/bin/smartping "$@"
