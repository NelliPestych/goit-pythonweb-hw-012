#!/bin/bash
# wait_for_db.sh

set -e

host="$1"
port="$2"
shift 2
cmd="$@"

echo "Waiting for PostgreSQL at $host:$port..."

export PGPASSWORD="$POSTGRES_PASSWORD"
export PGUSER="$POSTGRES_USER"
export PGDATABASE="$POSTGRES_DB"

>&2 echo "DEBUG: PGPASSWORD is set (value hidden)"
>&2 echo "DEBUG: PGUSER is $PGUSER"
>&2 echo "DEBUG: PGDATABASE is $PGDATABASE"
>&2 echo "DEBUG: Attempting psql -h $host -U $PGUSER -d $PGDATABASE -c '\q'"

until psql -h "$host" -U "$PGUSER" -d "$PGDATABASE" -c '\q'; do
  >&2 echo "PostgreSQL is unavailable - sleeping"
  sleep 1
done

>&2 echo "PostgreSQL is up - executing command: $cmd"
exec $cmd