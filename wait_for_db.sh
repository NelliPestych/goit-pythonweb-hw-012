#!/bin/sh

set -e

host="$1"
port="$2"
# Shift off the first two arguments (host and port)
shift 2
# The rest of the arguments are the command to execute
command_to_execute="$@"

echo "Waiting for PostgreSQL at $host:$port..."

# Export PostgreSQL connection variables for psql
export PGPASSWORD="$POSTGRES_PASSWORD"
export PGUSER="$POSTGRES_USER"
export PGDATABASE="$POSTGRES_DB"

# Loop until PostgreSQL is ready
until psql -h "$host" -U "$PGUSER" -d "$PGDATABASE" -c '\q'; do
  >&2 echo "PostgreSQL is unavailable - sleeping"
  sleep 1
done

>&2 echo "PostgreSQL is up - executing command: $command_to_execute"

# Use 'exec' to replace the current shell process with the command_to_execute.
# This is crucial. By directly calling the variable, if it contains spaces,
# 'sh' will treat the entire string as the command name, leading to "not found".
# We explicitly pass it to 'sh -c' to ensure it's parsed as a shell command.
exec sh -c "$command_to_execute"
