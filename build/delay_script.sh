#!/bin/bash
set -e

echo "Starting delay_script.sh..."

# Set the password for PostgreSQL
export PGPASSWORD="Ebosdev1"

# Wait for PostgreSQL to start
until pg_isready -U "$POSTGRES_USER"; do
  echo "Waiting for PostgreSQL to start..."
  sleep 2
done


echo "PostgreSQL is ready. Restoring database..."
# Restore the database from the dump file
#pg_restore -U "postgres" -d "EO4EU-Main-DB" /docker-entrypoint-initdb.d/backuptest.dump
pg_restore -U "postgres" -d "EO4EU-Main-DB" /docker-entrypoint-initdb.d/test.dump