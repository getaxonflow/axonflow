#!/bin/bash
# PostgreSQL initialization script for local development
# Only creates the dblink extension - migrations will create Grafana database
# The main 'axonflow' database is created automatically by POSTGRES_DB env var

set -e

echo "=== Initializing PostgreSQL for local development ==="

# Install required extensions for migrations
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Install dblink extension (required for migration 017)
    CREATE EXTENSION IF NOT EXISTS dblink;

    -- Note: Grafana database and user will be created by migration 017
    -- This ensures local dev tests the SAME code path as AWS deployment
EOSQL

echo "✅ Installed required PostgreSQL extensions"
echo "✅ PostgreSQL initialization complete"
echo ""
echo "Note: Grafana database and user will be created by Agent migration 017"
