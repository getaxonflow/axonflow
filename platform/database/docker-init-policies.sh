#!/bin/sh

# Docker container policy initialization script
# Add this to Agent/Orchestrator Dockerfiles to auto-initialize policies on startup

set -e

echo "[Policy Init] Checking if policy tables exist..."

# Wait for database to be ready
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if psql "$DATABASE_URL" -c "SELECT 1" > /dev/null 2>&1; then
        echo "[Policy Init] Database is ready"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "[Policy Init] Waiting for database... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "[Policy Init] WARNING: Database not ready, skipping policy initialization"
    exit 0
fi

# Check if policy tables exist
TABLE_COUNT=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN ('static_policies', 'dynamic_policies')
" 2>/dev/null | tr -d ' ')

if [ "$TABLE_COUNT" = "2" ]; then
    echo "[Policy Init] Policy tables already exist"

    # Check if policies are loaded
    POLICY_COUNT=$(psql "$DATABASE_URL" -t -c "
        SELECT COUNT(*) FROM static_policies
    " 2>/dev/null | tr -d ' ')

    if [ "$POLICY_COUNT" -gt "0" ]; then
        echo "[Policy Init] Found $POLICY_COUNT static policies"
    else
        echo "[Policy Init] WARNING: No policies found in database"
        echo "[Policy Init] Run platform/database/init-policies.sh to load default policies"
    fi
else
    echo "[Policy Init] Policy tables do not exist"
    echo "[Policy Init] Creating policy tables and loading default policies..."

    # Check if schema file is embedded in container
    if [ -f "/app/policy_schema.sql" ]; then
        psql "$DATABASE_URL" < /app/policy_schema.sql
        echo "[Policy Init] Policy tables created and default policies loaded"
    else
        echo "[Policy Init] WARNING: policy_schema.sql not found in container"
        echo "[Policy Init] Manual initialization required"
    fi
fi

echo "[Policy Init] Policy initialization complete"