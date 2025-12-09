#!/bin/bash

# AxonFlow Policy Database Initialization Script
# Run this to initialize policy tables in any environment

set -e

# Configuration
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLICY_SCHEMA_FILE="$SCRIPT_DIR/policy_schema.sql"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "=== AxonFlow Policy Database Initialization ==="
echo ""

# Check if DATABASE_URL is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <DATABASE_URL>"
    echo "Example: $0 'postgresql://user:pass@host:5432/dbname?sslmode=require'"
    exit 1
fi

DATABASE_URL="$1"

# Check if schema file exists
if [ ! -f "$POLICY_SCHEMA_FILE" ]; then
    echo -e "${RED}Error: Policy schema file not found: $POLICY_SCHEMA_FILE${NC}"
    exit 1
fi

echo "Applying policy schema to database..."
echo "Database: $DATABASE_URL"
echo ""

# Apply the schema
if psql "$DATABASE_URL" < "$POLICY_SCHEMA_FILE" 2>&1 | grep -E "ERROR"; then
    echo -e "${RED}Failed to apply policy schema${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Policy schema applied successfully${NC}"
echo ""

# Verify tables were created
echo "Verifying policy tables:"
psql "$DATABASE_URL" -c "\dt *policies*" 2>/dev/null || true

echo ""
echo "Policy counts:"
psql "$DATABASE_URL" -c "
    SELECT
        'static_policies' as table_name,
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE tenant_id = 'global') as global,
        COUNT(*) FILTER (WHERE tenant_id = 'healthcare') as healthcare,
        COUNT(*) FILTER (WHERE tenant_id = 'ecommerce') as ecommerce
    FROM static_policies
    UNION ALL
    SELECT
        'dynamic_policies',
        COUNT(*),
        COUNT(*) FILTER (WHERE tenant_id = 'global'),
        COUNT(*) FILTER (WHERE tenant_id = 'healthcare'),
        COUNT(*) FILTER (WHERE tenant_id = 'ecommerce')
    FROM dynamic_policies;
" 2>/dev/null || true

echo ""
echo -e "${GREEN}=== Policy Database Initialization Complete ===${NC}"
echo ""
echo "Next steps:"
echo "1. Update Agent to load static policies from database"
echo "2. Update Orchestrator to load dynamic policies from database"
echo "3. Run load tests to verify performance"
echo ""