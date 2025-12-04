#!/bin/bash
# Setup script for usage recording integration tests
#
# This script sets up a test environment for integration tests:
# 1. Creates test PostgreSQL database (or uses existing)
# 2. Applies migrations
# 3. Creates test organization with license key
# 4. Sets environment variables for tests

set -e

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Usage Recording Integration Test Setup${NC}"
echo -e "${BLUE}=========================================${NC}"

# Configuration
TEST_DB_HOST="${TEST_DB_HOST:-localhost}"
TEST_DB_PORT="${TEST_DB_PORT:-5432}"
TEST_DB_USER="${TEST_DB_USER:-postgres}"
TEST_DB_PASSWORD="${TEST_DB_PASSWORD:-postgres}"
TEST_DB_NAME="${TEST_DB_NAME:-axonflow_test}"
TEST_ORG_ID="test-integration-usage"
TEST_LICENSE_KEY="${TEST_LICENSE_KEY:-}"

# Construct database URL
export TEST_DATABASE_URL="postgresql://${TEST_DB_USER}:${TEST_DB_PASSWORD}@${TEST_DB_HOST}:${TEST_DB_PORT}/${TEST_DB_NAME}?sslmode=disable"

echo -e "${BLUE}Configuration:${NC}"
echo -e "  Database Host: ${TEST_DB_HOST}"
echo -e "  Database Port: ${TEST_DB_PORT}"
echo -e "  Database Name: ${TEST_DB_NAME}"
echo -e "  Test Org ID: ${TEST_ORG_ID}"
echo ""

# Step 1: Check if PostgreSQL is accessible
echo -e "${BLUE}[1/5] Checking PostgreSQL connection...${NC}"
if pg_isready -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PostgreSQL is accessible${NC}"
else
    echo -e "${YELLOW}⚠️  PostgreSQL not accessible, attempting to start Docker container...${NC}"

    # Try to start a PostgreSQL container
    docker run -d --name axonflow-test-db \
        -e POSTGRES_USER="$TEST_DB_USER" \
        -e POSTGRES_PASSWORD="$TEST_DB_PASSWORD" \
        -e POSTGRES_DB="$TEST_DB_NAME" \
        -p "${TEST_DB_PORT}:5432" \
        postgres:15 || true

    # Wait for PostgreSQL to be ready
    echo -e "${BLUE}Waiting for PostgreSQL to be ready...${NC}"
    for i in {1..30}; do
        if pg_isready -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
            break
        fi
        sleep 1
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ Failed to start PostgreSQL${NC}"
            exit 1
        fi
    done
fi

# Step 2: Apply migrations
echo -e "${BLUE}[2/5] Applying database migrations...${NC}"
MIGRATIONS_DIR="$(cd ../.. && pwd)/migrations"
if [ ! -d "$MIGRATIONS_DIR" ]; then
    echo -e "${RED}❌ Migrations directory not found: $MIGRATIONS_DIR${NC}"
    exit 1
fi

for migration in "$MIGRATIONS_DIR"/*.sql; do
    if [ -f "$migration" ]; then
        echo -e "  Applying $(basename "$migration")..."
        PGPASSWORD="$TEST_DB_PASSWORD" psql -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" -d "$TEST_DB_NAME" -f "$migration" 2>&1 | grep -v "already exists" | grep -v "ERROR" || true
    fi
done
echo -e "${GREEN}✅ Migrations applied${NC}"

# Step 3: Generate test license key if not provided
if [ -z "$TEST_LICENSE_KEY" ]; then
    echo -e "${BLUE}[3/5] Generating test license key...${NC}"

    # Generate a test license key (simplified version)
    # In production, this would use the actual license generation tool
    TIER="ENT"
    EXPIRY=$(date -u -v+1y +%Y%m%d 2>/dev/null || date -u -d "+1 year" +%Y%m%d)
    SIGNATURE=$(echo -n "AXON-${TIER}-${TEST_ORG_ID}-${EXPIRY}" | openssl dgst -sha256 -hmac "test-secret-key-for-integration-tests" | cut -d' ' -f2 | cut -c1-8)
    TEST_LICENSE_KEY="AXON-${TIER}-${TEST_ORG_ID}-${EXPIRY}-${SIGNATURE}"

    echo -e "${GREEN}✅ Generated test license key: ${TEST_LICENSE_KEY}${NC}"
else
    echo -e "${BLUE}[3/5] Using provided license key${NC}"
fi

export TEST_LICENSE_KEY

# Step 4: Create test organization
echo -e "${BLUE}[4/5] Creating test organization...${NC}"
PGPASSWORD="$TEST_DB_PASSWORD" psql -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" -d "$TEST_DB_NAME" <<EOF
INSERT INTO organizations (org_id, name, tier, license_key, status, max_nodes, expires_at, created_at, updated_at)
VALUES (
    '${TEST_ORG_ID}',
    'Integration Test Organization',
    'ENT',
    '${TEST_LICENSE_KEY}',
    'ACTIVE',
    100,
    NOW() + INTERVAL '365 days',
    NOW(),
    NOW()
)
ON CONFLICT (org_id) DO UPDATE
SET license_key = EXCLUDED.license_key,
    status = 'ACTIVE',
    expires_at = EXCLUDED.expires_at,
    updated_at = NOW();
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Test organization created/updated${NC}"
else
    echo -e "${RED}❌ Failed to create test organization${NC}"
    exit 1
fi

# Step 5: Set environment variables
echo -e "${BLUE}[5/5] Setting environment variables...${NC}"

# Export for current session
export TEST_DATABASE_URL
export TEST_LICENSE_KEY
export TEST_AGENT_URL="${TEST_AGENT_URL:-http://localhost:8080}"

# Save to .env.test file for convenience
cat > .env.test <<EOF
# Integration Test Environment Variables
TEST_DATABASE_URL=${TEST_DATABASE_URL}
TEST_LICENSE_KEY=${TEST_LICENSE_KEY}
TEST_AGENT_URL=${TEST_AGENT_URL}
TEST_ORG_ID=${TEST_ORG_ID}
EOF

echo -e "${GREEN}✅ Environment variables set and saved to .env.test${NC}"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Test Environment Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${BLUE}To run integration tests:${NC}"
echo -e "  1. Source environment variables:"
echo -e "     ${YELLOW}source test/integration/.env.test${NC}"
echo -e ""
echo -e "  2. Ensure agent is running at ${TEST_AGENT_URL}"
echo -e ""
echo -e "  3. Run tests:"
echo -e "     ${YELLOW}cd test/integration && go test -v${NC}"
echo -e ""
echo -e "${BLUE}To clean up test database:${NC}"
echo -e "  ${YELLOW}./cleanup_test_env.sh${NC}"
echo ""
