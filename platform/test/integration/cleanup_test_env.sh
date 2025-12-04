#!/bin/bash
# Cleanup script for usage recording integration tests

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Integration Test Cleanup${NC}"
echo -e "${BLUE}=========================================${NC}"

# Load configuration from .env.test if it exists
if [ -f ".env.test" ]; then
    source .env.test
    echo -e "${BLUE}Loaded configuration from .env.test${NC}"
fi

# Configuration
TEST_DB_HOST="${TEST_DB_HOST:-localhost}"
TEST_DB_PORT="${TEST_DB_PORT:-5432}"
TEST_DB_USER="${TEST_DB_USER:-postgres}"
TEST_DB_PASSWORD="${TEST_DB_PASSWORD:-postgres}"
TEST_DB_NAME="${TEST_DB_NAME:-axonflow_test}"
TEST_ORG_ID="${TEST_ORG_ID:-test-integration-usage}"

# Step 1: Delete test usage events
echo -e "${BLUE}[1/3] Deleting test usage events...${NC}"
PGPASSWORD="$TEST_DB_PASSWORD" psql -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" -d "$TEST_DB_NAME" <<EOF
DELETE FROM usage_events WHERE org_id = '${TEST_ORG_ID}';
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Test usage events deleted${NC}"
else
    echo -e "${YELLOW}⚠️  Failed to delete test usage events (may not exist)${NC}"
fi

# Step 2: Delete test organization
echo -e "${BLUE}[2/3] Deleting test organization...${NC}"
PGPASSWORD="$TEST_DB_PASSWORD" psql -h "$TEST_DB_HOST" -p "$TEST_DB_PORT" -U "$TEST_DB_USER" -d "$TEST_DB_NAME" <<EOF
DELETE FROM organizations WHERE org_id = '${TEST_ORG_ID}';
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Test organization deleted${NC}"
else
    echo -e "${YELLOW}⚠️  Failed to delete test organization (may not exist)${NC}"
fi

# Step 3: Stop test database container (if it was started by setup script)
echo -e "${BLUE}[3/3] Checking for test database container...${NC}"
if docker ps -a | grep -q "axonflow-test-db"; then
    echo -e "${BLUE}Stopping and removing test database container...${NC}"
    docker stop axonflow-test-db > /dev/null 2>&1
    docker rm axonflow-test-db > /dev/null 2>&1
    echo -e "${GREEN}✅ Test database container removed${NC}"
else
    echo -e "${BLUE}ℹ️  No test database container found (using existing PostgreSQL)${NC}"
fi

# Step 4: Remove .env.test file
if [ -f ".env.test" ]; then
    rm .env.test
    echo -e "${GREEN}✅ Removed .env.test file${NC}"
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Cleanup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
