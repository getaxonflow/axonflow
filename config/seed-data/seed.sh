#!/bin/bash
#
# AxonFlow Demo Data Seeder
# Seeds PostgreSQL with demo data for the AI Customer Support Assistant scenario
#
# Usage:
#   ./config/seed-data/seed.sh           # Uses default docker-compose settings
#   ./config/seed-data/seed.sh custom    # Prompts for custom connection settings
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="$SCRIPT_DIR/demo_data.sql"

# Default connection settings (match docker-compose.yml)
DB_HOST="${DATABASE_HOST:-localhost}"
DB_PORT="${DATABASE_PORT:-5432}"
DB_NAME="${DATABASE_NAME:-axonflow}"
DB_USER="${DATABASE_USER:-axonflow}"
DB_PASSWORD="${DATABASE_PASSWORD:-localdev123}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${BLUE}AxonFlow Demo Data Seeder${NC}"
echo -e "${BLUE}=========================${NC}"
echo ""

# Check if SQL file exists
if [ ! -f "$SQL_FILE" ]; then
    echo -e "${RED}Error: SQL file not found at $SQL_FILE${NC}"
    exit 1
fi

# Check for psql
if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: psql not found. Install PostgreSQL client or use docker:${NC}"
    echo "  docker exec -i axonflow-postgres psql -U axonflow -d axonflow < $SQL_FILE"
    exit 1
fi

# Show connection info
echo -e "${YELLOW}Connection settings:${NC}"
echo "  Host:     $DB_HOST"
echo "  Port:     $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User:     $DB_USER"
echo ""

# Run the SQL file
echo -e "${BLUE}Seeding demo data...${NC}"

PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -f "$SQL_FILE" \
    --quiet \
    2>&1 | grep -v "^NOTICE:" || true

echo ""
echo -e "${GREEN}Demo data seeded successfully.${NC}"
echo ""

# Show summary
echo -e "${YELLOW}Data summary:${NC}"
PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -t \
    -c "SELECT 'Support tickets: ' || COUNT(*) FROM support_tickets;" 2>/dev/null || echo "  Support tickets: (run query manually)"

PGPASSWORD="$DB_PASSWORD" psql \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    -t \
    -c "SELECT 'Audit logs: ' || COUNT(*) FROM audit_logs;" 2>/dev/null || echo "  Audit logs: (run query manually)"

echo ""
echo -e "${BLUE}Ready for demo.${NC}"
echo ""
