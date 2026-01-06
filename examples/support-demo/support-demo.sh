#!/bin/bash
# Copyright 2025 AxonFlow
# SPDX-License-Identifier: BUSL-1.1

# Support Demo launcher script
# Usage: ./support-demo.sh [--stop|--logs|--clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             AxonFlow Support Demo                            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_ports() {
    echo -e "${GREEN}Services are running at:${NC}"
    echo -e "  Frontend:     ${YELLOW}http://localhost:3001${NC}"
    echo -e "  Backend API:  ${YELLOW}http://localhost:8082${NC}"
    echo -e "  AxonFlow Agent:       ${YELLOW}http://localhost:8080${NC}"
    echo -e "  AxonFlow Orchestrator: ${YELLOW}http://localhost:8081${NC}"
    echo -e "  PostgreSQL:   ${YELLOW}localhost:5433${NC}"
    echo ""
    echo -e "${GREEN}Demo Users (password: demo123):${NC}"
    echo -e "  Agent:   john.doe@company.com"
    echo -e "  Manager: sarah.manager@company.com"
    echo -e "  Admin:   admin@company.com"
    echo ""
}

wait_for_health() {
    local url=$1
    local name=$2
    local max_attempts=30
    local attempt=1

    echo -n "Waiting for $name..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            echo -e " ${GREEN}ready${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    echo -e " ${RED}timeout${NC}"
    return 1
}

case "${1:-}" in
    --stop)
        echo -e "${YELLOW}Stopping support demo services...${NC}"
        docker compose down
        echo -e "${GREEN}Services stopped.${NC}"
        exit 0
        ;;
    --logs)
        docker compose logs -f
        exit 0
        ;;
    --clean)
        echo -e "${YELLOW}Stopping and removing all support demo data...${NC}"
        docker compose down -v --remove-orphans
        echo -e "${GREEN}Cleanup complete.${NC}"
        exit 0
        ;;
    --help|-h)
        echo "Usage: $0 [--stop|--logs|--clean|--help]"
        echo ""
        echo "Options:"
        echo "  --stop   Stop all services"
        echo "  --logs   Follow container logs"
        echo "  --clean  Stop services and remove volumes"
        echo "  --help   Show this help message"
        exit 0
        ;;
esac

print_header

# Check for required environment variables
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo -e "${YELLOW}Warning: No LLM API keys found.${NC}"
    echo -e "Set OPENAI_API_KEY or ANTHROPIC_API_KEY for LLM features."
    echo ""
fi

echo -e "${BLUE}Starting support demo services...${NC}"
echo ""

# Build and start services
docker compose up -d --build

echo ""
echo -e "${BLUE}Waiting for services to be healthy...${NC}"
echo ""

# Wait for health checks
wait_for_health "http://localhost:8082/api/health" "Backend"
wait_for_health "http://localhost:8080/health" "AxonFlow Agent"
wait_for_health "http://localhost:8081/health" "AxonFlow Orchestrator"

# Setup demo policies
echo ""
echo -e "${BLUE}Setting up demo policies...${NC}"
if [ -x "./setup-dynamic-policies.sh" ]; then
    ./setup-dynamic-policies.sh > /dev/null 2>&1 && \
        echo -e "${GREEN}Dynamic policies configured${NC}" || \
        echo -e "${YELLOW}Note: Could not configure dynamic policies${NC}"
fi

echo ""
print_ports

echo -e "${GREEN}Support Demo is ready!${NC}"
echo -e "Open ${YELLOW}http://localhost:3001${NC} in your browser."
echo ""
echo -e "Use ${YELLOW}./support-demo.sh --logs${NC} to view logs."
echo -e "Use ${YELLOW}./support-demo.sh --stop${NC} to stop services."
