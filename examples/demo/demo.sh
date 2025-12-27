#!/bin/bash
#
# AxonFlow Community Demo
# Comprehensive demonstration of AI governance capabilities
#
# Scenario: AI Customer Support Assistant
# Shows how AxonFlow governs an AI agent that helps support teams
# query customer data while ensuring security and compliance.
#
# Usage:
#   ./examples/demo/demo.sh              # Full demo (~10 minutes)
#   ./examples/demo/demo.sh --quick      # Quick demo (~3 minutes)
#   ./examples/demo/demo.sh --part N     # Run specific part (1-7)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# UI helpers
print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  $1${NC}"
    echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}${BOLD}  $1${NC}"
    echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_step() {
    echo -e "${BLUE}→ $1${NC}"
}

print_success() {
    echo -e "${GREEN}${BOLD}✓ $1${NC}"
}

print_blocked() {
    echo -e "${RED}${BOLD}✗ BLOCKED: $1${NC}"
}

print_info() {
    echo -e "${DIM}  $1${NC}"
}

wait_for_user() {
    if [ "$QUICK_MODE" != "true" ]; then
        echo ""
        echo -e "${DIM}Press Enter to continue...${NC}"
        read -r
    fi
}

# Check prerequisites
check_services() {
    print_step "Checking services..."

    if ! curl -s "$AGENT_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Error: Agent not responding at $AGENT_URL${NC}"
        echo -e "Run: ${CYAN}docker-compose up -d${NC}"
        exit 1
    fi
    print_success "Agent healthy at $AGENT_URL"

    if ! curl -s "$ORCHESTRATOR_URL/health" > /dev/null 2>&1; then
        echo -e "${RED}Error: Orchestrator not responding at $ORCHESTRATOR_URL${NC}"
        echo -e "Run: ${CYAN}docker-compose up -d${NC}"
        exit 1
    fi
    print_success "Orchestrator healthy at $ORCHESTRATOR_URL"
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 not found${NC}"
        echo "Install Python 3 to run the demo examples"
        exit 1
    fi

    # Only install if packages are missing
    if ! python3 -c "import axonflow, httpx, openai" 2>/dev/null; then
        echo -e "${YELLOW}Installing Python dependencies...${NC}"
        pip3 install -r "$SCRIPT_DIR/requirements.txt" --quiet --disable-pip-version-check
    fi
}

# ============================================================================
# PART 1: THE PROBLEM
# ============================================================================
part1_the_problem() {
    print_section "Part 1: The Problem - Unprotected AI"

    echo -e "${MAGENTA}Scenario: Your AI assistant talks directly to an LLM.${NC}"
    echo -e "${MAGENTA}What could go wrong?${NC}"
    echo ""

    print_step "Running unprotected call..."
    echo ""

    python3 "$SCRIPT_DIR/01_the_problem.py"

    echo ""
    echo -e "${RED}${BOLD}Problems with unprotected AI:${NC}"
    echo -e "  ${RED}•${NC} No audit trail - who asked what?"
    echo -e "  ${RED}•${NC} No PII detection - sensitive data leaks"
    echo -e "  ${RED}•${NC} No injection protection - prompts can be hijacked"
    echo -e "  ${RED}•${NC} No rate limiting - runaway costs"

    wait_for_user
}

# ============================================================================
# PART 2: CORE GOVERNANCE
# ============================================================================
part2_governance() {
    print_section "Part 2: Core Governance - Policy Enforcement"

    echo -e "${MAGENTA}Same queries, but now with AxonFlow governance.${NC}"
    echo -e "${MAGENTA}Watch policies block dangerous content automatically.${NC}"
    echo ""

    # 2.1 PII Detection
    echo -e "${CYAN}${BOLD}2.1 PII Detection Suite${NC}"
    echo ""
    print_step "Testing PII patterns (SSN, Credit Card, PAN, Aadhaar)..."
    echo ""

    python3 "$SCRIPT_DIR/02_pii_detection.py"

    wait_for_user

    # 2.2 SQL Injection
    echo -e "${CYAN}${BOLD}2.2 SQL Injection Blocking${NC}"
    echo ""
    print_step "Testing SQL injection patterns..."
    echo ""

    python3 "$SCRIPT_DIR/03_sql_injection.py"

    wait_for_user
}

# ============================================================================
# PART 3: INTEGRATION MODES
# ============================================================================
part3_integration() {
    print_section "Part 3: Integration Modes"

    echo -e "${MAGENTA}Two ways to integrate AxonFlow into your stack:${NC}"
    echo ""
    echo -e "  ${CYAN}Proxy Mode${NC}  - AxonFlow handles everything (simplest)"
    echo -e "  ${CYAN}Gateway Mode${NC} - You control the LLM call (lowest latency)"
    echo ""

    # 3.1 Proxy Mode
    echo -e "${CYAN}${BOLD}3.1 Proxy Mode${NC}"
    echo -e "${DIM}App → AxonFlow → LLM → Response${NC}"
    echo ""

    python3 "$SCRIPT_DIR/04_proxy_mode.py"

    wait_for_user

    # 3.2 Gateway Mode
    echo -e "${CYAN}${BOLD}3.2 Gateway Mode${NC}"
    echo -e "${DIM}Pre-check → Your LLM Call → Audit${NC}"
    echo ""

    python3 "$SCRIPT_DIR/05_gateway_mode.py"

    wait_for_user
}

# ============================================================================
# PART 4: MCP CONNECTORS
# ============================================================================
part4_connectors() {
    print_section "Part 4: MCP Connectors - AI Meets Your Data"

    echo -e "${MAGENTA}Connect AI to databases with built-in governance.${NC}"
    echo -e "${MAGENTA}Natural language → SQL, with security at every step.${NC}"
    echo ""

    print_step "Querying support tickets via PostgreSQL connector..."
    echo ""

    python3 "$SCRIPT_DIR/06_mcp_connector.py"

    wait_for_user
}

# ============================================================================
# PART 5: MULTI-AGENT PLANNING (MAP)
# ============================================================================
part5_map() {
    print_section "Part 5: Multi-Agent Planning (MAP)"

    echo -e "${MAGENTA}Orchestrate complex workflows with declarative YAML.${NC}"
    echo -e "${MAGENTA}Governance applied at every step automatically.${NC}"
    echo ""

    print_step "Generating and executing a multi-step plan..."
    echo ""

    python3 "$SCRIPT_DIR/07_multi_agent_planning.py"

    wait_for_user
}

# ============================================================================
# PART 6: OBSERVABILITY
# ============================================================================
part6_observability() {
    print_section "Part 6: Observability - Complete Audit Trail"

    echo -e "${MAGENTA}Every request logged. Every decision recorded.${NC}"
    echo -e "${MAGENTA}Query audit logs and visualize in Grafana.${NC}"
    echo ""

    # 6.1 Audit Trail
    echo -e "${CYAN}${BOLD}6.1 Audit Trail Query${NC}"
    echo ""

    python3 "$SCRIPT_DIR/08_audit_trail.py"

    echo ""

    # 6.2 Grafana
    echo -e "${CYAN}${BOLD}6.2 Grafana Dashboard${NC}"
    echo ""
    echo -e "${GREEN}→ Open Grafana: ${BOLD}http://localhost:3000${NC}"
    echo -e "${DIM}  Login: admin / grafana_localdev456${NC}"
    echo -e "${DIM}  Dashboard: AxonFlow Community (auto-provisioned)${NC}"
    echo ""
    echo -e "  ${CYAN}Panels:${NC}"
    echo -e "    • Request rate and blocked requests"
    echo -e "    • Latency percentiles (P50, P95, P99)"
    echo -e "    • Policy enforcement breakdown"
    echo -e "    • LLM token usage and costs"
    echo -e "    • MCP connector metrics"

    wait_for_user
}

# ============================================================================
# PART 7: MULTI-MODEL ROUTING
# ============================================================================
part7_multimodel() {
    print_section "Part 7: Multi-Model Routing"

    echo -e "${MAGENTA}Same governance, any LLM provider.${NC}"
    echo -e "${MAGENTA}Switch providers without changing application code.${NC}"
    echo ""

    python3 "$SCRIPT_DIR/09_multi_model.py"

    wait_for_user
}

# ============================================================================
# SUMMARY
# ============================================================================
print_summary() {
    print_header "Demo Complete"

    echo -e "${BOLD}What you just saw:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} ${BOLD}Policy Enforcement${NC} - PII detection, SQL injection blocking"
    echo -e "  ${GREEN}✓${NC} ${BOLD}Two Integration Modes${NC} - Proxy (simple) and Gateway (fast)"
    echo -e "  ${GREEN}✓${NC} ${BOLD}MCP Connectors${NC} - AI safely querying your database"
    echo -e "  ${GREEN}✓${NC} ${BOLD}Multi-Agent Planning${NC} - Orchestrated workflows with governance"
    echo -e "  ${GREEN}✓${NC} ${BOLD}Complete Observability${NC} - Audit logs and Grafana dashboards"
    echo -e "  ${GREEN}✓${NC} ${BOLD}Multi-Model Support${NC} - Vendor-neutral LLM routing"
    echo ""
    echo -e "${BOLD}Quick Links:${NC}"
    echo ""
    echo -e "  ${CYAN}Documentation:${NC}     https://docs.getaxonflow.com"
    echo -e "  ${CYAN}GitHub:${NC}            https://github.com/getaxonflow/axonflow"
    echo -e "  ${CYAN}Grafana Dashboard:${NC} http://localhost:3000"
    echo -e "  ${CYAN}Prometheus:${NC}        http://localhost:9090"
    echo ""
    echo -e "${DIM}All examples: $SCRIPT_DIR/*.py${NC}"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    local QUICK_MODE="false"
    local SPECIFIC_PART=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick|-q)
                QUICK_MODE="true"
                shift
                ;;
            --part|-p)
                SPECIFIC_PART="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --quick, -q       Quick mode (skip pauses)"
                echo "  --part N, -p N    Run specific part (1-7)"
                echo "  --help, -h        Show this help"
                echo ""
                echo "Parts:"
                echo "  1: The Problem (unprotected AI)"
                echo "  2: Core Governance (PII, SQL injection)"
                echo "  3: Integration Modes (Proxy, Gateway)"
                echo "  4: MCP Connectors (PostgreSQL)"
                echo "  5: Multi-Agent Planning"
                echo "  6: Observability (Audit, Grafana)"
                echo "  7: Multi-Model Routing"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    export QUICK_MODE

    # Header
    print_header "AxonFlow Community Demo - AI Customer Support Assistant"

    echo -e "${DIM}Scenario: An AI assistant helps support agents query customer${NC}"
    echo -e "${DIM}data while AxonFlow ensures security, compliance, and audit.${NC}"
    echo ""

    # Prerequisites
    check_services
    check_python

    # Run parts
    if [ -n "$SPECIFIC_PART" ]; then
        case $SPECIFIC_PART in
            1) part1_the_problem ;;
            2) part2_governance ;;
            3) part3_integration ;;
            4) part4_connectors ;;
            5) part5_map ;;
            6) part6_observability ;;
            7) part7_multimodel ;;
            *) echo "Invalid part: $SPECIFIC_PART (use 1-7)"; exit 1 ;;
        esac
    else
        # Full demo
        if [ "$QUICK_MODE" = "true" ]; then
            # Quick mode: Parts 2, 3, 6 only
            part2_governance
            part3_integration
            part6_observability
        else
            # Full demo
            part1_the_problem
            part2_governance
            part3_integration
            part4_connectors
            part5_map
            part6_observability
            part7_multimodel
        fi
    fi

    print_summary
}

main "$@"
