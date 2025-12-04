# AxonFlow Backend Services - Complete File Manifest

**Generated**: October 28, 2025  
**Document Status**: Complete  

---

## Overview

This manifest provides a complete inventory of all backend service files with absolute paths, line counts, and brief descriptions.

---

## AGENT SERVICE (`/Users/saurabhjain/Development/axonflow/platform/agent/`)

### Core Service Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.go` | 926 | Main entry point, HTTP router setup, request handler orchestration |
| `static_policies.go` | 213 | Regex-based policy engine for SQL injection/dangerous query detection |
| `db_policies.go` | 500+ | Database-backed policy engine with caching and refresh |
| `auth.go` | 200+ | Client authentication with license key validation, user whitelist |
| `db_auth.go` | 340+ | Database-backed authentication, API key management |
| `redis_rate_limit.go` | 155 | Redis distributed rate limiting with fallback |
| `audit_queue.go` | 260+ | Async audit logging with file-based fallback |
| `mcp_handler.go` | 350+ | Model Context Protocol connector registry and management |

### License Package Files

| File | Lines | Purpose |
|------|-------|---------|
| `license/validation.go` | 320+ | License key validation with HMAC signature checking |
| `license/keygen.go` | ~100 | License key generation utility |
| `license/cmd/keygen/main.go` | ~50 | CLI tool for license key generation |

### Configuration & Database

| File | Lines | Purpose |
|------|-------|---------|
| `init_db.sql` | 100+ | Initial database schema setup |
| `Dockerfile` | ~30 | Docker container definition |
| `.dockerignore` | ~10 | Docker build exclusions |

### Migrations

| Directory | Purpose |
|-----------|---------|
| `migrations/` | Database migration files (multiple versions) |

**Total Agent Service**: ~3,500+ lines of code

---

## ORCHESTRATOR SERVICE (`/Users/saurabhjain/Development/axonflow/platform/orchestrator/`)

### Core Service Files

| File | Lines | Purpose |
|------|-------|---------|
| `main.go` | 1,028 | Main entry point, component initialization, HTTP routes |
| `dynamic_policy_engine.go` | 400+ | Context-aware policy evaluation, conditions, actions |
| `llm_router.go` | 280+ | Multi-provider LLM routing with load balancing |
| `planning_engine.go` | 400+ | Query decomposition and workflow generation |
| `workflow_engine.go` | 600+ | Multi-step workflow execution orchestration |
| `result_aggregator.go` | 236 | LLM-based result synthesis |
| `response_processor.go` | 270+ | PII detection and response redaction |
| `audit_logger.go` | 320+ | Comprehensive audit trail logging |
| `metrics_collector.go` | 280+ | Performance metrics collection |
| `amadeus_client.go` | 235 | Travel API client integration |
| `amadeus_connector.go` | ~200 | Amadeus connector implementation |
| `db_dynamic_policies.go` | 350+ | Dynamic policy database operations |
| `api_call_processor.go` | 210+ | API request/response processing |
| `connector_marketplace_handlers.go` | 350+ | MCP connector marketplace endpoints |
| `mcp_connector_processor.go` | 260+ | MCP connector processing |

### Configuration & Deployment

| File | Lines | Purpose |
|------|-------|---------|
| `Dockerfile` | ~30 | Docker container definition |
| `.dockerignore` | ~10 | Docker build exclusions |
| `docker-compose.yml` | ~30 | Local development setup |

### Binary

| File | Size | Purpose |
|------|------|---------|
| `axonflow-orchestrator` | ~16MB | Compiled binary (development) |

**Total Orchestrator Service**: ~5,000+ lines of code

---

## SHARED LIBRARIES (`/Users/saurabhjain/Development/axonflow/platform/shared/`)

### Logger Package

| File | Lines | Purpose |
|------|-------|---------|
| `logger/logger.go` | 126 | Structured JSON logger for multi-tenant systems |

**Total Shared Libraries**: ~126 lines of code

---

## MODULE DEFINITIONS

### Root Module

| File | Purpose |
|------|---------|
| `/Users/saurabhjain/Development/axonflow/platform/go.mod` | Go module definition with dependencies |
| `/Users/saurabhjain/Development/axonflow/platform/go.sum` | Go module lock file |

### Key Dependencies (from go.mod)

```
github.com/dgrijalva/jwt-go v3.2.0+incompatible     - JWT handling
github.com/gorilla/mux v1.8.1                       - HTTP routing
github.com/lib/pq v1.10.9                           - PostgreSQL driver
github.com/go-redis/redis/v8 v8.11.5               - Redis client
github.com/prometheus/client_golang v1.17.0        - Prometheus metrics
github.com/rs/cors v1.10.1                         - CORS support
github.com/gocql/gocql v1.7.0                      - Cassandra driver
```

---

## DOCUMENTATION FILES

### Generated Documentation

| File | Lines | Purpose |
|------|-------|---------|
| `BACKEND_ARCHITECTURE_AND_TESTING_GUIDE.md` | 2,370 | Complete architecture and testing blueprint |
| `ARCHITECTURE_SUMMARY.md` | 250+ | Executive summary of architecture |
| `FILE_MANIFEST.md` | This file | Complete file inventory |

### README Files

| File | Purpose |
|------|---------|
| `agent/README.md` | Agent service documentation |
| `orchestrator/README.md` | Orchestrator service documentation |

---

## ENVIRONMENT VARIABLES REQUIRED

### Agent Service

```
AXONFLOW_LICENSE_KEY       - License key for validation (required)
JWT_SECRET                 - Secret for JWT token validation (required)
ORCHESTRATOR_URL           - Orchestrator service URL (default: http://localhost:8081)
DATABASE_URL               - PostgreSQL connection (optional)
REDIS_URL                  - Redis connection (optional)
PORT                       - Server port (default: 8080)
INSTANCE_ID                - Instance identifier (for logging)
```

### Orchestrator Service

```
DATABASE_URL               - PostgreSQL connection (optional)
OPENAI_API_KEY            - OpenAI API key (for LLM routing)
ANTHROPIC_API_KEY         - Anthropic API key (for LLM routing)
LOCAL_LLM_ENDPOINT        - Local LLM endpoint (optional)
AMADEUS_API_KEY           - Amadeus API credentials
AMADEUS_API_SECRET        - Amadeus API secret
PORT                      - Server port (default: 8081)
INSTANCE_ID               - Instance identifier (for logging)
```

---

## DATABASE TABLES

### Required Tables for Agent Service

```
clients
├── id
├── client_id (unique)
├── license_key
├── name
├── tenant_id
├── permissions (array)
├── rate_limit (int)
└── enabled (boolean)

users
├── id
├── email (unique)
├── name
├── department
├── role
├── region
├── permissions (array)
└── tenant_id

policies
├── id
├── policy_id (unique)
├── name
├── category
├── pattern
├── severity
├── description
├── action
├── tenant_id
└── enabled (boolean)

audit_logs
├── id
├── request_id
├── user_email
├── client_id
├── tenant_id
├── request_type
├── query
├── status
├── blocked (boolean)
├── block_reason
├── response_summary
└── created_at
```

### Required Tables for Orchestrator Service

```
policies_dynamic
├── id
├── policy_id (unique)
├── name
├── description
├── type
├── conditions (jsonb)
├── actions (jsonb)
├── priority
├── enabled (boolean)
├── tenant_id
├── created_at
└── updated_at

workflow_executions
├── id
├── workflow_name
├── tenant_id
├── user_email
├── status
├── input (jsonb)
├── output (jsonb)
├── steps (jsonb)
├── start_time
├── end_time
├── error
└── created_at

workflow_steps
├── id
├── execution_id
├── step_name
├── status
├── input (jsonb)
├── output (jsonb)
├── start_time
├── end_time
└── process_time
```

---

## HTTP ENDPOINTS

### Agent Service (Port 8080)

```
GET    /health                     - Service health check
GET    /metrics                    - JSON metrics
GET    /prometheus                 - Prometheus metrics
POST   /api/request                - Main request handler
GET    /api/clients                - List clients
POST   /api/clients                - Create client
POST   /api/policies/test          - Test policy
GET    /mcp/connectors             - List connectors
GET    /mcp/connectors/{name}/health - Connector health
```

### Orchestrator Service (Port 8081)

```
GET    /health                                      - Service health
GET    /metrics                                     - JSON metrics
GET    /prometheus                                  - Prometheus metrics
POST   /api/v1/process                             - Main processing
GET    /api/v1/providers/status                    - LLM provider status
PUT    /api/v1/providers/weights                   - Update weights
GET    /api/v1/policies/dynamic                    - List policies
POST   /api/v1/policies/test                       - Test policy
GET    /api/v1/metrics                             - Metrics
POST   /api/v1/audit/search                        - Search audit
GET    /api/v1/audit/tenant/{id}                   - Tenant audit
POST   /api/v1/workflows/execute                   - Execute workflow
GET    /api/v1/workflows/executions/{id}           - Get execution
GET    /api/v1/workflows/executions                - List executions
GET    /api/v1/workflows/executions/tenant/{id}    - Tenant executions
POST   /api/v1/plan                                - Multi-agent plan
GET    /api/v1/connectors                          - List connectors
GET    /api/v1/connectors/{id}                     - Get connector
POST   /api/v1/connectors/{id}/install             - Install
DELETE /api/v1/connectors/{id}/uninstall           - Uninstall
GET    /api/v1/connectors/{id}/health              - Health check
```

---

## METRICS EXPORTED

### Prometheus Metrics

**Agent Service**:
- `axonflow_agent_requests_total` - Total requests
- `axonflow_agent_request_duration_milliseconds` - Request latency
- `axonflow_agent_policy_evaluations_total` - Policy evaluations
- `axonflow_agent_blocked_requests_total` - Blocked requests

**Orchestrator Service**:
- `axonflow_orchestrator_requests_total` - Total requests
- `axonflow_orchestrator_request_duration_milliseconds` - Request latency
- `axonflow_orchestrator_policy_evaluations_total` - Policy evaluations
- `axonflow_orchestrator_blocked_requests_total` - Blocked requests
- `axonflow_orchestrator_llm_calls_total` - LLM calls by provider

---

## CODE STATISTICS

### Total Backend Code

```
Service             Files    Lines     
Agent Service       13       2,200+
Orchestrator        17       4,000+
Shared Libraries    1        126
Configuration       3        ~100
Documentation       3        2,600+
─────────────────────────────────
TOTAL              37       ~8,900+
```

### Test Coverage Status

```
Current: 0% (No tests exist)
Target:  75-90% (varies by service)
Required Tests: 19 files
Estimated Test Code: ~6,000-8,000 lines
```

---

## CRITICAL FILES FOR TESTING

**Must Test (Security/Core)**:
1. `/Users/saurabhjain/Development/axonflow/platform/agent/auth.go`
2. `/Users/saurabhjain/Development/axonflow/platform/agent/static_policies.go`
3. `/Users/saurabhjain/Development/axonflow/platform/agent/db_policies.go`
4. `/Users/saurabhjain/Development/axonflow/platform/agent/redis_rate_limit.go`
5. `/Users/saurabhjain/Development/axonflow/platform/orchestrator/dynamic_policy_engine.go`
6. `/Users/saurabhjain/Development/axonflow/platform/orchestrator/llm_router.go`
7. `/Users/saurabhjain/Development/axonflow/platform/orchestrator/workflow_engine.go`

**Should Test (Features)**:
8. `/Users/saurabhjain/Development/axonflow/platform/orchestrator/planning_engine.go`
9. `/Users/saurabhjain/Development/axonflow/platform/orchestrator/result_aggregator.go`
10. `/Users/saurabhjain/Development/axonflow/platform/agent/audit_queue.go`
11. `/Users/saurabhjain/Development/axonflow/platform/agent/license/validation.go`
12. `/Users/saurabhjain/Development/axonflow/platform/shared/logger/logger.go`

---

## ARCHITECTURE DOCUMENTS GENERATED

All documents are in `/Users/saurabhjain/Development/axonflow/platform/`

1. **BACKEND_ARCHITECTURE_AND_TESTING_GUIDE.md** (2,370 lines)
   - Complete service architecture
   - Detailed component descriptions
   - 19 test files structure
   - Database schemas
   - Mock implementations
   - CI/CD integration examples

2. **ARCHITECTURE_SUMMARY.md** (250+ lines)
   - Executive summary
   - Key findings
   - Testing effort estimates
   - Recommended execution plan

3. **FILE_MANIFEST.md** (this file)
   - Complete file inventory
   - Path references
   - Environment variables
   - Endpoints reference
   - Statistics

---

## NEXT STEPS

1. Read: `/Users/saurabhjain/Development/axonflow/platform/BACKEND_ARCHITECTURE_AND_TESTING_GUIDE.md`
2. Review: Agent service files starting with `auth.go`
3. Plan: Test infrastructure setup
4. Implement: Phase 1 tests (logger + auth)
5. Expand: Complete remaining tests following the guide

---

**Document Generated**: October 28, 2025  
**Last Updated**: October 28, 2025  
**Status**: Complete and Ready for Implementation

