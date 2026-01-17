# Changelog

All notable changes to AxonFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Grafana Dashboard**: Add Security & Compliance section with PII detection, provider distribution, and policy metrics panels (#836)

### Fixed

- Improved enterprise license validation consistency (#1010)

---

## [3.3.0] - 2026-01-16

### Added

- **MCP Connector Audit Logging** (#1006): Full audit trail for all MCP connector queries and commands
  - New `mcp_query_audits` table captures all MCP operations with policy evaluation results
  - REQUEST phase logging: SQLi detection, PII blocking, matched policies
  - RESPONSE phase logging: PII redaction, redacted field paths (JSONPath format)
  - EXFILTRATION logging: Row counts, volume limit violations
  - Compliance mode (sync) for violations, performance mode (async) for success
  - Statement privacy: SHA256 hash stored instead of raw queries
  - `audit_id` field correlates with SDK `PolicyInfo` for traceability

- **MCP Audit Examples**: Comprehensive examples for all 4 SDKs + HTTP API
  - `examples/mcp-audit/http/` - HTTP API examples (curl/bash)
  - `examples/mcp-audit/go/` - Go SDK example
  - `examples/mcp-audit/python/` - Python SDK example
  - `examples/mcp-audit/typescript/` - TypeScript SDK example
  - `examples/mcp-audit/java/` - Java SDK example

### Documentation

- New guide: `docs/guides/audit-logging.md` - Comprehensive audit logging architecture guide
- New guide: `docs/guides/mcp-audit-logging.md` - MCP audit logging configuration and usage
- Updated API docs: `docs/api/agent-api.yaml` - Added audit logging details to MCP endpoints

---

## [3.2.0] - 2026-01-14

### Added

- **MCP Exfiltration Detection** (#966): Row and data volume limits for MCP connector queries
  - Configurable row count limits (default: 10,000 per query)
  - Configurable data volume limits (default: 10MB per response)
  - Returns 403 with detailed limit information when exceeded
  - `ExfiltrationCheck` field in `PolicyInfo` response

- **MCP Dynamic Policy Evaluation** (#968): Real-time policy evaluation via Orchestrator
  - Pre-query policy evaluation for rate limits, budgets, time/role access
  - Graceful degradation when Orchestrator is unavailable
  - `DynamicPolicyInfo` field in `PolicyInfo` response

### Fixed

- Removed unused `MCP_DYNAMIC_POLICIES_ENDPOINT` environment variable (#1003)

### Tests

- Added integration tests for MCP exfiltration and dynamic policy features (#1002)

### Documentation

- Updated community/enterprise feature matrix with MCP policy features (#1000)

---

## [3.1.0] - 2026-01-09

### Added

- **MCP Tiered Policy Enforcement** (#963, #975): Phase-aware policy enforcement for MCP connector requests
  - REQUEST phase: SQLi pattern blocking (DROP TABLE, UNION SELECT, OR 1=1, DELETE, TRUNCATE)
  - REQUEST phase: Critical PII blocking (SSN, Credit Card, India PAN, Aadhaar)
  - RESPONSE phase: PII redaction in connector data (SSN, Credit Card masked)
  - PolicyInfo metadata in all MCP responses (`policies_evaluated`, `redactions_applied`, `processing_time_ms`)
  - Non-critical PII (Email, Phone) allowed through with logging

- **MCP PII Redaction Examples**: Comprehensive examples for all 4 SDKs + HTTP API
  - `examples/mcp-policies/pii-redaction/go/` - Go SDK example
  - `examples/mcp-policies/pii-redaction/python/` - Python SDK example
  - `examples/mcp-policies/pii-redaction/typescript/` - TypeScript SDK example
  - `examples/mcp-policies/pii-redaction/java/` - Java SDK example
  - `examples/mcp-policies/pii-redaction/http/` - HTTP API examples (curl)

### Enterprise

- **Healthcare PHI Patterns**: Enterprise example for HIPAA-compliant PHI detection
  - Medical Record Number (MRN) detection
  - DEA Number detection
  - NPI (National Provider Identifier) detection
  - Medicare Beneficiary Identifier (MBI) detection
  - ICD-10 code detection

### Fixed

- **Healthcare example**: Fixed policy verification to use `GetStaticPolicy` instead of `ListStaticPolicies`

---

## [3.1.1] - 2026-01-09

### Fixed

- **MAP GetPlanStatus API**: Fixed response fields to match SDK expectations
  - Changed `step_count` to `total_steps` in API response
  - Added `completed_steps` field (0 when pending, equals total_steps when completed)
  - SDK methods `GetPlanStatus()` / `get_plan_status()` now correctly receive step tracking info

---

## [3.0.2] - 2026-01-08

### Fixed

- **Agent proxy routes**: Fixed missing proxy routes for `/api/v1/pricing`, `/api/v1/plan`, and `/api/v1/audit` endpoints. SDK methods like `getPricing()`, `generatePlan()`, `executePlan()`, and `searchAuditLogs()` now work correctly through the Agent single entry point (ADR-026). Previously these returned 404 errors.

### Changed

- **GoReleaser upgraded to v2**: Release workflow now uses GoReleaser v2 configuration format for better compatibility.

### Enterprise

- **OAuth2 Basic auth support**: Agent now accepts `Authorization: Basic base64(clientId:clientSecret)` for authentication (ADR-028), in addition to existing `X-License-Key` header.
- **Code governance: ClosePR endpoint**: Added endpoint for closing PRs without merging, useful for cleaning up test/demo PRs.

---

## [3.0.1] - 2026-01-07

### Fixed

- **Multi-Agent Planning (MAP) Two-Step Execution**: Fixed race condition where plan execution started before DB commit
  - `GeneratePlan` now stores workflow plan in database with 1-hour TTL before returning
  - `ExecutePlan` retrieves stored plan by `plan_id` and executes workflow
  - New `migrations/core/037_plans.sql` - Plans table for deferred execution
  - New `migrations/core/038_plans_composite_index.sql` - Composite index for cross-tenant queries
  - New `platform/orchestrator/planning/` package (service, repository, types)
  - Agent routes `execute-plan` requests to `/api/v1/plan/execute`

- **Agent Environment Variable Support for ECS/K8s**: Fixed orchestrator URL detection in containerized environments
  - Agent now checks `ORCHESTRATOR_URL` env var first (required for ECS, Kubernetes)
  - Priority: env var → Docker detection → localhost fallback
  - Increased MAP timeout to 60s

- **Support Demo Fixes**: Fixed broken support-demo in community repo
  - Removed vendor dependency causing Docker build failures
  - Fixed network naming (`axonflow_axonflow-network` requires `COMPOSE_PROJECT_NAME=axonflow`)
  - Removed direct orchestrator calls (all requests go through Agent)
  - Fixed role/region provider display for EU users

- **Dynamic Policy API Path**: Fixed incorrect API path in examples
  - Changed `/api/v1/policies/dynamic` → `/api/v1/dynamic-policies`

- **Dynamic Policy Payload Format**: Fixed condition format in examples
  - Changed `conditions: "{}"` → `conditions: "[]"` (array, not object)

### Added

- **Portal Proxy Routes (Enterprise)**: Agent now proxies `/api/v1/auth/*` for portal authentication

---

## [3.0.0] - 2026-01-05

### Breaking Changes

- **Single Entry Point Architecture (ADR-026)**: All API routes now go through the Agent (port 8080)
  - Agent proxies `/api/v1/dynamic-policies/*`, `/api/v1/budgets/*`, `/api/v1/usage/*`, `/api/v1/executions/*` to Orchestrator
  - Agent proxies `/portal/*` routes to Customer Portal
  - SDKs now use single `endpoint` parameter (default: `http://localhost:8080`)
  - **Deprecated**: `agent_url` and `orchestrator_url` SDK parameters (use `endpoint` instead)
  - **Deprecated**: Direct Orchestrator access on port 8081 (still works but not recommended)

- **Detection Defaults Changed (ADR-027)**: More nuanced default actions based on detection confidence
  - PII detection: `block` → `redact` (non-blocking, better UX)
  - High risk score (>0.8): `block` → `warn` (composite score needs tuning)
  - SQL injection: remains `block` (high confidence attacks)
  - Dangerous queries (DROP/TRUNCATE): remains `block` (destructive operations)

- **Environment Variable Changes**:
  - **New**: `SQLI_ACTION` (values: `block`, `warn`, `log`) - replaces `SQLI_BLOCK_MODE`
  - **New**: `PII_ACTION` (values: `block`, `warn`, `redact`, `log`) - replaces `PII_BLOCK_CRITICAL`
  - **New**: `SENSITIVE_DATA_ACTION` (values: `block`, `warn`, `log`) - credentials/secrets detection
  - **New**: `HIGH_RISK_ACTION` (values: `block`, `warn`, `log`) - high risk score threshold
  - **New**: `DANGEROUS_QUERY_ACTION` (values: `block`, `warn`, `log`) - DROP/TRUNCATE detection
  - **Deprecated**: `SQLI_BLOCK_MODE` (use `SQLI_ACTION` instead)
  - **Deprecated**: `PII_BLOCK_CRITICAL` (use `PII_ACTION` instead)

### Added

- **Sensitive Data Patterns in Database**: Credential and secret detection patterns now stored in `static_policies` table
  - Password, API key, token, secret, credentials, connection string patterns
  - Context exclusions for SQL keywords (PRIMARY KEY, FOREIGN KEY no longer false positives)
  - Per-tenant customization via policy overrides (Enterprise)

- **Environment Variable Precedence**: Clear hierarchy for detection configuration
  1. Per-tenant policy override (API) - highest priority
  2. Environment variable (docker-compose)
  3. Per-policy DB default (migration seed) - lowest priority

- **PII Redaction Support in SDKs**: New `requiresRedaction` field in `PolicyApprovalResult`
  - Returns `true` when PII was detected with `redact` action
  - Callers should process response for redaction when this flag is set
  - Available in all SDKs: `isRequiresRedaction()` (Java), `requires_redaction` (Python), `RequiresRedaction` (Go), `requiresRedaction` (TypeScript)

- **Strict Provider Enforcement for Dynamic Policies** (Issue #883): Compliance-aware LLM routing
  - Policies can specify `allowed_providers` to restrict which LLM providers handle requests
  - Requests **fail** (instead of fallback) if no compliant provider is available
  - Multiple policies use **intersection logic** (least privilege - most restrictive wins)
  - Enables GDPR, HIPAA, RBI compliance scenarios (e.g., EU data stays on-premise)
  - Example: `{"allowed_providers": ["ollama"]}` ensures only local model handles sensitive data

### Fixed

- **Dynamic policy condition evaluation**: `DatabaseDynamicPolicyEngine` now correctly evaluates conditions before applying actions
  - Previously, all policy actions were applied regardless of whether conditions matched
  - Now supports operators: `equals`, `not_equals`, `contains`, `not_contains`, `contains_any`, `regex`, `greater_than`, `less_than`, `in`, `not_in`

- **Tenant extraction bug**: Fixed `Client.ID` → `Client.TenantID` in policy evaluation

### Changed

- **SDK Method Signatures**: All SDKs updated for single endpoint
  - Go: `axonflow.NewClient(axonflow.AxonFlowConfig{Endpoint: "http://localhost:8080"})`
  - Python: `AxonFlow(endpoint="http://localhost:8080")`
  - TypeScript: `new AxonFlow({ endpoint: "http://localhost:8080" })`
  - Java: `AxonFlow.create(AxonFlowConfig.builder().endpoint("http://localhost:8080").build())`

### Migration Guide

**SDK Migration:**
```python
# Before (v2.x)
client = AxonFlow(
    agent_url="http://localhost:8080",
    orchestrator_url="http://localhost:8081"
)

# After (v3.0)
client = AxonFlow(endpoint="http://localhost:8080")
```

**Environment Variable Migration:**
```yaml
# Before (v2.x)
SQLI_BLOCK_MODE: "block"
PII_BLOCK_CRITICAL: "true"

# After (v3.0)
SQLI_ACTION: "block"
PII_ACTION: "redact"
SENSITIVE_DATA_ACTION: "warn"
HIGH_RISK_ACTION: "warn"
```

---

## [2.6.0] - 2026-01-04

### Added

- **Decision & Execution Replay API**: Debug and audit workflow executions with full state capture and policy decisions
  - `GET /api/v1/executions` - List executions with filtering (status, time range, agent/workflow)
  - `GET /api/v1/executions/{id}` - Get execution with all step snapshots
  - `GET /api/v1/executions/{id}/steps` - Get individual step snapshots
  - `GET /api/v1/executions/{id}/timeline` - Timeline view for visualization
  - `GET /api/v1/executions/{id}/export` - Export for compliance and archival
  - `DELETE /api/v1/executions/{id}` - Delete execution records
  - SDK examples for Go, Python, TypeScript, Java

- **Cost Controls Phase 1**: Budget management and LLM usage tracking
  - Budget scopes: Organization, Team, Agent, Workflow, User
  - Budget periods: Daily, Weekly, Monthly, Quarterly, Yearly
  - Enforcement actions: Warn, Block, Downgrade on exceed
  - Configurable alert thresholds (default 50%, 80%, 100%)
  - Usage aggregation: Hourly, Daily, Weekly, Monthly
  - Provider pricing for OpenAI, Anthropic, Azure, Gemini, Bedrock, Ollama
  - SDK examples for Go, Python, TypeScript, Java

### Fixed

- **Replay Data Race**: Fixed race condition in background summary update when multiple goroutines access execution state

### Documentation

- **ADR-024**: SDK method inclusion criteria for feature parity decisions
- **SDK Feature Coverage**: Cross-SDK method availability matrix

---

## [2.5.0] - 2026-01-02

### Added

- **Azure OpenAI Provider** (Community): Native Azure OpenAI Service integration
  - Supports both Azure AI Foundry (`cognitiveservices.azure.com`) and Classic (`openai.azure.com`) endpoints
  - Automatic authentication detection (Bearer token vs api-key header)
  - Streaming support via `GenerateContentStream`
  - Health checks and provider status endpoints
  - Environment variables: `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT_NAME`, `AZURE_OPENAI_API_VERSION`

- **Azure OpenAI Examples**: Complete example suite
  - Hello World (Go, Python, TypeScript, Java, HTTP)
  - PII Detection (Python)
  - SQL Injection Scanning (TypeScript)
  - Proxy Mode (Go)

- **README Philosophy Section**: Added positioning section explaining AxonFlow's "secure-by-default, configurable enforcement" approach for LLM discoverability

### Changed

- **Docker Compose UX**: Reorganized environment variables for better developer experience
  - **CORE CONFIGURATION**: 10 essential variables (LLM API keys, Azure config, ports, deployment mode)
  - **ADVANCED CONFIGURATION**: Defaults work for most users (database, internal services, routing)
  - Added explicit security configuration toggles (`SQLI_SCANNER_MODE`, `SQLI_BLOCK_MODE`)

### Documentation

- Added Azure OpenAI to Supported LLM Providers in README
- Provider documentation at `docs/llm/azure-openai.md`
- Updated Community vs Enterprise feature matrix

---

## [2.4.0] - 2025-12-31

### Changed

- **DEPLOYMENT_MODE Unification**: Single env var for auth (`community` = no auth, `enterprise` = license required)
  - Replaces `SELF_HOSTED_MODE` with clearer naming
  - New `isCommunityMode()` helper for consistent mode checks

### Added

- **MCP Connector Examples**: Python, TypeScript, Java implementations
- **Workflow Examples**: 6 patterns (sequential, parallel, conditional, fallbacks, pipelines, approvals)

### Fixed

- Shell script audit endpoint URL corrected
- Unit tests for enterprise mode validation

---

## [2.3.0] - 2025-12-30

### Changed

- **LLM Router Consolidation**: Completed migration to interface-based router architecture
  - Removed legacy `LLMRouter` concrete implementation (~1,700 lines)
  - All routing now through `LLMRouterInterface` abstraction introduced in v2.2.0
  - Cleaner codebase with single routing implementation path

- **Docker Compose Architecture**: Simplified deployment configuration
  - `docker-compose.yml` now serves as Community base configuration
  - Enterprise features available via overlay pattern

- **Default Anthropic Model**: Updated to `claude-sonnet-4-20250514` (Claude 4)

### Added

- **LLM Provider E2E Tests**: Comprehensive end-to-end test suite
  - Coverage for OpenAI, Anthropic, Google Gemini, and AWS Bedrock
  - Multi-language test implementations (Go, Python, TypeScript, Java)

### Removed

- `llm_router.go` - Superseded by `UnifiedRouterWrapper`
- `llm_routing_strategy.go` - Consolidated into unified router
- Legacy router test files

---

## [2.2.0] - 2025-12-29

### Added

- **LLM Router Interface Abstraction**: Components now depend on standard interface rather than concrete implementations
  - `LLMRouterInterface` - Standard interface for router abstraction
  - `UnifiedRouterWrapper` - Adapter enabling UnifiedRouter as drop-in LLMRouter replacement
  - Type conversion utilities between legacy and new router types

- **LLM Provider Routing Examples**: New HTTP/curl examples for direct API access
  - Shell script examples for all supported providers (OpenAI, Anthropic, Ollama, Gemini)
  - Gateway mode pre-check and audit examples
  - Java SDK example for provider routing

### Changed

- Orchestrator now uses interface type for LLM router configuration
- Improved test coverage for audit logging and routing strategies

---

## [2.1.0] - 2025-12-28

### Added

- **Human-in-the-Loop (HITL)**: New `require_approval` policy action for human oversight
  - Enterprise: Pauses execution, creates approval request in HITL queue
  - Community: Auto-approves (upgrade path to Enterprise)
  - EU AI Act Article 14 and SEBI AI/ML compliance support

- **Code Governance**: Automatic detection and audit of LLM-generated code
  - Identifies language, code type, potential secrets, unsafe patterns
  - Detects eval, exec, shell injection risks
  - Metadata logged for compliance

- **LLM Provider Routing**: Runtime control over provider selection
  - Weighted routing across providers
  - Health-based automatic failover
  - Per-request provider preferences

### Fixed

- Anthropic provider now respects `ANTHROPIC_MODEL` environment variable
- Support demo build and runtime fixes
- HITL example tier filter fixes

---

## [2.0.0] - 2025-12-25

**Unified Policy Architecture - Major Release**

This major release introduces enterprise-grade policy management to AxonFlow with a new three-tier hierarchy for granular control at every level.

### ⚠️ Breaking Changes

**Category Enum Values Changed in Responses**

| Old Category | New Category |
|--------------|--------------|
| `sql_injection` | `security-sqli` |
| `admin_access` | `security-admin` |
| `pii_detection` | `pii-global`, `pii-us`, `pii-eu`, `pii-india` |
| `dangerous_queries` | `security-sqli` |

**Migration Notes:**
- Old category values are still accepted in **request** parameters (backwards compatible)
- Update your code if you're parsing category values from **responses**
- SDKs don't require updates - they pass through category values as strings

### Added

- **Three-Tier Policy Hierarchy**: New policy architecture with System → Organization → Tenant inheritance
  - **System Tier**: 63 immutable security policies (53 static + 10 dynamic)
  - **Organization Tier**: Company-wide policies (Enterprise only)
  - **Tenant Tier**: Team-specific policies with full CRUD
  - Tier-aware policy resolution with caching

- **63 System Policies**: Comprehensive security and compliance coverage out-of-the-box
  - **Security - SQL Injection** (37): UNION, boolean-based, time-based, stacked queries, etc.
  - **Security - Admin Access** (4): Users table, audit log, config table access
  - **PII - Global** (7): Credit card, email, phone, IP, passport, DOB
  - **PII - US** (2): SSN, bank accounts
  - **PII - EU** (1): IBAN
  - **PII - India** (2): PAN, Aadhaar
  - **Dynamic** (10): Risk, compliance (HIPAA, GDPR), cost, access control

- **Policy CRUD APIs**: Full create, read, update, delete for organization and tenant policies
  - `GET /api/v1/static-policies` - List with tier/category filtering
  - `POST /api/v1/static-policies` - Create custom policy
  - `PUT /api/v1/static-policies/{id}` - Update policy
  - `DELETE /api/v1/static-policies/{id}` - Delete policy
  - `GET /api/v1/effective-policies` - Get merged hierarchy for tenant

- **Policy Overrides** (Enterprise): Customize system policy behavior
  - Disable system policies for organization
  - Change action (only to more restrictive)
  - Expiration dates for temporary overrides
  - Audit trail with reason requirement

- **SDK Policy Methods**: All 4 SDKs support policy management
  - TypeScript: `listStaticPolicies()`, `createStaticPolicy()`, etc.
  - Python: `list_static_policies()`, `create_static_policy()`, etc.
  - Go: `ListStaticPolicies()`, `CreateStaticPolicy()`, etc.
  - Java: `listStaticPolicies()`, `createStaticPolicy()`, etc.

- **Customer Portal UI**: Visual policy management for Enterprise customers
  - Unified policy dashboard
  - Override management
  - Policy testing interface

### Changed

- **Policy Categories**: New category naming convention
  - `security-sqli`, `security-admin` for security policies
  - `pii-global`, `pii-us`, `pii-eu`, `pii-india` for PII detection
  - `dynamic-risk`, `dynamic-compliance`, `dynamic-cost`, `dynamic-access` for context-aware policies

- **Performance**: Static policy evaluation maintains < 5ms p99 latency
  - Tier-aware caching with configurable TTL
  - Optimized regex pattern compilation

### Fixed

- **PII Detection Priority**: Credit card detection now correctly takes priority over phone number detection
  - Root cause: Policies were sorted by severity string (alphabetically "medium" > "critical")
  - Fix: Changed to `ORDER BY priority DESC` using numeric priority field

- **Tenant Policy Isolation**: Tenant-specific policies now only apply to their respective tenants
  - Root cause: `LoadPoliciesFromDB()` was loading ALL policies without tier filtering
  - Fix: Added two-phase evaluation - system policies via fast path, tenant policies via tier-aware engine

### Enterprise Features

- Organization-tier policy management
- System policy override capabilities
- Policy version history
- Customer Portal policy UI

---

## [1.1.3] - 2025-12-21

### Fixed

- **Usage Recording:** Fixed postgres errors in Community mode when `usage_events` table doesn't exist ([#96](https://github.com/getaxonflow/axonflow/issues/96))
  - Usage metering is now properly separated as an Enterprise-only feature
  - Community builds have zero-overhead no-op implementation using build tags
  - Thanks to [@gzak](https://github.com/gzak) for identifying and contributing the initial fix ([#97](https://github.com/getaxonflow/axonflow/pull/97))

- **OpenAI Provider:** Fixed "you must provide a model parameter" error when `OPENAI_MODEL` not explicitly set ([#100](https://github.com/getaxonflow/axonflow/pull/100))
  - `OpenAIProvider` now reads `OPENAI_MODEL` environment variable with `gpt-4o` fallback
  - Consistent with other providers (Anthropic, Gemini, Ollama)

### Changed

- **Code Cleanup:** Removed 450+ lines of dead code
  - Removed unused `AnthropicProvider` struct (superseded by `EnhancedAnthropicProvider`)
  - Usage package refactored with build tags for clean Community/Enterprise separation

---

## [1.1.2] - 2025-12-20

### Fixed

- **LLM Router:** Use provider's configured model instead of hardcoded defaults ([#94](https://github.com/getaxonflow/axonflow/pull/94))
  - Previously, `selectModel()` returned hardcoded model names (e.g., `gpt-3.5-turbo`, `claude-3-5-sonnet`) which caused failures when the API key didn't have access to those specific models
  - Now respects `OPENAI_MODEL`, `ANTHROPIC_MODEL`, and other provider-specific environment variables
  - Model specified in request context takes highest priority

### Changed

- Added `OPENAI_MODEL` and `ANTHROPIC_MODEL` environment variable passthrough in docker-compose.yml

---

## [1.1.1] - 2025-12-20

### Fixed

- **Self-hosted mode:** Fixed authentication bypass not working when `userToken` is empty or omitted ([#89](https://github.com/getaxonflow/axonflow/pull/89))
  - Previously, self-hosted mode required a dummy `userToken`/`apiKey` even though it should accept requests without credentials
  - Now correctly bypasses authentication when `SELF_HOSTED_MODE=true` and `SELF_HOSTED_MODE_ACKNOWLEDGED=I_UNDERSTAND_NO_AUTH` are set
  - Thanks to [@gzak](https://github.com/gzak) for the contribution

---

## [1.1.0] - 2025-12-19

**SDK Feature Parity & Terminology Update**

### Added

- **Google Gemini LLM Provider**: Native Gemini integration now available in Community edition
  - Supports Gemini Pro and Gemini Pro Vision models
  - Automatic failover and routing alongside OpenAI, Anthropic, Ollama

- **SDK Feature Parity**: All four SDKs now have complete feature parity
  - **TypeScript SDK** (v1.4.0): 85.75% test coverage
  - **Python SDK** (v0.3.0): 71.39% test coverage
  - **Java SDK** (v1.1.0): 81.9% test coverage
  - **Go SDK** (v1.5.0): 82.8% test coverage

- **LLM Interceptors** (all SDKs): Wrapper-based governance for LLM providers
  - OpenAI, Anthropic, Gemini, Ollama, AWS Bedrock interceptors
  - Gateway Mode: Two-phase policy checking with `getPolicyApprovedContext()` and `auditLLMCall()`
  - Proxy Mode: Single-call governance with `executeQuery()`

### Changed

- **Terminology**: Renamed "OSS" to "Community" across the entire codebase
  - Environment variable: `AXONFLOW_MODE=community` (previously `oss`)
  - API responses: `"mode": "community"` (previously `"oss"`)
  - Documentation updated throughout

### Breaking Changes

- **`AXONFLOW_MODE` Environment Variable**: If you were using `AXONFLOW_MODE=oss`, update to `AXONFLOW_MODE=community`
- **API Response**: The `mode` field in API responses now returns `"community"` instead of `"oss"`

### Migration Notes

To upgrade from 1.0.x:

1. Update environment variables:
   ```bash
   # Before
   AXONFLOW_MODE=oss

   # After
   AXONFLOW_MODE=community
   ```

2. Update any code that checks for `mode === "oss"` to check for `mode === "community"`

3. Update SDKs to latest versions for LLM Interceptors support

---

## [1.0.1] - 2025-12-16

### Added

- **Internal Service Authentication**: Shared secret authentication for secure agent↔orchestrator communication via `AXONFLOW_INTERNAL_SERVICE_SECRET`

### Changed

- **PII Detection**: Made critical PII blocking configurable per-policy (Aadhaar, PAN patterns)

---

## [1.0.0] - 2025-12-14

**Community Launch Release**

This is the first public release of AxonFlow, a self-hosted governance and orchestration platform for production AI systems.

### Core Platform

- **Policy Enforcement Agent**: Real-time policy enforcement with single-digit millisecond overhead
  - Static policy engine with configurable rules
  - PII detection (SSN, credit cards, PAN, Aadhaar)
  - SQL injection blocking in user inputs
  - Rate limiting and request validation

- **Multi-Agent Planning (MAP)**: Declarative agent orchestration
  - YAML-based agent configuration
  - Natural language to workflow conversion
  - Sequential and parallel execution modes
  - Error handling with fallbacks

- **MCP Connectors**: Model Context Protocol integration
  - PostgreSQL, MySQL, MongoDB, Redis, HTTP connectors (Community)
  - Salesforce, Slack, Snowflake, ServiceNow (Enterprise)

- **Gateway Mode**: Wrap existing LLM calls with governance
  - Pre-check → your LLM call → audit trail
  - Incremental adoption path for existing codebases

- **Multi-Model Routing**: Intelligent LLM provider management
  - OpenAI, Anthropic, Ollama (Community)
  - AWS Bedrock, Google Gemini (Enterprise)
  - Automatic failover and cost-based routing

### Security & Compliance

- **SQL Injection Response Scanning**: Detect SQLi payloads in MCP connector responses
  - 37 regex patterns across 8 attack categories
  - Monitoring mode by default (detect and log, configurable blocking)
  - Per-connector configuration overrides
  - Audit trail integration for compliance
  - Basic scanner (Community), Advanced ML-based scanner (Enterprise)

- **EU AI Act Compliance** (Articles 12, 13, 14, 15, 43):
  - Decision chain tracing with full audit trails
  - Transparency headers (X-AI-Decision-ID, X-AI-Model-Provider, etc.)
  - Human-in-the-Loop (HITL) workflows (Enterprise)
  - Conformity assessment endpoints (Enterprise)
  - Emergency circuit breaker (Enterprise)

- **RBI FREE-AI Framework**: Data integrity monitoring for financial AI (India)

- **SEBI AI/ML Guidelines**: Security audit trail for investment platforms (India)

### Infrastructure

- **Docker Compose Deployment**: Local development in under 5 minutes
- **Row-Level Security**: Database-level multi-tenant isolation
- **Production Migrations**: Idempotent, versioned database migrations
- **Test Coverage**: 70%+ coverage across core packages

### Documentation

- Getting Started Guide
- LLM Provider Configuration
- MCP Connector Development Guide
- Security Best Practices
- EU AI Act Compliance Guide

---

## Links

- [GitHub Repository](https://github.com/getaxonflow/axonflow)
- [Documentation](https://docs.getaxonflow.com)
- [AWS Marketplace](https://aws.amazon.com/marketplace)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)

---

**For a complete list of changes, see the [commit history](https://github.com/getaxonflow/axonflow/commits/main).**
