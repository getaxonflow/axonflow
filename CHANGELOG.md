# Changelog

All notable changes to AxonFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
