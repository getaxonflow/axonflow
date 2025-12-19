# Changelog

All notable changes to AxonFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [1.0.1] - 2025-12-16

### Added

- **Internal Service Authentication**: Shared secret authentication for secure agent↔orchestrator communication via `AXONFLOW_INTERNAL_SERVICE_SECRET`

### Changed

- **PII Detection**: Made critical PII blocking configurable per-policy (Aadhaar, PAN patterns)

---

## [1.1.0] - 2025-12-19

**SDK Feature Parity & Terminology Update**

### Added

- **Google Gemini LLM Provider**: Native Gemini integration now available in Community edition
  - Supports Gemini Pro and Gemini Pro Vision models
  - Automatic failover and routing alongside OpenAI, Anthropic, Ollama

- **SDK Feature Parity**: All four SDKs now have complete feature parity
  - **TypeScript SDK** (v1.4.0): 85.75% test coverage
  - **Python SDK** (v1.4.0): 71.39% test coverage
  - **Java SDK** (v1.4.0): 81.9% test coverage
  - **Go SDK** (v1.4.0): 82.8% test coverage

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

3. Update SDKs to v1.4.0 for LLM Interceptors support

---

## Pre-release Development History

The following versions were internal development milestones leading up to v1.0.0.

## [1.0.12] - 2025-11-07

### Added

- **AWS Marketplace Production Release**: Complete CloudFormation template for marketplace deployment
  - License key authentication via AWS Secrets Manager
  - LLM API keys (OpenAI + Anthropic) via Secrets Manager (no plaintext secrets)
  - AWS Service Discovery for reliable agent↔orchestrator communication
  - CloudWatch Alarms for unhealthy hosts, database, and errors
  - SNS topic for production alerting
  - Region-aware image management (eliminates cross-region transfer costs)
  - Git-based version management (single source of truth)
- **CloudFormation Enhancements**:
  - 43 resources (5 new for monitoring and service discovery)
  - 20 parameters (3 new, all secrets use `NoEcho` for security)
  - Comprehensive outputs for debugging and integration
- **Redis Integration**: Distributed rate limiting with Redis URL parameter
- **Helper Scripts**: Autonomous AWS Marketplace testing and stack monitoring tools

### Fixed

- **All 16 AWS Marketplace Issues** (comprehensive systematic fix):
  - ✅ Issue #1-4: DNS retry logic, security groups, networking
  - ✅ Issue #5: License key environment variable injection
  - ✅ Issue #6: LLM API keys from Secrets Manager
  - ✅ Issue #7: Service Discovery (eliminates ALB routing loop)
  - ✅ Issue #8: Route table naming clarity for debugging
  - ✅ Issue #9-11, 14-16: Outputs, auto-scaling, logs, backup, grace periods
  - ✅ Issue #10: CloudWatch Alarms with SNS notifications
  - ✅ Issue #12: Cross-region ECR image access fix
  - ✅ Issue #13: Version management from git tags
- **Build System**: Dynamic version from git tags and region auto-detection
- **Critical Networking**: Added Internet Gateway route for marketplace VPC
- **Security Groups**: Fixed 7-day deployment blocker for orchestrator connectivity
- **HTTP Servers**: Fixed agent and orchestrator HTTP server startup blocking
- **CloudFormation Validation**: Template validates successfully with all 43 resources

### Changed

- **Version Management**: Git tags are now single source of truth for versioning
- **Image Registry**: Region-aware ECR registry URLs (no more cross-region costs)
- **Template Version**: Updated to v1.0.12 with comprehensive marketplace fixes

### Security

- **No Plaintext Secrets**: All API keys and credentials use AWS Secrets Manager
- **NoEcho Parameters**: Sensitive CloudFormation parameters hidden from console/CLI
- **Service Discovery**: Secure internal communication without exposing ALB endpoints

---

## [1.0.11] - 2025-11-06

### Added

- **AWS Marketplace Integration**: CloudFormation template with AWS Marketplace metering
  - Hourly usage reporting to AWS for billing
  - Multi-tenant metering architecture
  - Graceful degradation when metering unavailable
- **MCP Connectors**: Production-ready connectors for enterprise integrations
  - **Slack**: Workspace messaging and notifications
  - **Salesforce**: CRM data access and operations
  - **Snowflake**: Data warehouse queries with key-pair authentication
- **Test Coverage Expansion**:
  - Comprehensive tests for connector marketplace handlers (23 tests, 85.9% avg coverage)
  - Integration tests for PostgreSQL connector persistence
  - MCP connector processor tests (100% for 9/11 functions)
  - Response processor and result aggregator tests (90%+ coverage)
- **Documentation**:
  - Technical documentation index for easy navigation
  - Comprehensive guides for Redis, Audit Modes, CI/CD, and Testing
  - License key onboarding documentation
  - Deployment architectures comparison (ECS Fargate vs EC2)

### Fixed

- **Multi-Instance Deployments**:
  - Fixed ECR credentials persistence across SSM sessions
  - Fixed ECR login for multi-instance deployments
  - Fixed namespace collision in deployment scripts
  - Fixed AWS CLI installation for multi-instance setups
- **Migrations**:
  - Fixed migration 006 idempotency with conditional ALTER TABLE
  - Fixed migration 014-015 to handle legacy schema
  - Fixed migration 017 conflicts with migration 006
  - Fixed migration 020 to upgrade old `schema_migrations` table
- **CloudFormation**: Fixed AWS Marketplace deployment issues
- **PostgreSQL**: Fixed default version to 15.14 for cross-region compatibility

### Changed

- **Orchestrator Test Coverage**: Improved from 41.6% → 52.0%
- **Deployment Script**: Enhanced `--target` parameter handling
- **Rolling Deployment**: Added retry logic and error capture for robustness

### Security

- **Snowflake Authentication**: SERVICE account support with key-pair authentication
- **Deployment Security**: Fixed production deployment script parameter validation

---

## [1.0.10] - 2025-11-01

### Added

- **Snowflake Connector**: Full support for Snowflake data warehouse integration
  - Key-pair authentication for SERVICE accounts
  - Comprehensive test coverage for configuration and authentication
  - Deployment script support for Snowflake credentials
- **Database Tools**: Schema verification and migration system guide
  - Complete migration system documentation
  - Schema verification for safe deployments

### Fixed

- **Rolling Deployment**: Properly handles scale-down operations
- **Migrations**: Fixed idempotency issues in migrations 014-015
  - Handles legacy `policy_violations.timestamp` column
  - Handles legacy `orchestrator_audit_logs` schema
  - Handles legacy `dynamic_policies` schema

### Changed

- **Test Coverage**: Achieved 52% orchestrator coverage (up from 41%)
- **Deployment Logging**: Enhanced logging for better troubleshooting
- **Tenant Isolation**: Fixed tenant isolation test with separate tokens

---

## [1.0.9] - 2025-10-28

### Added

- **Comprehensive CI/CD Pipeline**: Full repository automation
  - Automated testing for agent and orchestrator packages
  - Coverage enforcement (minimum 70% per file)
  - GitHub Actions workflows for continuous integration
- **Unit Tests**: Node enforcement and migration helper tests

### Fixed

- **CloudFormation**: Fixed circular dependency between CustomerPortalSecurityGroup and DBSecurityGroup
- **Customer Portal**: Fixed DATABASE environment variable naming
- **ECR Naming**: Fixed image naming with `axonflow-` prefix mapping
- **Migration Helpers**: Fixed schema_migrations table upgrade logic

### Changed

- **Test Coverage**: Achieved 50.7% → 52.0% orchestrator coverage
- **.gitignore**: Added `*.backup` pattern to exclude backup files

---

## [1.0.8] - 2025-10-20

### Added

- **Example Workflows**: 10 production-ready workflow examples
  - Simple sequential workflows
  - Parallel execution with MAP
  - Conditional logic (if/else)
  - Error handling with fallbacks
  - Data pipeline ETL workflows
  - Multi-step approval chains
- **Monitoring**: Autonomous deployment monitoring script
  - Deep ECS task inspection
  - Real-time deployment status
  - Automated health checks

### Fixed

- **ECR Repository Validation**: Fixed naming bug
- **ECR Image Naming**: Complete fix for hyphen vs slash issues
- **Customer Portal**: Fixed database access (environment vars + security group)
- **Validation Script**: Fixed ECR repository naming with `axonflow-` prefix

### Changed

- **Component Naming**: Renamed 'dashboard' to 'customer-portal' for consistency
- **Docker Compose**: Fixed orchestrator build context
- **Build Script**: Enhanced validation to accept customer-portal component

---

## [1.0.7] - 2025-10-15

### Added

- **Community Launch Preparation**: Docker Compose quickstart for local development
  - README overhaul with competitive positioning
  - Quick start guide (<5 minutes setup)
  - Self-hosted mode documentation
- **Customer Portal**: Added configuration to staging and production environments
- **CloudFormation**: Customer Portal integration with Agent + Orchestrator

### Fixed

- **ECR Image URLs**: Removed registry_prefix causing double 'axonflow' directory
- **yq Handling**: Fixed "null" handling in ECR registry URL construction
- **Migration 011**: Allow deployment without `axonflow_app` user

### Changed

- **Roadmap**: Updated master roadmap with Community launch status
- **Test Coverage**: Updated documentation with orchestrator integration tests (70.4%)

---

## Migration Notes

### Upgrading to 1.0.12

**Breaking Changes:**
- None (backward compatible with 1.0.11)

**New Requirements:**
- AWS Secrets Manager for license keys (if using AWS Marketplace)
- CloudWatch Alarms SNS topic (optional but recommended)
- Service Discovery namespace (created automatically)

**Database Migrations:**
- Migrations 006-020 will run automatically on startup
- No manual intervention required

### Upgrading to 1.0.11

**Breaking Changes:**
- None (backward compatible with 1.0.10)

**New Requirements:**
- AWS Marketplace entitlement (if using Marketplace deployment)
- Snowflake key-pair credentials (if using Snowflake connector)

**Database Migrations:**
- Run migrations 014-017 for new connector features
- Backup database before upgrading (recommended)

### Upgrading from 1.0.9 to 1.0.10

**Database Migrations:**
- Migrations 014-015 handle legacy schema automatically
- Safe to run on existing deployments

**Deployment Changes:**
- Rolling deployment now requires `--target` parameter
- Use configuration-driven deployment scripts

---

## Links

- [GitHub Repository](https://github.com/axonflow/axonflow)
- [Documentation](https://docs.getaxonflow.com)
- [AWS Marketplace](https://aws.amazon.com/marketplace)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)

---

**For a complete list of changes, see the [commit history](https://github.com/axonflow/axonflow/commits/main).**
