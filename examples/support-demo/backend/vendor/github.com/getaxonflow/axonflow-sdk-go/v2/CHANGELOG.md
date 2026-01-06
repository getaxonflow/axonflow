# Changelog

All notable changes to the AxonFlow Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-01-06

### Added

- **Sensitive Data Category**: Added `CategorySensitiveData` to `PolicyCategory` enum for policies that return `sensitive-data` category
- **Provider Restrictions for Compliance**: Support for `allowed_providers` in dynamic policy action config
  - Specify allowed providers via `DynamicPolicyAction.Config["allowed_providers"]`
  - Enables GDPR, HIPAA, and RBI compliance by restricting LLM routing to specific providers
  - Example: `Actions: []DynamicPolicyAction{{Type: "route", Config: map[string]interface{}{"allowed_providers": []string{"ollama", "azure-eu"}}}}`
- **Category field**: Added `Category` field to `CreateDynamicPolicyRequest` and `UpdateDynamicPolicyRequest`
- **DynamicPolicy fields**: Added `Category`, `Tier`, `Version`, `TenantID` fields to `DynamicPolicy` struct

### Fixed

- **Go Module Path**: Updated module path to `github.com/getaxonflow/axonflow-sdk-go/v2` for Go semantic versioning compliance
  - Go requires `/v2` suffix in module path for major versions >= 2
  - All imports now use the `/v2` path
- **ToggleDynamicPolicy HTTP Method**: Changed from PATCH to PUT to match API specification
- **Dynamic Policy Response Parsing**: Fixed `ListDynamicPolicies`, `GetDynamicPolicy`, `CreateDynamicPolicy`, `UpdateDynamicPolicy`, `ToggleDynamicPolicy`, and `GetEffectiveDynamicPolicies` to correctly parse wrapped API responses
  - API returns `{"policies": [...]}` and `{"policy": {...}}` wrappers
  - Added `dynamicPoliciesResponse` and `dynamicPolicyResponse` wrapper structs

### Migration

Update your imports from:
```go
import "github.com/getaxonflow/axonflow-sdk-go"
```

To:
```go
import "github.com/getaxonflow/axonflow-sdk-go/v2"
```

## [2.0.0] - 2026-01-05

### Breaking Changes

- **BREAKING**: Renamed `AgentURL` to `Endpoint` in `AxonFlowConfig`
- **BREAKING**: Removed `OrchestratorURL` and `PortalURL` config options (Agent now proxies all routes per ADR-026)
- **BREAKING**: Dynamic policy API path changed from `/api/v1/policies/dynamic` to `/api/v1/dynamic-policies`

### Added

- **Audit Log Reading**: Added `SearchAuditLogs()` for searching audit logs with filters (user email, client ID, time range, request type)
- **Tenant Audit Logs**: Added `GetAuditLogsByTenant()` for retrieving audit logs scoped to a specific tenant
- **Audit Types**: Added `AuditLogEntry`, `AuditSearchRequest`, `AuditQueryOptions`, and `AuditSearchResponse` types
- **PII Redaction Support**: Added `RequiresRedaction` field to `PolicyApprovalResult` (Issue #891)
  - When `true`, PII was detected with redact action and response should be processed for redaction
  - Supports new detection defaults: PII defaults to redact instead of block

### Changed

- All SDK methods now route through single Agent endpoint
- Simplified configuration - only `Endpoint` field needed
- Removed `getOrchestratorURL()` and `getPortalURL()` helper methods

### Migration Guide

**Before (v1.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    AgentURL:        "http://localhost:8080",
    OrchestratorURL: "http://localhost:8081",
    PortalURL:       "http://localhost:8082",
    ClientID:        "my-client",
    ClientSecret:    "my-secret",
})
```

**After (v2.x):**
```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     "my-client",
    ClientSecret: "my-secret",
})
```

---

## [1.17.0] - 2026-01-04

### Added

- **Portal Authentication**: Added `LoginToPortal()` and `LogoutFromPortal()` for session-based authentication
- **Portal URL Configuration**: New `PortalURL` config option for Code Governance portal endpoints
- **CSV Export**: Added `ExportCodeGovernanceDataCSV()` for CSV format exports

### Fixed

- **Code Governance Authentication**: Changed Code Governance methods to use portal session-based auth instead of API key auth

---

## [1.16.0] - 2026-01-04

### Added

- **Get Connector**: `GetConnector(id)` to retrieve details for a specific connector
- **Connector Health Check**: `GetConnectorHealth(id)` to check health status of an installed connector
- **ConnectorHealthStatus type**: New type for connector health responses
- **Orchestrator Health Check**: `OrchestratorHealthCheck()` to verify Orchestrator service health
- **Uninstall Connector**: `UninstallConnector()` to remove installed MCP connectors

### Fixed

- **Connector API Endpoints**: Fixed endpoints to use Orchestrator (port 8081) instead of Agent
  - `ListConnectors()` - Changed from Agent `/api/connectors` to Orchestrator `/api/v1/connectors`
  - `InstallConnector()` - Fixed path to `/api/v1/connectors/{id}/install`
- **Dynamic Policies Endpoint**: Changed from Agent `/api/v1/policies` to Orchestrator `/api/v1/policies/dynamic`

---

## [1.15.0] - 2026-01-04

### Added

- **Execution Replay API**: Debug governed workflows with step-by-step state capture
  - `ListExecutions()` - List executions with filtering (status, time range)
  - `GetExecution()` - Get execution with all step snapshots
  - `GetExecutionSteps()` - Get individual step snapshots
  - `GetExecutionTimeline()` - Timeline view for visualization
  - `ExportExecution()` - Export for compliance/archival
  - `DeleteExecution()` - Delete execution records

- **Cost Controls**: Budget management and LLM usage tracking
  - `CreateBudget()` / `GetBudget()` / `ListBudgets()` - Budget CRUD
  - `UpdateBudget()` / `DeleteBudget()` - Budget management
  - `GetBudgetStatus()` - Check current budget usage
  - `CheckBudget()` - Pre-request budget validation
  - `RecordUsage()` - Record LLM token usage
  - `GetUsageSummary()` - Usage analytics and reporting

---

## [1.14.0] - 2025-12-30

### Fixed

- **403 Forbidden Handling**: Properly handle HTTP 403 responses for blocked requests
  - Agent returns 403 when requests are blocked by policy
  - Previously this triggered retry logic and fail-open, causing blocked requests to appear allowed
  - Now correctly parses 403 response body and returns `Blocked=true` with proper `BlockReason`

---

## [1.13.0] - 2025-12-30

### Changed

- **Community Mode**: Credentials are now optional for self-hosted/community deployments
  - SDK can be initialized without `ClientSecret` or `LicenseKey` for community features
  - `ExecuteQuery()` and `HealthCheck()` work without credentials
  - Auth headers are only sent when credentials are configured

### Added

- `requireCredentials()` helper for enterprise feature validation
- Enterprise features (`GetPolicyApprovedContext`, `AuditLLMCall`) now validate credentials at call time

### Fixed

- Gateway Mode methods now return clear error message when called without credentials

---

## [1.12.0] - 2025-12-30

### Fixed

- Fixed JSON field names for `PolicyOverride` types to match API schema (`action_override`, `override_reason`)
- Fixed `ListPolicyOverrides()` to correctly parse wrapped response format
- Fixed `GetStaticPolicyVersions()` to correctly parse wrapped response format

> **Note:** These changes affect Enterprise users only. Community users can skip this release.

---

## [1.11.0] - 2025-12-29

### Added

- **Enterprise Policy Features**:
  - `OrganizationID` field in `CreateStaticPolicyRequest` for organization-tier policies
  - `OrganizationID` field in `ListStaticPoliciesOptions` for filtering by organization
  - `ListPolicyOverrides()` method to list all active policy overrides

- **Type Aliases** (for backward compatibility with existing code):
  - `ListStaticPoliciesRequest` = `ListStaticPoliciesOptions`
  - `CreateOverrideRequest` = `CreatePolicyOverrideRequest`
  - `GetEffectiveRequest` = `EffectivePoliciesOptions`

- **TestPatternResult Improvements**:
  - `Results` field as alias for `Matches`
  - `GetResults()` method for convenience

---

## [1.10.0] - 2025-12-29

### Added

- **Code Governance Metrics & Export APIs** (Enterprise): Compliance reporting for AI-generated code
  - `GetCodeGovernanceMetrics()` - Returns aggregated statistics (PR counts, file totals, security findings)
  - `ExportCodeGovernanceData()` - Exports PR records as JSON for auditors
  - `ExportCodeGovernanceDataCSV()` - Exports PR records as CSV

- **New Types**: `CodeGovernanceMetrics`, `ExportOptions`, `ExportResponse`

---

## [1.9.0] - 2025-12-29

### Added

- **Code Governance Git Provider APIs** (Enterprise): Create PRs from LLM-generated code
  - `ValidateGitProvider()` - Validate credentials before saving
  - `ConfigureGitProvider()` - Configure GitHub, GitLab, or Bitbucket
  - `ListGitProviders()` - List configured providers
  - `DeleteGitProvider()` - Remove a provider
  - `CreatePR()` - Create PR from generated code with audit trail
  - `ListPRs()` - List PRs with filtering
  - `GetPR()` - Get PR details
  - `SyncPRStatus()` - Sync status from Git provider

- **New Types**: `GitProviderType`, `FileAction`, `CodeFile`, `CreatePRRequest`, `CreatePRResponse`, `PRRecord`, `ListPRsOptions`, `ListPRsResponse`

- **Supported Git Providers**:
  - GitHub (Cloud and Enterprise Server)
  - GitLab (Cloud and Self-Managed)
  - Bitbucket (Cloud and Server/Data Center)

---

## [1.8.0] - 2025-12-28

### Added

- **HITL Support**: `ActionRequireApproval` for human oversight policies
  - Use with `CreateStaticPolicy()` to trigger approval workflows
  - Enterprise: Full HITL queue integration
  - Community: Auto-approves immediately

---

## [1.7.0] - 2025-12-28

### Added

- **Code Governance Support** - `CodeArtifact` type for detecting and auditing LLM-generated code (#16)
  - `CodeArtifact` struct in `PolicyEvaluationInfo` with fields:
    - `IsCodeOutput` - Whether response contains code
    - `Language` - Detected programming language (14 supported)
    - `CodeType` - Code category (function, class, script, config, snippet, module)
    - `SizeBytes` - Size of detected code in bytes
    - `LineCount` - Number of lines of code
    - `SecretsDetected` - Count of potential secrets found
    - `UnsafePatterns` - Count of unsafe code patterns
  - Automatic code detection in LLM responses
  - Supports Python, Go, TypeScript, JavaScript, Java, SQL, Ruby, Rust, C/C++, Bash, YAML, JSON, Dockerfile, Terraform

## [1.6.0] - 2025-12-25

### Added

- **Policy CRUD Methods**: Full policy management support for Unified Policy Architecture v2.0.0
  - `ListStaticPolicies()` - List policies with filtering
  - `GetStaticPolicy()` - Get single policy by ID
  - `CreateStaticPolicy()` - Create custom policy
  - `UpdateStaticPolicy()` - Update existing policy
  - `DeleteStaticPolicy()` - Delete policy
  - `ToggleStaticPolicy()` - Enable/disable policy
  - `GetEffectiveStaticPolicies()` - Get merged hierarchy
  - `TestPattern()` - Test regex pattern

- **Policy Override Methods** (Enterprise)
- **Dynamic Policy Methods**
- **New Types**: `StaticPolicy`, `DynamicPolicy`, `PolicyOverride`

## [1.5.1] - 2025-12-23

### Added

- **MAP Timeout Configuration** - New `MapTimeout` config option (default: 120s) for Multi-Agent Planning operations
  - MAP operations involve multiple LLM calls and can take 30-60+ seconds
  - Separate `mapHttpClient` with longer timeout
  - `GeneratePlan()` and `ExecutePlan()` now use the longer MAP timeout

## [1.5.0] - 2025-12-19

### Added

- **LLM Interceptors** - Transparent governance for LLM API calls (#8)
  - `WrapOpenAIClient()` for OpenAI API interception
  - `WrapAnthropicClient()` for Anthropic API interception
  - `WrapGeminiModel()` for Google Generative AI interception
  - Policy enforcement and audit logging for all providers
- Full feature parity with other SDKs for LLM interceptors

## [1.4.1] - 2025-12-15

### Added

- **Contract Testing Suite** - Validates SDK models against real API responses (#7)
  - JSON fixtures for all response types
  - Integration test workflow with GitHub Actions
- Unit tests for `parseTimeWithFallback` helper (#5)

### Fixed

- Datetime parsing with nanosecond precision (#4)
- `GeneratePlan()` and `ExecutePlan()` authentication with explicit user token (#4)

## [1.4.0] - 2025-12-10

### Changed

- Prepare for repository rename to `axonflow-sdk-go`
- Updated module path and documentation

## [1.3.0] - 2025-12-08

### Added

- **Gateway Mode API** - Support for direct LLM calls with policy enforcement (#1)
  - `GetPolicyApprovedContext()` for pre-checks
  - `AuditLLMCall()` for compliance logging
- Self-hosted mode for localhost deployments
  - Skip auth headers for localhost endpoints
  - License key optional for self-hosted
- User token parameter to `QueryConnector()` method

### Fixed

- Formatting in connectors example
- Printf format mismatch in basic example
- Nested error handling in SDK
- `PolicyEvaluationInfo.ProcessingTime` type mismatch

## [1.2.0] - 2025-12-04

### Added

- License-based authentication as primary method
- License key authentication support

## [1.1.0] - 2025-11-27

### Added

- License key authentication support
- Comprehensive examples with license key authentication

## [1.0.0] - 2025-10-27

### Added

- Initial release of AxonFlow Go SDK
- Core client with `ExecuteQuery()` for governed AI calls
- Policy enforcement with `PolicyViolationError`
- Multi-agent planning with `GeneratePlan()` and `ExecutePlan()`
- MCP connector operations (`ListConnectors`, `InstallConnector`, `QueryConnector`)
- Comprehensive type definitions
- Retry logic with exponential backoff
- Response caching with TTL
