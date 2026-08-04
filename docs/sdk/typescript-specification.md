# TypeScript SDK Technical Specification

**Last Updated:** February 2026

**SDK Version:** 9.0.0 | **Platform Version:** 9.14.0

**Status:** Production Ready

---

## Architecture Overview

The AxonFlow TypeScript SDK provides a single `AxonFlow` client class that communicates with the AxonFlow Agent and Orchestrator services. The SDK implements two integration modes (Proxy Mode and Gateway Mode), plus full CRUD operations for policies, connectors, workflows, budgets, and more.

### Design Principles

1. **Node.js 18+** -- Uses native `fetch` and `Buffer`; not designed for browser environments.
2. **Client Credentials Auth** -- `clientId`/`clientSecret` sent as `Authorization: Basic` header.
3. **Fail-Open** -- Gracefully degrades if the AxonFlow service is unavailable (production mode).
4. **Typed Errors** -- Custom error classes for policy violations, authentication failures, timeouts, and more.
5. **Dual Build** -- Ships both CommonJS (`dist/cjs/`) and ESM (`dist/esm/`) builds.

## Component Architecture

```
┌──────────────────────────────────────────────┐
│             Application Code                 │
├──────────────────────────────────────────────┤
│            TypeScript SDK Layer              │
│  ┌────────────────────────────────────────┐  │
│  │         AxonFlow Client                │  │
│  │  - Proxy Mode (proxyLLMCall)           │  │
│  │  - Gateway Mode (getPolicyApproved-    │  │
│  │    Context + auditLLMCall)             │  │
│  │  - Policy CRUD (static + dynamic)      │  │
│  │  - Multi-Agent Planning (MAP)          │  │
│  │  - Connector management (MCP)          │  │
│  │  - Workflow Control Plane (WCP)        │  │
│  │  - Cost controls (budgets + usage)     │  │
│  │  - Execution replay + audit logs       │  │
│  │  - Code governance (Enterprise)        │  │
│  └────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────┐  │
│  │     Typed Error Classes                │  │
│  │  - PolicyViolationError                │  │
│  │  - AuthenticationError                 │  │
│  │  - TimeoutError / RateLimitError       │  │
│  │  - APIError / ConnectionError          │  │
│  │  - ConfigurationError                  │  │
│  │  - ConnectorError                      │  │
│  │  - PlanExecutionError                  │  │
│  │  - VersionConflictError                │  │
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│         AxonFlow Control Plane               │
│    (Agent + Orchestrator Services)           │
└──────────────────────────────────────────────┘
```

## API Specification

### Client Initialization

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'my-org',
  clientSecret: 'my-license-key',
  debug: true,
});
```

### Configuration

```typescript
interface AxonFlowConfig {
  clientId?: string;          // Authentication identity
  clientSecret?: string;      // Authentication credential
  endpoint?: string;          // Agent URL (default: http://localhost:8080)
  mode?: 'sandbox' | 'production'; // Default: production when credentials provided
  tenant?: string;            // Deprecated; use clientId instead
  debug?: boolean;            // Enable debug logging (default: false)
  timeout?: number;           // Request timeout in ms (default: 30000)
  mapTimeout?: number;        // MAP timeout in ms (default: 120000)
  retry?: {
    enabled: boolean;         // Default: true
    maxAttempts?: number;     // Default: 3
    delay?: number;           // Initial delay in ms (default: 1000)
  };
  cache?: {
    enabled: boolean;         // Default: true
    ttl?: number;             // Cache TTL in ms (default: 60000)
  };
}
```

**Validation rules:**
- Providing `clientSecret` without `clientId` throws a `ConfigurationError`.
- When neither `clientId` nor `clientSecret` is provided, the SDK operates in community mode with no authentication headers.

### Core Methods

#### proxyLLMCall() -- Proxy Mode

Routes a query through the AxonFlow Agent, which handles policy enforcement, LLM provider routing, and response processing.

```typescript
async proxyLLMCall(options: ExecuteQueryOptions): Promise<ExecuteQueryResponse>

interface ExecuteQueryOptions {
  userToken?: string;                         // User token (defaults to "anonymous")
  query: string;                              // Query or prompt
  requestType: 'chat' | 'sql' | 'mcp-query' | 'multi-agent-plan' | 'execute-plan';
  context?: Record<string, unknown>;          // Additional context
}

interface ExecuteQueryResponse {
  success: boolean;
  data?: unknown;
  result?: string;
  planId?: string;
  requestId?: string;
  metadata: Record<string, unknown>;
  error?: string;
  blocked: boolean;
  blockReason?: string;
  policyInfo?: PolicyInfo;
  budgetInfo?: BudgetInfo;
}
```

#### getPolicyApprovedContext() -- Gateway Mode Pre-Check

Evaluates policies against a query before making a direct LLM call.

```typescript
async getPolicyApprovedContext(
  options: PolicyApprovalOptions
): Promise<PolicyApprovalResult>

interface PolicyApprovalOptions {
  userToken: string;
  query: string;
  dataSources?: string[];
  context?: Record<string, unknown>;
}

interface PolicyApprovalResult {
  contextId: string;
  approved: boolean;
  requiresRedaction?: boolean;
  approvedData: Record<string, unknown>;
  policies: string[];
  rateLimitInfo?: RateLimitInfo;
  expiresAt: Date;
  blockReason?: string;
}
```

#### auditLLMCall() -- Gateway Mode Audit

Logs the result of a direct LLM call for compliance tracking.

```typescript
async auditLLMCall(options: AuditOptions): Promise<AuditResult>

interface AuditOptions {
  contextId: string;            // From getPolicyApprovedContext()
  responseSummary: string;
  provider: string;             // e.g., "openai", "anthropic"
  model: string;                // e.g., "gpt-4", "claude-opus-4"
  tokenUsage: TokenUsage;
  latencyMs: number;
  metadata?: Record<string, unknown>;
}

interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

interface AuditResult {
  success: boolean;
  auditId: string;
}
```

### Health Checks

```typescript
// Check Agent health
async healthCheck(): Promise<HealthStatus>

// Check Orchestrator health
async orchestratorHealthCheck(): Promise<HealthStatus>

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version?: string;
  uptime?: string;
  components?: Record<string, { status: string; message?: string }>;
}
```

### Multi-Agent Planning (MAP)

```typescript
async generatePlan(
  query: string,
  domain?: string,
  userToken?: string,
  options?: GeneratePlanOptions
): Promise<PlanResponse>

async executePlan(planId: string, userToken?: string): Promise<PlanExecutionResponse>
async getPlanStatus(planId: string): Promise<PlanExecutionResponse>
async cancelPlan(planId: string, reason?: string): Promise<CancelPlanResponse>
async updatePlan(planId: string, request: UpdatePlanRequest): Promise<UpdatePlanResponse>
async resumePlan(planId: string, approved?: boolean): Promise<ResumePlanResponse>
async rollbackPlan(planId: string, targetVersion: number): Promise<RollbackPlanResponse>
async getPlanVersions(planId: string): Promise<PlanVersionsResponse>
```

### Policy Management

#### Static Policies (Regex-based)

```typescript
async listStaticPolicies(options?: ListStaticPoliciesOptions): Promise<StaticPolicy[]>
async getStaticPolicy(id: string): Promise<StaticPolicy>
async createStaticPolicy(policy: CreateStaticPolicyRequest): Promise<StaticPolicy>
async updateStaticPolicy(id: string, policy: UpdateStaticPolicyRequest): Promise<StaticPolicy>
async deleteStaticPolicy(id: string): Promise<void>
async toggleStaticPolicy(id: string, enabled: boolean): Promise<StaticPolicy>
async getEffectiveStaticPolicies(options?: EffectivePoliciesOptions): Promise<StaticPolicy[]>
async testPattern(pattern: string, testInputs: string[]): Promise<TestPatternResult>
async getStaticPolicyVersions(id: string): Promise<PolicyVersion[]>
```

#### Dynamic Policies (Context-aware)

```typescript
async listDynamicPolicies(options?: ListDynamicPoliciesOptions): Promise<DynamicPolicy[]>
async getDynamicPolicy(id: string): Promise<DynamicPolicy>
async createDynamicPolicy(policy: CreateDynamicPolicyRequest): Promise<DynamicPolicy>
async updateDynamicPolicy(id: string, policy: UpdateDynamicPolicyRequest): Promise<DynamicPolicy>
async deleteDynamicPolicy(id: string): Promise<void>
async toggleDynamicPolicy(id: string, enabled: boolean): Promise<DynamicPolicy>
async getEffectiveDynamicPolicies(options?: EffectivePoliciesOptions): Promise<DynamicPolicy[]>
```

#### Policy Overrides

```typescript
async createPolicyOverride(policyId: string, override: CreatePolicyOverrideRequest): Promise<PolicyOverride>
async deletePolicyOverride(policyId: string): Promise<void>
async listPolicyOverrides(): Promise<PolicyOverride[]>
```

### MCP Connectors

```typescript
async listConnectors(): Promise<ConnectorMetadata[]>
async installConnector(request: ConnectorInstallRequest): Promise<void>
async uninstallConnector(connectorName: string): Promise<void>
async getConnector(connectorId: string): Promise<ConnectorMetadata>
async getConnectorHealth(connectorId: string): Promise<ConnectorHealthStatus>
async queryConnector(connectorName: string, ...): Promise<any>
async mcpQuery(options: { connector: string; tool: string; arguments: Record<string, unknown> }): Promise<any>
async mcpExecute(options: { connector: string; tool: string; arguments: Record<string, unknown> }): Promise<any>
```

### Workflow Control Plane (WCP)

```typescript
async createWorkflow(request: CreateWorkflowRequest): Promise<CreateWorkflowResponse>
async getWorkflow(workflowId: string): Promise<WorkflowStatusResponse>
async stepGate(workflowId: string, stepId: string, request: StepGateRequest): Promise<StepGateResponse>
async listWorkflows(options?: ListWorkflowsOptions): Promise<ListWorkflowsResponse>
async completeWorkflow(workflowId: string): Promise<void>
async abortWorkflow(workflowId: string, reason?: string): Promise<void>
async approveStep(workflowId: string, stepId: string): Promise<ApproveStepResponse>
async rejectStep(workflowId: string, stepId: string, reason?: string): Promise<RejectStepResponse>
async getPendingApprovals(options?: PendingApprovalsOptions): Promise<PendingApprovalsResponse>
```

### Cost Controls

```typescript
async createBudget(request: CreateBudgetRequest): Promise<Budget>
async getBudget(budgetId: string): Promise<Budget>
async listBudgets(options?: ListBudgetsOptions): Promise<BudgetsResponse>
async updateBudget(budgetId: string, request: UpdateBudgetRequest): Promise<Budget>
async deleteBudget(budgetId: string): Promise<void>
async getBudgetStatus(budgetId: string): Promise<BudgetStatus>
async getBudgetAlerts(budgetId: string): Promise<BudgetAlertsResponse>
async checkBudget(request: BudgetCheckRequest): Promise<BudgetDecision>
async getUsageSummary(period?: string): Promise<UsageSummary>
async getUsageBreakdown(groupBy: string, period?: string): Promise<UsageBreakdown>
async listUsageRecords(options?: ListUsageRecordsOptions): Promise<UsageRecordsResponse>
async getPricing(provider?: string, model?: string): Promise<PricingListResponse>
```

### Execution Replay

```typescript
async listExecutions(options?: ListExecutionsOptions): Promise<ListExecutionsResponse>
async getExecution(executionId: string): Promise<ExecutionDetail>
async getExecutionSteps(executionId: string): Promise<ExecutionSnapshot[]>
async getExecutionTimeline(executionId: string): Promise<TimelineEntry[]>
async exportExecution(executionId: string, options?: ExecutionExportOptions): Promise<any>
async deleteExecution(executionId: string): Promise<void>
```

### Audit Logs

```typescript
async searchAuditLogs(request?: AuditSearchRequest): Promise<AuditSearchResponse>
async getAuditLogsByTenant(tenantId: string, options?: AuditQueryOptions): Promise<AuditSearchResponse>
```

### Webhooks

```typescript
async createWebhook(request: CreateWebhookRequest): Promise<WebhookSubscription>
async getWebhook(webhookId: string): Promise<WebhookSubscription>
async updateWebhook(webhookId: string, request: UpdateWebhookRequest): Promise<WebhookSubscription>
async deleteWebhook(webhookId: string): Promise<void>
async listWebhooks(): Promise<ListWebhooksResponse>
```

## Error Handling

All errors extend the base `AxonFlowError` class:

| Error Class | When Thrown | Key Properties |
|-------------|------------|----------------|
| `ConfigurationError` | Invalid SDK configuration | `message` |
| `ConnectionError` | Network or DNS failure | `cause` |
| `AuthenticationError` | Invalid credentials (401/403) | `message` |
| `PolicyViolationError` | Request blocked by policy | `blockReason`, `policies` |
| `RateLimitError` | Rate limit exceeded | `limit`, `remaining`, `resetAt` |
| `TimeoutError` | Request timed out | `timeoutMs` |
| `APIError` | Non-2xx HTTP response | `statusCode`, `statusText`, `body` |
| `ConnectorError` | MCP connector failure | `connector`, `operation` |
| `PlanExecutionError` | MAP step failure | `planId`, `step` |
| `VersionConflictError` | Optimistic concurrency conflict (409) | `planId`, `expectedVersion`, `currentVersion` |

```typescript
import { PolicyViolationError, AuthenticationError } from '@axonflow/sdk';

try {
  const response = await client.proxyLLMCall({
    query: 'My SSN is 123-45-6789',
    requestType: 'chat',
  });
} catch (error) {
  if (error instanceof PolicyViolationError) {
    console.error('Policy blocked:', error.blockReason);
    console.error('Violated policies:', error.policies);
  }
}
```

## Request Flow

### Proxy Mode

```
1. Application calls client.proxyLLMCall(options)
2. SDK sends POST /api/request to Agent with auth headers
3. Agent evaluates static + dynamic policies
4. Agent checks budget limits (if configured)
5. Agent routes to configured LLM provider
6. Agent processes response (PII redaction, code analysis)
7. SDK returns ExecuteQueryResponse with policyInfo and budgetInfo
```

### Gateway Mode

```
1. Application calls client.getPolicyApprovedContext(options)
2. SDK sends pre-check request to Agent
3. Agent returns PolicyApprovalResult with contextId
4. Application makes direct LLM call (approved queries only)
5. Application calls client.auditLLMCall(options) with contextId
6. Agent logs audit entry for compliance
```

## Security

### Credential Handling

- Credentials are sent as `Authorization: Basic base64(clientId:clientSecret)` on every request.
- The SDK also derives tenant from Basic auth: {clientId}` for multi-tenant routing.
- Credentials are never logged, even when `debug: true` is enabled.
- No data is persisted by the SDK; all state lives server-side.

### Network

- HTTPS is recommended for all production deployments.
- All requests include `Content-Type: application/json`.
- Timeouts are enforced via `AbortSignal.timeout()` to prevent hanging connections.

## Compatibility

| Requirement | Version |
|-------------|---------|
| Node.js | 18+ |
| TypeScript | 4.7+ (optional; JavaScript is also supported) |

## Exports

The SDK exports from `@axonflow/sdk`:

- **`AxonFlow`** -- The client class (also available as `default` export).
- **`VERSION`** -- SDK version string (`'9.0.0'`).
- **`wasRedacted()`** -- Utility to check if a connector response was redacted.
- **`WorkflowHelpers`** -- Helper utilities for workflow operations.
- **`ExecutionHelpers`** -- Helper utilities for unified execution operations.
- **Error classes** -- All typed error classes listed above.
- **Type exports** -- All TypeScript interfaces and types for configuration, requests, responses, policies, planning, connectors, workflows, cost controls, code governance, execution replay, and MAS FEAT compliance.

---

*This specification describes the AxonFlow TypeScript SDK v9.0.0 API surface. For architecture details, see [TypeScript Architecture](typescript-architecture.md). For a quick-start guide, see [TypeScript Quickstart](typescript-quickstart.md).*
