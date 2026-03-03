# AxonFlow TypeScript SDK Architecture

**Last Updated:** February 2026

**SDK Version:** v3.8.0 | **Platform Version:** v4.8.0

---

## Overview

The AxonFlow TypeScript SDK (`@axonflow/sdk`) provides a typed client for integrating AI governance into Node.js applications. It communicates with the AxonFlow Agent and Orchestrator services to enforce policies, manage connectors, handle Multi-Agent Planning (MAP), and audit LLM interactions.

The SDK supports two primary integration modes:

- **Proxy Mode** -- AxonFlow routes LLM calls through its Agent, applying policies transparently.
- **Gateway Mode** -- Your application makes direct LLM calls while using AxonFlow for pre-check policy approval and post-call auditing.

## Core Design Principles

1. **Single Client** -- One `AxonFlow` class handles all interactions (proxy, gateway, connectors, planning, policies, workflows, cost controls).
2. **Client Credentials Auth** -- Authentication uses `clientId` and `clientSecret`, sent as `Authorization: Basic` headers.
3. **Fail-Open by Default** -- Production mode degrades gracefully if the AxonFlow service is unavailable.
4. **TypeScript-First** -- Full type definitions for all request/response types, error classes, and configuration options.
5. **Node.js Runtime** -- Requires Node.js 18+ (uses native `fetch`, `Buffer`, `AbortSignal.timeout`).

## Package Structure

```
@axonflow/sdk/
├── src/
│   ├── index.ts              # Public exports (AxonFlow, types, errors, VERSION)
│   ├── client.ts             # AxonFlow client class (all methods)
│   ├── errors.ts             # Typed error classes
│   └── types/
│       ├── config.ts          # AxonFlowConfig interface
│       ├── gateway.ts         # Gateway Mode types (PolicyApprovalResult, AuditOptions, etc.)
│       ├── proxy.ts           # Proxy Mode types (ExecuteQueryOptions, ExecuteQueryResponse, etc.)
│       ├── policies.ts        # Static/Dynamic policy CRUD types
│       ├── planning.ts        # Multi-Agent Planning (MAP) types
│       ├── connector.ts       # MCP connector types
│       ├── workflows.ts       # Workflow Control Plane (WCP) types
│       ├── cost-controls.ts   # Budget and usage tracking types
│       ├── code-governance.ts # Git provider and PR types (Enterprise)
│       ├── execution-replay.ts # Execution history types
│       ├── execution.ts       # Unified execution types
│       └── masfeat.ts         # MAS FEAT compliance types (Enterprise)
├── dist/
│   ├── cjs/                   # CommonJS build
│   └── esm/                   # ES Module build
├── package.json
└── tsconfig.json
```

## Client Class

The `AxonFlow` class is the single entry point for all SDK functionality.

### Initialization

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'my-org',
  clientSecret: 'my-license-key',
});
```

### Configuration Interface

```typescript
interface AxonFlowConfig {
  clientId?: string;          // Authentication identity (X-Client-Id)
  clientSecret?: string;      // Authentication credential (X-Client-Secret)
  endpoint?: string;          // AxonFlow Agent URL (default: https://staging-eu.getaxonflow.com)
  mode?: 'sandbox' | 'production'; // Deployment mode
  tenant?: string;            // Multi-tenant routing context (deprecated; use clientId)
  debug?: boolean;            // Enable debug logging (default: false)
  timeout?: number;           // Request timeout in ms (default: 30000)
  mapTimeout?: number;        // MAP operation timeout in ms (default: 120000)
  retry?: {
    enabled: boolean;
    maxAttempts?: number;     // Default: 3
    delay?: number;           // Default: 1000ms
  };
  cache?: {
    enabled: boolean;
    ttl?: number;             // Cache TTL in ms (default: 60000)
  };
}
```

### Authentication

The SDK sends credentials as an `Authorization: Basic` header using base64-encoded `clientId:clientSecret`. It also sends `X-Tenant-ID` set to the `clientId` value for multi-tenant routing.

For Community Edition (self-hosted) deployments without authentication, you can omit `clientId` and `clientSecret`. The SDK defaults to `"community"` as the effective client ID.

## Integration Modes

### Proxy Mode

AxonFlow acts as a proxy between your application and the LLM provider. The Agent handles policy enforcement, LLM routing, and response processing.

```typescript
const response = await client.proxyLLMCall({
  userToken: 'user-123',
  query: 'Explain quantum computing',
  requestType: 'chat',
  context: { provider: 'openai', model: 'gpt-4' },
});

if (response.success) {
  console.log('Response:', response.data);
  console.log('Policies evaluated:', response.policyInfo?.policiesEvaluated);
}
```

**Request types:** `'chat'`, `'sql'`, `'mcp-query'`, `'multi-agent-plan'`, `'execute-plan'`

### Gateway Mode

Your application makes direct LLM calls. AxonFlow provides pre-call policy checks and post-call audit logging.

```typescript
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Step 1: Pre-check -- get policy approval
const ctx = await client.getPolicyApprovedContext({
  userToken: 'user-123',
  query: prompt,
});

if (!ctx.approved) {
  throw new Error(`Query blocked: ${ctx.blockReason}`);
}

// Step 2: Make direct LLM call
const start = Date.now();
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: prompt }],
});
const latencyMs = Date.now() - start;

// Step 3: Audit the call
await client.auditLLMCall({
  contextId: ctx.contextId,
  responseSummary: response.choices[0].message.content?.substring(0, 100) || '',
  provider: 'openai',
  model: 'gpt-4',
  tokenUsage: {
    promptTokens: response.usage?.prompt_tokens || 0,
    completionTokens: response.usage?.completion_tokens || 0,
    totalTokens: response.usage?.total_tokens || 0,
  },
  latencyMs,
});
```

## Method Categories

The `AxonFlow` client exposes methods across several functional areas:

| Category | Key Methods | Description |
|----------|-------------|-------------|
| **Proxy Mode** | `proxyLLMCall()` | Route LLM calls through AxonFlow Agent |
| **Gateway Mode** | `getPolicyApprovedContext()`, `auditLLMCall()` | Pre-check and audit direct LLM calls |
| **Health** | `healthCheck()`, `orchestratorHealthCheck()` | Check Agent and Orchestrator status |
| **Static Policies** | `listStaticPolicies()`, `createStaticPolicy()`, `updateStaticPolicy()`, `deleteStaticPolicy()`, `toggleStaticPolicy()`, `testPattern()` | CRUD and management of regex-based policies |
| **Dynamic Policies** | `listDynamicPolicies()`, `createDynamicPolicy()`, `updateDynamicPolicy()`, `deleteDynamicPolicy()`, `toggleDynamicPolicy()` | CRUD for context-aware policies |
| **Policy Overrides** | `createPolicyOverride()`, `deletePolicyOverride()`, `listPolicyOverrides()` | Per-tenant policy overrides |
| **Multi-Agent Planning** | `generatePlan()`, `executePlan()`, `getPlanStatus()`, `cancelPlan()`, `updatePlan()`, `resumePlan()`, `rollbackPlan()`, `getPlanVersions()` | MAP lifecycle |
| **Connectors** | `listConnectors()`, `installConnector()`, `uninstallConnector()`, `queryConnector()`, `mcpQuery()`, `mcpExecute()` | MCP connector management |
| **Workflows** | `createWorkflow()`, `getWorkflow()`, `stepGate()`, `listWorkflows()`, `approveStep()`, `rejectStep()`, `getPendingApprovals()` | Workflow Control Plane (WCP) |
| **Cost Controls** | `createBudget()`, `getBudget()`, `checkBudget()`, `getUsageSummary()`, `getUsageBreakdown()`, `getPricing()` | Budget and usage management |
| **Execution Replay** | `listExecutions()`, `getExecution()`, `getExecutionTimeline()`, `exportExecution()` | Execution history and audit |
| **Audit Logs** | `searchAuditLogs()`, `getAuditLogsByTenant()` | Audit log queries |
| **Code Governance** | `configureGitProvider()`, `createPR()`, `listPRs()` | Git-based code governance (Enterprise) |
| **Webhooks** | `createWebhook()`, `updateWebhook()`, `deleteWebhook()`, `listWebhooks()` | Event webhook subscriptions |

## Error Handling

The SDK provides typed error classes that extend a common `AxonFlowError` base:

```typescript
import {
  AxonFlowError,
  ConfigurationError,
  ConnectionError,
  PolicyViolationError,
  AuthenticationError,
  RateLimitError,
  TimeoutError,
  APIError,
  ConnectorError,
  PlanExecutionError,
  VersionConflictError,
} from '@axonflow/sdk';

try {
  const response = await client.proxyLLMCall({ ... });
} catch (error) {
  if (error instanceof PolicyViolationError) {
    console.log('Blocked:', error.blockReason, error.policies);
  } else if (error instanceof AuthenticationError) {
    console.log('Auth failed:', error.message);
  } else if (error instanceof TimeoutError) {
    console.log('Timed out after', error.timeoutMs, 'ms');
  } else if (error instanceof APIError) {
    console.log('API error:', error.statusCode, error.body);
  }
}
```

## Request Flow

### Proxy Mode Flow

```
Application
  └─> client.proxyLLMCall(options)
        └─> POST /api/request (Agent)
              ├─ Policy evaluation (static + dynamic)
              ├─ PII detection and redaction
              ├─ Budget check
              ├─ LLM provider routing
              └─ Response processing
        └─> ExecuteQueryResponse (with policyInfo, budgetInfo)
```

### Gateway Mode Flow

```
Application
  ├─> client.getPolicyApprovedContext(options)
  │     └─> Agent pre-check endpoint
  │     └─> PolicyApprovalResult (contextId, approved, policies)
  │
  ├─> Direct LLM call (OpenAI, Anthropic, etc.)
  │
  └─> client.auditLLMCall(options)
        └─> Agent audit endpoint
        └─> AuditResult (auditId, success)
```

## Compatibility

| Requirement | Minimum Version |
|-------------|----------------|
| Node.js | 18+ |
| TypeScript | 4.7+ (optional) |

> **Note:** The SDK is designed for Node.js server-side use. It relies on `Buffer` and native `fetch` (Node.js 18+). Browser usage is not supported.

---

*This document describes the architecture of the AxonFlow TypeScript SDK v3.8.0. For quick-start instructions, see [TypeScript Quickstart](typescript-quickstart.md). For the full API specification, see [TypeScript Specification](typescript-specification.md).*
