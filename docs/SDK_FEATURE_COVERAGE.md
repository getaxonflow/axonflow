# SDK Feature Coverage

**Last Updated:** 2026-01-14
**Reference:** ADR-024 SDK Method Inclusion Criteria

This document defines what features AxonFlow SDKs cover and explicitly exclude.

---

## Coverage Tiers (per ADR-024)

| Tier | Description | SDK Coverage | Rationale |
|------|-------------|--------------|-----------|
| **Tier 1** | Hot path operations called per-request | Always | Type safety, retry logic, latency-sensitive |
| **Tier 2** | Feature operations called programmatically | Usually | Core resources, observability queries |
| **Tier 3** | Admin operations, one-time setup | Rarely (HTTP-only) | Infrequent, admin scripts sufficient |

---

## Current SDK Methods

### Tier 1: Hot Path (Always in SDK)

| Method | Description | Status |
|--------|-------------|--------|
| `healthCheck()` | Verify connectivity | ✅ All SDKs |
| `getPolicyApprovedContext()` | Pre-check policy before LLM call | ✅ All SDKs |
| `preCheck()` | Alias for getPolicyApprovedContext | ✅ All SDKs |
| `auditLLMCall()` | Log LLM call for audit | ✅ All SDKs |
| `protect()` | Wrap LLM call with governance | ✅ TypeScript only |

### Tier 2: Feature Operations (Usually in SDK)

#### System Policies (Pattern-Based)
| Method | Description | Status |
|--------|-------------|--------|
| `listStaticPolicies()` | List all system policies | ✅ All SDKs |
| `getStaticPolicy(id)` | Get policy by ID | ✅ All SDKs |
| `createStaticPolicy()` | Create new policy | ✅ All SDKs |
| `updateStaticPolicy()` | Update existing policy | ✅ All SDKs |
| `deleteStaticPolicy()` | Delete policy | ✅ All SDKs |
| `toggleStaticPolicy()` | Enable/disable policy | ✅ All SDKs |
| `getEffectiveStaticPolicies()` | Get policies after inheritance | ✅ All SDKs |
| `testPattern()` | Test regex pattern | ✅ All SDKs |

#### MAP (Multi-Agent Planning)
| Method | Description | Status |
|--------|-------------|--------|
| `generatePlan()` | Generate execution plan | ✅ All SDKs |
| `executePlan()` | Execute a plan | ✅ All SDKs |
| `getPlanStatus()` | Get plan execution status | ✅ All SDKs |

#### MCP Connectors
| Method | Description | Status |
|--------|-------------|--------|
| `listConnectors()` | List available connectors | ✅ All SDKs |
| `installConnector()` | Install a connector | ✅ All SDKs |
| `queryConnector()` | Query a connector | ✅ All SDKs |
| `executeQuery()` | Execute connector query | ✅ All SDKs |

#### MCP Policy Response Fields (Platform v3.2.0+)
| Field | Description | Status |
|-------|-------------|--------|
| `policy_info.exfiltration_check` | Row/byte limits info | ✅ All SDKs |
| `policy_info.dynamic_policy_info` | Tenant policy evaluation info | ✅ All SDKs |

#### Replay/Debug (Planned - #763)
| Method | Description | Status |
|--------|-------------|--------|
| `listExecutions()` | List MAP executions | 🔜 Planned |
| `getExecution()` | Get execution details | 🔜 Planned |
| `getExecutionSteps()` | Get execution steps | 🔜 Planned |
| `exportExecution()` | Export execution JSON | 🔜 Planned |

#### Cost Controls (Planned - #764)
| Method | Description | Status |
|--------|-------------|--------|
| `createBudget()` | Create budget | 🔜 Planned |
| `getBudget()` | Get budget | 🔜 Planned |
| `listBudgets()` | List budgets | 🔜 Planned |
| `getBudgetStatus()` | Get budget + usage | 🔜 Planned |
| `deleteBudget()` | Delete budget | 🔜 Planned |
| `getUsage()` | Get usage summary | 🔜 Planned |
| `getUsageBreakdown()` | Usage by dimension | 🔜 Planned |

---

## Intentional Exclusions (Tier 3 - HTTP Only)

These APIs are intentionally NOT in SDKs. Use HTTP/curl for these operations.

### Agent Management
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `POST /api/v1/agents` | One-time setup, admin operation |
| `PUT /api/v1/agents/{id}` | Rare admin operation |
| `DELETE /api/v1/agents/{id}` | Rare admin operation |
| `POST /api/v1/agents/{id}/activate` | Rare admin operation |
| `POST /api/v1/agents/{id}/deactivate` | Rare admin operation |

### LLM Provider Management
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `POST /api/v1/llm-providers` | One-time setup |
| `PUT /api/v1/llm-providers/{name}` | Rare config change |
| `DELETE /api/v1/llm-providers/{name}` | Rare admin operation |
| `GET /api/v1/llm-providers/health` | Monitoring, not app code |
| `PUT /api/v1/llm-providers/routing` | Rare config change |

### Tenant Policies (Legacy Endpoints)
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `GET /api/v1/policies/dynamic` | Legacy path (use `/api/v1/dynamic-policies` via SDK) |
| `POST /api/v1/policies/import` | One-time migration |
| `GET /api/v1/policies/export` | One-time backup |

> **Note:** Tenant policies CRUD is available in all SDKs via `/api/v1/dynamic-policies` endpoints:
> `listDynamicPolicies()`, `createDynamicPolicy()`, `getDynamicPolicy()`, `updateDynamicPolicy()`,
> `deleteDynamicPolicy()`, `toggleDynamicPolicy()`, `getEffectiveDynamicPolicies()`

### Circuit Breaker
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `POST /api/v1/circuit-breaker/activate` | Emergency admin action |
| `POST /api/v1/circuit-breaker/deactivate` | Emergency admin action |
| `GET /api/v1/circuit-breaker/status` | Monitoring dashboard |

### HITL (Human-in-the-Loop) Decisions
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `GET /api/v1/hitl/decisions` | Portal/dashboard use |
| `POST /api/v1/hitl/decisions/{id}/approve` | Human action via Portal |
| `POST /api/v1/hitl/decisions/{id}/reject` | Human action via Portal |

### Accuracy & Bias Monitoring
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `GET /api/v1/accuracy/metrics` | Dashboard/monitoring |
| `GET /api/v1/accuracy/bias` | Dashboard/monitoring |
| `GET /api/v1/accuracy/alerts` | Dashboard/monitoring |

### Compliance Exports
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `POST /api/v1/sebi/audit/export` | Compliance team action |
| `POST /api/v1/euaiact/export` | Compliance team action |
| `GET /api/v1/conformity/assessments` | Portal use |

### Connector Cache/Refresh
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `POST /api/v1/connectors/refresh` | Admin maintenance |
| `GET /api/v1/connectors/cache/stats` | Debugging |

---

## Requesting New SDK Methods

If you need an excluded API in the SDK:

1. Open an issue describing your use case
2. Explain why HTTP is insufficient
3. Reference this document and ADR-024
4. We'll evaluate and potentially upgrade to Tier 2

---

## SDK Parity

All 4 SDKs should have identical method coverage:

| SDK | Current Version | Methods | Parity |
|-----|---------|---------|--------|
| Go | v2.3.0 | ~21 | ✅ |
| Python | v1.3.0 | ~21 | ✅ |
| TypeScript | v2.3.0 | ~22 | ✅ (+protect) |
| Java | v2.3.0 | ~21 | ✅ |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-01-14 | Added MCP policy response fields (exfiltration_check, dynamic_policy_info) |
| 2026-01-03 | Initial document created |
