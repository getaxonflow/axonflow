# SDK Feature Coverage

**Last Updated:** 2026-08-24
**Reference:** ADR-022 SDK Method Inclusion Criteria

This document defines what features AxonFlow SDKs cover and explicitly exclude.

---

## Coverage Tiers (per ADR-022)

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
| `healthCheckDetailed()` | Detailed health with capabilities and version discovery | ✅ All SDKs (v4.1.0) |
| `hasCapability()` | Check if platform supports a named capability | ✅ All SDKs (v4.1.0) |
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
| `generatePlanWithOptions()` | Generate plan with execution mode | ✅ All SDKs |
| `executePlan()` | Execute a plan | ✅ All SDKs |
| `getPlanStatus()` | Get plan execution status | ✅ All SDKs |
| `cancelPlan()` | Cancel a pending/executing plan | ✅ All SDKs |
| `updatePlan()` | Update plan with version check | ✅ All SDKs |
| `getPlanVersions()` | Get plan version history | ✅ All SDKs |
| `resumePlan()` | Resume paused plan (Enterprise) | ✅ All SDKs |
| `rollbackPlan()` | Rollback plan to previous version | ✅ All SDKs |

#### WCP Workflow Lifecycle
| Method | Description | Status |
|--------|-------------|--------|
| `failWorkflow()` | Fail a workflow with optional reason | ✅ All SDKs (v3.7.0) |
| `approveStep()` | Approve a pending WCP step | ✅ All SDKs |
| `rejectStep()` | Reject a pending WCP step | ✅ All SDKs |
| `getPendingApprovals()` | List steps awaiting approval | ✅ All SDKs |

#### HITL Queue (Enterprise)
| Method | Description | Status |
|--------|-------------|--------|
| `listHITLQueue()` | List pending approval requests | ✅ All SDKs (v3.7.0) |
| `getHITLRequest()` | Get approval request details | ✅ All SDKs (v3.7.0) |
| `approveHITLRequest()` | Approve a HITL request | ✅ All SDKs (v3.7.0) |
| `rejectHITLRequest()` | Reject a HITL request | ✅ All SDKs (v3.7.0) |
| `getHITLStats()` | Get HITL queue statistics | ✅ All SDKs (v3.7.0) |

#### SSE Streaming
| Method | Description | Status |
|--------|-------------|--------|
| `streamExecutionStatus()` | SSE streaming for real-time execution monitoring. Community: 5 concurrent connections/tenant | ✅ All SDKs (v3.7.0) |

#### Webhook Management
| Method | Description | Status |
|--------|-------------|--------|
| `createWebhook()` | Create a webhook | ✅ All SDKs |
| `getWebhook()` | Get webhook by ID | ✅ All SDKs |
| `updateWebhook()` | Update existing webhook | ✅ All SDKs |
| `deleteWebhook()` | Delete a webhook | ✅ All SDKs |
| `listWebhooks()` | List all webhooks | ✅ All SDKs |

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

#### Singapore PII Detection (MAS FEAT, Platform v3.7.0+)
| Pattern | Description | Status |
|---------|-------------|--------|
| NRIC (S/T/M prefix) | Singapore National Registration Identity Card | ✅ System policy |
| FIN (F/G prefix) | Foreign Identification Number | ✅ System policy |
| UEN | Unique Entity Number (business registration) | ✅ System policy |
| Phone (+65) | Singapore phone numbers (mobile/landline) | ✅ System policy |
| Postal code (6-digit) | Singapore postal codes | ✅ System policy |

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

### HITL (Human-in-the-Loop) Legacy Decisions
| Endpoint | Reason for Exclusion |
|----------|---------------------|
| `GET /api/v1/hitl/queue` | Portal/dashboard use (legacy endpoint) |

> **Note:** HITL Queue API is now available in all SDKs (v3.7.0) via `/api/v1/hitl/queue` endpoints:
> `listHITLQueue()`, `getHITLRequest()`, `approveHITLRequest()`, `rejectHITLRequest()`, `getHITLStats()`

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
3. Reference this document and ADR-022
4. We'll evaluate and potentially upgrade to Tier 2

---

## SDK Parity

The four established SDKs should have identical method coverage. Rust is a preview SDK at v0.10.0 covering the baseline (auth, proxy, audit, basic MAP, basic MCP) plus OpenAI + Anthropic interceptors, `create_hitl_request`, Indonesia PII category, the v9 `X-Client-ID` outbound header, the Decision Mode PEP (`decide` / `fulfill_request` / `decide_and_fulfill`, engine-only fail-closed redaction), and the AuthZEN-native decide surface (generated wire types, typed refusals); feature parity is being filled in over subsequent releases - track progress on the [Rust SDK issues](https://github.com/getaxonflow/axonflow-sdk-rust/issues).

| SDK | Current Version | Methods | Parity |
|-----|---------|---------|--------|
| Go | v9.3.0 | ~45 | ✅ |
| Python | v9.3.0 | ~45 | ✅ |
| TypeScript | v9.3.0 | ~46 | ✅ (+protect) |
| Java | v9.3.0 | ~45 | ✅ |
| Rust _(preview)_ | v0.10.0 | ~21 | 🟡 Baseline (auth + proxy + audit + basic MAP + basic MCP + OpenAI + Anthropic interceptors + `create_hitl_request` + Indonesia PII + `X-Client-ID` + Decision Mode PEP + AuthZEN-native decide surface) |

### Infrastructure (v4.1.0)

| Feature | Description | Status |
|---------|-------------|--------|
| User-Agent header | All requests include `axonflow-sdk-{lang}/{version}` | ✅ All SDKs |
| Version mismatch warning | Log warning when SDK < platform min_sdk_version | ✅ All SDKs |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-09-06 | Version column refreshed to the v10.4.0-train tags (Go/Python/TypeScript/Java v9.3.0, Rust v0.10.0); these match `RecommendedVersions()` in `platform/shared/sdkcompat`, which is what both `/health` planes serve. The 9.3.0 releases carry the read-path identity scoping (`explain`/`list` scoped to a per-user identity, the vacuous empty read refused) and, in Python, the per-call `extra_headers` attach point the PEP capability handshake needs; Rust 0.10.0 carries the telemetry-parity work. Method counts unchanged. **Pinned at PREP, before the tags are cut**: the release order publishes the platform first and the SDKs after it, so between the platform release and the SDK tags this table names versions that are not yet on their registries |
| 2026-09-02 | Version column refreshed to the v10.3.0-train tags (Go/Python/TypeScript/Java v9.2.0, Rust v0.9.0); these match `RecommendedSDKVersion` in `platform/agent/capabilities.go` as of v10.3.0. The v9.2.0 / v0.9.0 releases add the AuthZEN-native decide surface in all five SDKs; method counts unchanged |
| 2026-08-24 | Version column refreshed to the current tags (Go v9.1.1, Python/TypeScript/Java v9.1.0, Rust v0.8.2); these match `RecommendedSDKVersion` in `platform/agent/capabilities.go`. No method changes |
| 2026-05-21 | All four stable SDKs bumped to v8.1.0 carrying `X-Client-ID` outbound header on every request. Rust SDK bumped to v0.3.1 adding both `X-Client-ID` AND the previously-missing `X-Axonflow-Client` header. All 5 SDKs ship `runtime-e2e/x-client-id/` runner + `tests/x_client_id_header*` unit-test pair. Released to registries in lockstep with the v9.0.0 platform cut. |
| 2026-05-04 | Added Rust SDK to the matrix as a preview (v0.2.0). Baseline covers HTTP Basic auth (with `community:` default), `proxy_llm_call`, `audit_llm_call`, basic MAP (`generate_plan`, `execute_plan`, `get_plan_status`, `cancel_plan`), basic MCP connectors, OpenAI interceptor, `X-License-Key`, `AXONFLOW_TELEMETRY=off` opt-out. Subsequent releases will add the universal surface, full interceptor lineup, governance, workflows, cost, and compliance methods to bring it to parity with the four established SDKs |
| 2026-03-01 | Added healthCheckDetailed() and hasCapability() to all SDKs (v4.1.0); Added User-Agent headers and version mismatch warnings; Added Infrastructure section |
| 2026-02-12 | Added failWorkflow() to all SDKs; Added HITL Queue API (listHITLQueue, getHITLRequest, approveHITLRequest, rejectHITLRequest, getHITLStats) to all SDKs; Moved HITL from exclusions to Tier 2 |
| 2026-02-07 | Added SSE streaming (streamExecutionStatus) for real-time MAP/WCP execution monitoring |
| 2026-02-07 | Added WCP step approval (approveStep, rejectStep, getPendingApprovals), rollbackPlan, webhook management (createWebhook, getWebhook, updateWebhook, deleteWebhook, listWebhooks) |
| 2026-02-06 | Added MAP v1.0 methods: cancelPlan, updatePlan, getPlanVersions, resumePlan, generatePlanWithOptions |
| 2026-02-02 | Added Singapore PII detection patterns (MAS FEAT compliance) |
| 2026-01-14 | Added MCP policy response fields (exfiltration_check, dynamic_policy_info) |
| 2026-01-03 | Initial document created |
