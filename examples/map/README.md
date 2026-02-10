# Multi-Agent Planning (MAP) Examples

These examples demonstrate how to use AxonFlow's Multi-Agent Planning (MAP) feature across all supported SDKs.

## Prerequisites

- AxonFlow Agent running (default: `http://localhost:8080`)
- SDK installed for your language
- For enterprise examples: Enterprise license required

## Environment Variables

All examples support these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent URL |
| `AXONFLOW_CLIENT_ID` | `demo-org` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret for authentication |
| `AXONFLOW_USER_TOKEN` | (varies) | User token for request attribution |
| `AXONFLOW_DEBUG` | (empty) | Set to `true` to enable debug logging |

## Example Directories

### `map/` — Core MAP Examples

Comprehensive examples covering all MAP features (15 test sections):

| Section | Feature | Edition |
|---------|---------|---------|
| 1-3 | Generate plan, display steps, get status | Community |
| 4-5 | Execute plan, verify results | Community |
| 6-7 | Cancel plan, execution modes | Community |
| 8 | Plan versioning (update, conflict detection, history) | Community |
| 9-10 | PII policy integration, error handling | Community |
| 11 | Cancel plan (detailed) | Community |
| 12 | Execution modes (sequential, parallel, balanced) | Community |
| 13 | Plan versioning (update, conflict, version history) | Community |
| 14 | Rollback plan to previous version | Community |
| 15 | SSE streaming for real-time execution status monitoring | Community |

### `map-lifecycle/` — Comprehensive Lifecycle Example

Tests the complete MAP plan lifecycle in a single flow:

1. Generate plan → verify plan_id, steps, version=1
2. Get status (pending)
3. Update plan (change execution_mode, expected_version=1) → verify version=2
4. Get versions → verify 2 entries
5. Stale update (expected_version=1) → verify 409 conflict
6. Execute plan → verify completed
7. Get status (completed) with step results
8. Try cancel completed plan → verify rejected
9. Generate + cancel + try execute cancelled → verify rejected
10. Generate with balanced mode → execute → verify completed

### `map-confirm-mode/` — Enterprise Confirm Mode (Enterprise Only)

Tests the confirm execution mode where every step requires approval:

1. Generate plan with `execution_mode: "confirm"`
2. Execute plan → verify `status: "awaiting_approval"`
3. Resume plan (approve) → step executes, pauses at next
4. Repeat until all steps complete
5. Verify final status is `completed`

**Requires:** Enterprise license. Gracefully skips if not available.

## Running the Examples

### HTTP/curl

```bash
cd map/http && bash map.sh
cd map-lifecycle/http && bash map-lifecycle.sh
cd map-confirm-mode/http && bash map-confirm.sh  # Enterprise only
```

### Go

```bash
cd map/go && go run main.go
cd map-lifecycle/go && go run main.go
cd map-confirm-mode/go && go run main.go  # Enterprise only
```

### Python

```bash
cd map/python && pip install -r requirements.txt && python main.py
cd map-lifecycle/python && pip install -r requirements.txt && python main.py
cd map-confirm-mode/python && pip install -r requirements.txt && python main.py  # Enterprise only
```

### TypeScript

```bash
cd map/typescript && npm install && npm start
cd map-lifecycle/typescript && npm install && npm start
cd map-confirm-mode/typescript && npm install && npm start  # Enterprise only
```

### Java

```bash
cd map/java && mvn compile exec:java
cd map-lifecycle/java && mvn compile exec:java
cd map-confirm-mode/java && mvn compile exec:java  # Enterprise only
```

## Expected Output

All examples use an assert pattern and exit with code 0 on success, code 1 on failure.

```
AxonFlow MAP Example - [Language]
==================================================

1. generatePlan...
   Plan ID: plan_abc123
   Steps: 3
   PASS: Plan generated with valid ID
   PASS: Plan has steps

2. executePlan...
   PASS: Execution completed

...

==================================================
Tests Run: N
ALL TESTS PASSED
```

## Policy Configuration for MAP

MAP plan generation and execution respects the same policy configuration as other AxonFlow operations:

| Variable | Default | Description |
|----------|---------|-------------|
| `PII_ACTION` | `redact` | Controls PII detection behavior globally |
| `GATEWAY_PII_ACTION` | (inherits `PII_ACTION`) | Override for gateway mode |

## New MAP v1.0 SDK Methods

| Method | Description | Edition |
|--------|-------------|---------|
| `generatePlan()` / `generatePlanWithOptions()` | Generate plan (with optional execution mode) | Community |
| `executePlan()` | Execute a generated plan | Community |
| `getPlanStatus()` | Get plan execution status | Community |
| `cancelPlan()` | Cancel a pending/executing plan | Community |
| `updatePlan()` | Update a pending plan (with version check) | Community |
| `getPlanVersions()` | Get plan version history | Community |
| `rollbackPlan()` | Rollback plan to previous version | Community |
| `resumePlan()` | Resume a paused plan (confirm/step modes) | Enterprise |
| `streamExecutionStatus()` | SSE streaming for real-time execution monitoring | Community |

## Learn More

- [MAP Documentation](https://docs.getaxonflow.com/docs/orchestration/overview)
- [SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)
