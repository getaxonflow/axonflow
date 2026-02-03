# Gateway-Specific Policy Configuration Examples

Demonstrates how to configure AxonFlow's static policy behavior for Gateway mode using environment variables. Gateway mode uses `getPolicyApprovedContext` for pre-checks and `proxyLLMCall` for governed LLM calls, and policy configuration affects both request validation and orchestrator response processing (MAP).

## What Are Gateway Policy Configurations?

AxonFlow ships with built-in static policies for common security threats: PII detection, SQL injection prevention, and dangerous query blocking. These policies apply across all modes, but can be configured **per-mode** using environment variables on the AxonFlow Agent.

**Gateway mode** is unique because policy enforcement happens at two stages:
1. **Pre-check** (`getPolicyApprovedContext`): Validates the request against policies BEFORE the LLM call. PII/SQLi in the user query is caught here.
2. **Response processing** (orchestrator + MAP): When using `proxyLLMCall`, the orchestrator also applies policies to the LLM response. This means GATEWAY_PII_ACTION affects both input and output scanning.

**Key concept:** Policy configuration is set on the **Agent side** via environment variables. Changing behavior requires restarting the AxonFlow Agent with different env vars. Each run of this example validates behavior for the **current** configuration.

## Environment Variable Precedence

AxonFlow resolves policy actions using this precedence (highest to lowest):

1. **Mode-specific env var** (e.g., `GATEWAY_PII_ACTION=block`) -- applies only to Gateway mode
2. **Global env var** (e.g., `PII_ACTION=block`) -- applies to all modes
3. **Built-in defaults** -- `pii=redact`, `sqli=block`, `dangerous_query=block`

## Gateway-Specific Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `GATEWAY_STATIC_POLICIES_ENABLED` | `true` / `false` | `true` | Enable/disable all static policies for Gateway mode |
| `GATEWAY_PII_ACTION` | `block` / `redact` / `log` | `redact` | Action when PII is detected in Gateway queries/responses |
| `GATEWAY_SQLI_ACTION` | `block` / `warn` / `log` | `block` | Action when SQL injection patterns are detected |
| `GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES` | comma-separated | (none) | Categories to skip (e.g., `pii-email,pii-phone`) |

## How Gateway Config Affects Orchestrator Response Processing and MAP

When `proxyLLMCall` is used, the orchestrator processes both the request and the LLM response through the policy engine:

- **Request side:** `getPolicyApprovedContext` applies `GATEWAY_PII_ACTION` and `GATEWAY_SQLI_ACTION` to the user query.
- **Response side:** The orchestrator applies `GATEWAY_PII_ACTION` to the LLM response before returning it. If the LLM response contains PII, it will be blocked/redacted/logged according to the same configuration.
- **MAP (Model-Aware Policies):** MAP rules that reference gateway-specific policies inherit the configured actions. For example, a MAP rule that triggers on PII detection will use `GATEWAY_PII_ACTION` to determine the enforcement action.

This means a single `GATEWAY_PII_ACTION=block` setting will block both PII in user queries AND PII in LLM responses.

## Docker Compose Configuration Examples

### Default behavior (PII redacted, SQLi blocked):
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      # Defaults apply -- no overrides needed
      AXONFLOW_LICENSE_KEY: ${AXONFLOW_LICENSE_KEY}
```

### Strict mode (all threats blocked):
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      GATEWAY_PII_ACTION: block
      GATEWAY_SQLI_ACTION: block
```

### Permissive mode (log only, nothing blocked):
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      GATEWAY_PII_ACTION: log
      GATEWAY_SQLI_ACTION: log
```

### Disable all static policies for gateway:
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      GATEWAY_STATIC_POLICIES_ENABLED: "false"
```

### Skip specific categories:
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES: pii-email,pii-phone
```

## Expected Behavior Matrix

| Config | PII Query (SSN) | SQLi Query (UNION) | Safe Query |
|--------|------------------|--------------------|------------|
| **Default** | APPROVED (redacted) | BLOCKED | APPROVED |
| `GATEWAY_PII_ACTION=block` | BLOCKED | BLOCKED | APPROVED |
| `GATEWAY_PII_ACTION=log` | APPROVED (logged only) | BLOCKED | APPROVED |
| `GATEWAY_SQLI_ACTION=warn` | APPROVED (redacted) | APPROVED (warned) | APPROVED |
| `GATEWAY_SQLI_ACTION=log` | APPROVED (redacted) | APPROVED (logged) | APPROVED |
| Policies disabled | APPROVED | APPROVED | APPROVED |

## Prerequisites

```bash
# Start AxonFlow (with desired env vars)
cd /path/to/axonflow
docker compose up -d

# Verify it's running
curl http://localhost:8080/health
```

## Run Examples

### Go
```bash
cd go
go run main.go
```

### Python
```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript
```bash
cd typescript
npm install
npx ts-node index.ts
```

### Java
```bash
cd java
mvn compile exec:java
```

## How It Works

1. The example uses `getPolicyApprovedContext()` to pre-check queries against gateway policies
2. Each query targets a specific policy category (PII, SQLi, safe)
3. The pre-check response is validated against the **expected** behavior for the current Agent config
4. A `proxyLLMCall()` is also tested to verify end-to-end governed LLM calls work with the current policy configuration
5. Pass/fail results are reported with exit code 1 on any failure

**Important:** This example reads `GATEWAY_PII_ACTION` and `GATEWAY_SQLI_ACTION` from the **client-side** environment to determine expected behavior. These must match what the Agent is configured with. If they differ, tests will report false failures.

## Environment Variables (Client-Side)

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent endpoint |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Client secret for authentication |
| `GATEWAY_PII_ACTION` | `redact` | Expected PII action (must match Agent config) |
| `GATEWAY_SQLI_ACTION` | `block` | Expected SQLi action (must match Agent config) |

## Related

- [Policy Configuration Example](../policy-configuration/) - MCP-mode policy configuration
- [Gateway Mode Example](../integrations/gateway-mode/) - Gateway Mode basics
- [PII Detection Example](../pii-detection/) - PII detection patterns
- [SQLi Detection Example](../sqli-detection/) - SQL injection detection
