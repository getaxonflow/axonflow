# Per-Mode MCP Policy Configuration Examples

Demonstrates how to configure AxonFlow's static policy behavior per-mode using environment variables, with a focus on MCP connector policies.

## What Are Configurable Static Policies?

AxonFlow ships with built-in static policies for common security threats: PII detection, SQL injection prevention, and dangerous query blocking. By default, these policies use sensible actions (e.g., PII is redacted, SQLi is blocked). However, you can override these defaults per-mode using environment variables on the AxonFlow Agent.

**Key concept:** Policy configuration is set on the **Agent side** via environment variables. Changing behavior requires restarting the AxonFlow Agent with different env vars. Each run of this example validates behavior for the **current** configuration.

## Environment Variable Precedence

AxonFlow resolves policy actions using this precedence (highest to lowest):

1. **Mode-specific env var** (e.g., `MCP_PII_ACTION=block`) -- applies only to MCP mode
2. **Global env var** (e.g., `PII_ACTION=block`) -- applies to all modes
3. **Built-in defaults** -- `pii=redact`, `sqli=block`, `dangerous_query=block`

## MCP-Specific Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `MCP_STATIC_POLICIES_ENABLED` | `true` / `false` | `true` | Enable/disable all static policies for MCP mode |
| `MCP_PII_ACTION` | `block` / `redact` / `log` | `redact` | Action when PII is detected in MCP queries |
| `MCP_SQLI_ACTION` | `block` / `warn` / `log` | `block` | Action when SQL injection patterns are detected |
| `MCP_DANGEROUS_QUERY_ACTION` | `block` / `warn` / `log` | `block` | Action for dangerous queries (DROP, TRUNCATE, etc.) |
| `MCP_STATIC_POLICIES_SKIP_CATEGORIES` | comma-separated | (none) | Categories to skip (e.g., `pii-email,pii-phone`) |

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
      MCP_PII_ACTION: block
      MCP_SQLI_ACTION: block
      MCP_DANGEROUS_QUERY_ACTION: block
```

### Permissive mode (log only, nothing blocked):
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      MCP_PII_ACTION: log
      MCP_SQLI_ACTION: log
      MCP_DANGEROUS_QUERY_ACTION: log
```

### Skip specific categories:
```yaml
services:
  axonflow-agent:
    image: getaxonflow/agent:latest
    environment:
      MCP_STATIC_POLICIES_SKIP_CATEGORIES: pii-email,pii-phone
```

## Expected Behavior Matrix

| Config | PII Query (SSN) | SQLi Query (UNION) | Safe Query |
|--------|------------------|--------------------|------------|
| **Default** | APPROVED (redacted) | BLOCKED | APPROVED |
| `MCP_PII_ACTION=block` | BLOCKED | BLOCKED | APPROVED |
| `MCP_PII_ACTION=log` | APPROVED (logged only) | BLOCKED | APPROVED |
| `MCP_SQLI_ACTION=warn` | APPROVED (redacted) | APPROVED (warned) | APPROVED |
| `MCP_SQLI_ACTION=log` | APPROVED (redacted) | APPROVED (logged) | APPROVED |
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

1. The example sends test queries through the MCP connector endpoint
2. Each query targets a specific policy category (PII, SQLi, safe)
3. The response is validated against the **expected** behavior for the current Agent config
4. Pass/fail results are reported with exit code 1 on any failure

**Important:** This example reads `MCP_PII_ACTION` and `MCP_SQLI_ACTION` from the **client-side** environment to determine expected behavior. These must match what the Agent is configured with. If they differ, tests will report false failures.

## Environment Variables (Client-Side)

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent endpoint |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Client secret for authentication |
| `MCP_PII_ACTION` | `redact` | Expected PII action (must match Agent config) |
| `MCP_SQLI_ACTION` | `block` | Expected SQLi action (must match Agent config) |

## Related

- [MCP Policies Example](../mcp-policies/) - Phase-aware MCP policy enforcement
- [PII Detection Example](../pii-detection/) - PII detection patterns
- [MCP Policy Enforcement Guide](../../docs/mcp/policy-enforcement.md)
