# Per-Mode MCP Policy Configuration Examples
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


Demonstrates how AxonFlow's static policy actions are decided and changed, with a focus on MCP connector policies.

## How Static Policy Actions Are Decided (v11)

AxonFlow ships with built-in static policies for common security threats: PII detection, SQL injection detection, and dangerous command blocking. **The stored policy action decides** what happens when one matches. The shipped actions exercised by this example:

| Policy | Request phase | Response phase |
|--------|---------------|----------------|
| `sys_pii_ssn`, `sys_pii_credit_card` | `warn` | `redact` |
| every `sys_sqli_*` | `warn` | `warn` |

So out of the box a PII or SQL injection match is **approved with a warning** (the matched policy id is returned in `policies`); it is not blocked.

**The only replacement for a stored action is an organization's recorded override.** Record one through the customer portal API (Enterprise, session auth, `sso:configure` permission):

```bash
# Block SQL injection for your organization
curl -X PUT http://localhost:8082/api/v1/detection-posture/sqli \
  -H "Content-Type: application/json" \
  -b "axonflow_session=$SESSION" \
  -d '{"action":"block"}'

# List overrides, or delete one to return to the stored action
curl -b "axonflow_session=$SESSION" http://localhost:8082/api/v1/detection-posture
curl -X DELETE -b "axonflow_session=$SESSION" http://localhost:8082/api/v1/detection-posture/sqli
```

Categories: `pii` (every `pii-*` policy category), `sqli` (`security-sqli`), `dangerous_command` (`security-dangerous`), `dangerous_query`, `obligation_fallback`. Actions: `block`, `redact`, `warn`, `log`. Every write is audited, and agents pick up a change within `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60).

The other supported way to change an outcome is to **change the policy's action**: edit a tenant policy, or create a system-policy override where your edition allows it (`POST /api/v1/static-policies/{id}/override`).

> **Removed in v11:** `MCP_PII_ACTION`, `MCP_SQLI_ACTION`, `MCP_DANGEROUS_QUERY_ACTION`, `MCP_DANGEROUS_COMMAND_ACTION`, `PII_ACTION`, `SQLI_ACTION` and the other detection-action variables no longer set an action. A deployment that still sets one keeps running; the agent logs a boot `WARN` per variable and increments `axonflow_ignored_posture_env_total{name="..."}`.

## MCP Environment Variables That Still Apply

These are not action variables and are unchanged:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `MCP_STATIC_POLICIES_ENABLED` | `true` / `false` | `true` | Enable/disable all static policies for MCP mode |
| `MCP_STATIC_POLICIES_SKIP_CATEGORIES` | comma-separated | (none) | Categories to skip (e.g., `pii-email,pii-phone`) |

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
| **Shipped actions, no override** | APPROVED (warned) | APPROVED (warned) | APPROVED |
| Org override `pii=block` | BLOCKED | APPROVED (warned) | APPROVED |
| Org override `sqli=block` | APPROVED (warned) | BLOCKED | APPROVED |
| Policies disabled | APPROVED | APPROVED | APPROVED |

This example validates the first row (and the last, when `MCP_STATIC_POLICIES_ENABLED=false`). With an override recorded it fails by design.

## Prerequisites

```bash
# Start AxonFlow
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
3. The response is validated against the shipped stored actions: approved, with the matched `sys_pii_*` / `sys_sqli_*` policy id in `policies`
4. Pass/fail results are reported with exit code 1 on any failure

**Important:** The only action-related client-side input is the static-policies enable flag (`MCP_STATIC_POLICIES_ENABLED` for Java, `GATEWAY_STATIC_POLICIES_ENABLED` for Go, Python and TypeScript), which must match the Agent's config.

## Environment Variables (Client-Side)

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent endpoint |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Client secret for authentication |

## Related

- [MCP Policies Example](../mcp-policies/) - Phase-aware MCP policy enforcement
- [PII Detection Example](../pii-detection/) - PII detection patterns
- [MCP Policy Enforcement Guide](../../docs/mcp/policy-enforcement.md)
