# SQL Injection Detection Examples
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


Demonstrates AxonFlow's SQL injection detection capabilities for both input queries and response scanning.

## What This Example Shows

AxonFlow detects SQL injection patterns:

| Detection Type | Description |
|----------------|-------------|
| Input Query | Detects SQLi in user queries before LLM processing (warns by default; blocks under an org `sqli=block` override) |
| Response Scan | Detects SQLi payloads in MCP connector responses |

### Input SQLi Patterns Detected

- `DROP TABLE`, `DELETE FROM`, `TRUNCATE`
- `UNION SELECT`, `OR 1=1`
- Comment injection (`--`, `/* */`)
- Stacked queries (`;`)
- Time-based blind SQLi (`SLEEP`, `WAITFOR`)

### Response SQLi Detection

When MCP connectors return data from databases, AxonFlow scans responses for SQLi payloads that could indicate:
- Compromised data being exfiltrated
- Injected malicious payloads in stored data
- Second-order SQL injection attempts

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

### HTTP (curl)
```bash
cd http
chmod +x sqli-detection.sh
./sqli-detection.sh
```

## Expected Output

Each example tests multiple SQLi patterns. With the shipped policy actions and no organization override:
- Safe query - APPROVED
- DROP TABLE - APPROVED, SQLi WARNED (`sys_sqli_*` policy in `policies`)
- UNION SELECT - APPROVED, SQLi WARNED
- OR 1=1 - APPROVED, SQLi WARNED
- Comment injection - APPROVED (not detected by default policies)
- Stacked queries - APPROVED, SQLi WARNED
- TRUNCATE - APPROVED, SQLi WARNED

The examples exit 1 if a detected pattern is blocked, because that is not the shipped outcome: it means an organization override or an edited policy action is in force.

## How It Works

1. Client sends query to AxonFlow
2. Policy engine scans for SQLi patterns using regex + heuristics
3. If SQLi is detected, the matched policy's stored action decides: every shipped `sys_sqli_*` policy stores `warn`, so the request is approved and the matched policy ids are returned in `policies`
4. Under an organization `sqli=block` override (or a policy whose action is `block`) the request is blocked before reaching the LLM, and the block reason names the policy

## Policy Configuration

SQLi detection is enabled by default via system policies:
- `sqli_detection` - Basic SQLi patterns
- `sqli_advanced_detection` - ML-assisted (Enterprise)

### Changing the Action (v11)

The stored policy action decides. Every shipped `sys_sqli_*` policy stores `warn`, so out of the box SQL injection is detected and warned, not blocked. There are two supported ways to change that:

1. **Record an organization override** (Enterprise, customer portal API, session auth, `sso:configure` permission). Category `sqli` reaches every `security-sqli` policy; actions are `block`, `redact`, `warn`, `log`:

   ```bash
   # Block SQL injection for your organization
   curl -X PUT http://localhost:8082/api/v1/detection-posture/sqli \
     -H "Content-Type: application/json" \
     -b "axonflow_session=$SESSION" \
     -d '{"action":"block"}'

   # Inspect, or remove the override to return to the stored action
   curl -b "axonflow_session=$SESSION" http://localhost:8082/api/v1/detection-posture
   curl -X DELETE -b "axonflow_session=$SESSION" http://localhost:8082/api/v1/detection-posture/sqli
   ```

   Every write is audited. Agents pick up a change within `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60).

2. **Change the policy's action** - edit a tenant policy, or create a system-policy override where your edition allows it (`POST /api/v1/static-policies/{id}/override`).

> **Removed in v11:** `SQLI_ACTION` and `SQLI_BLOCK_MODE` no longer set an action. A deployment that still sets one keeps running; the agent logs a boot `WARN` naming the variable and increments `axonflow_ignored_posture_env_total{name="SQLI_ACTION"}`.

With an `sqli=block` override recorded, these examples fail by design: they validate the shipped actions.

## Next Steps

- [PII Detection](../pii-detection/) - Block sensitive data
- [Policies Example](../policies/) - Create custom policies
- [MCP Connectors](../mcp-connectors/) - Database integrations
