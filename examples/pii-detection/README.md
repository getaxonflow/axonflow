# PII Detection Examples

Demonstrates AxonFlow's built-in PII (Personally Identifiable Information) detection capabilities.

## What This Example Shows

AxonFlow detects sensitive PII patterns; the stored action of each matched policy decides what happens:

| PII Type | Pattern | Region |
|----------|---------|--------|
| SSN | `123-45-6789` | US |
| Credit Card | `4111-1111-1111-1111` | Global |
| PAN | `ABCDE1234F` | India |
| Aadhaar | `1234 5678 9012` | India |
| Email | `user@example.com` | Global |
| Phone | `+1-555-123-4567` | Global |

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

# Basic PII detection (default redact mode)
./pii-detection.sh

# PII modes — tests request-side + response-side detection with assertions
./pii-modes.sh
```

## Expected Output

Each example tests multiple PII patterns:
- Safe query (no PII) - APPROVED
- SSN pattern - APPROVED, `sys_pii_ssn` matched
- Credit card pattern - APPROVED, `sys_pii_credit_card` matched
- India PAN - APPROVED, `sys_pii_pan` matched
- India Aadhaar - APPROVED, `sys_pii_aadhaar` matched (with Verhoeff checksum validation)

> **Note (v11):** the stored action of each matched PII policy decides:

| Stored action | Request-side | Response-side | Audit |
|---------------|-------------|---------------|-------|
| `block` | Rejected | Rejected | Yes |
| `redact` | Approved* | Redacted | Yes |
| `warn` | Approved | Pass-through | Yes |
| `log` | Approved | Pass-through | Yes |

\* Approved with `requires_redaction=true` flag.

The shipped SSN, credit card, PAN and Aadhaar policies store `warn` on the request side and `redact` on the response side; email and phone store `log` and `redact`. See [Changing the action](#changing-the-action) below.

## How It Works

1. Client sends query to AxonFlow
2. Policy engine scans for PII patterns
3. If PII is detected, the matched policy's stored action is applied (block, redact, warn or log)
4. Response names the matched policies (`policies`) and, for `redact`, sets `requires_redaction`

> **Stored actions (v11):** request-side PII warns out of the box, and so does SQL injection (every `sys_sqli_*` row stores `warn`). Dangerous commands still block.

## Policy Configuration

PII detection is enabled by default via system policies, including:
- `sys_pii_ssn`
- `sys_pii_credit_card`
- `sys_pii_pan`
- `sys_pii_aadhaar`
- `sys_pii_email`
- `sys_pii_phone`

### Changing the action

Since v11 environment variables no longer set detection actions. `PII_ACTION` and `GATEWAY_PII_ACTION` are ignored: at boot the agent logs a warning for each one that is set and increments `axonflow_ignored_posture_env_total`. There are two supported ways to change what a PII match does:

1. **Record an organization override** (Enterprise). The `pii` override reaches every `pii-*` policy category for your organization. It is written through the customer portal API (`localhost:8082` in the enterprise compose stack) with a session for a user holding `sso:configure`, and every write is audited:

   ```bash
   # Block PII for your organization
   curl -X PUT http://localhost:8082/api/v1/detection-posture/pii \
     -H "Content-Type: application/json" \
     -b "axonflow_session=$PORTAL_SESSION" \
     -d '{"action":"block"}'

   # Back to the stored policy actions
   curl -X DELETE http://localhost:8082/api/v1/detection-posture/pii \
     -b "axonflow_session=$PORTAL_SESSION"
   ```

   Agents pick up a change within `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60).

2. **Change the policy's action.** Edit a tenant policy, or create a system-policy override where your edition allows it.

The SDK examples assert the shipped stored actions, so they report failures while an organization override is in force.

## Next Steps

- [Policies Example](../policies/) - Create custom policies
- [Code Governance](../code-governance/) - Detect secrets in code
- [Gateway Mode](../integrations/gateway-mode/) - Full LLM integration
