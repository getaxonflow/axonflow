# PII Detection Examples

Demonstrates AxonFlow's built-in PII (Personally Identifiable Information) detection capabilities.

## What This Example Shows

AxonFlow detects and redacts requests containing sensitive PII patterns (Issue #891: tiered defaults):

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
- SSN pattern - REDACTED
- Credit card pattern - REDACTED
- India PAN - REDACTED
- India Aadhaar - REDACTED (with Verhoeff checksum validation)

> **Note:** PII detection defaults to `redact` mode. Use `PII_ACTION` to control behavior:

| PII_ACTION | Request-side | Response-side | Audit |
|------------|-------------|---------------|-------|
| `block` | Rejected | Rejected | Yes |
| `redact` (default) | Approved* | Redacted | Yes |
| `warn` | Approved | Pass-through | Yes |
| `log` | Approved | Pass-through | Yes |

\* Approved with `requires_redaction=true` flag.

To change: set `PII_ACTION` in docker-compose.yml and restart.
```bash
PII_ACTION=block docker compose up -d
```

## How It Works

1. Client sends query to AxonFlow
2. Policy engine scans for PII patterns
3. If PII detected, it is redacted before the request reaches the LLM
4. Response indicates which PII type was detected and redacted

> **Tiered Detection (Issue #891):** PII is redacted by default to preserve UX.
> SQLi and dangerous queries are still blocked (high-confidence threats).

## Policy Configuration

PII detection is enabled by default via system policies:
- `pii_ssn_detection`
- `pii_credit_card_detection`
- `pii_pan_detection`
- `pii_aadhaar_detection`
- `pii_email_detection`
- `pii_phone_detection`

To customize, create tenant-level policy overrides.

### Configurable Action Modes

PII detection behavior is controlled via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PII_ACTION` | `redact` | Controls PII detection action for all modes |
| `GATEWAY_PII_ACTION` | (inherits `PII_ACTION`) | Override for gateway mode only |

**Supported values:**

| Value | Behavior |
|-------|----------|
| `redact` | (Default) PII is detected and flagged for downstream redaction. Requests are approved with `requires_redaction=true`. |
| `block` | PII is detected and the request is blocked. Requests are rejected with a block reason. |
| `log` | PII is detected and logged but passes through unmodified. No blocking or redaction. |

**Example:**
```bash
# Block all requests containing PII
PII_ACTION=block go run main.go

# Log PII but allow requests through
PII_ACTION=log python main.py
```

Each SDK example includes conditional tests that adapt to the configured `PII_ACTION` value.

## Next Steps

- [Policies Example](../policies/) - Create custom policies
- [Code Governance](../code-governance/) - Detect secrets in code
- [Gateway Mode](../integrations/gateway-mode/) - Full LLM integration
