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
chmod +x pii-detection.sh
./pii-detection.sh
```

## Expected Output

Each example tests multiple PII patterns:
- Safe query (no PII) - APPROVED
- SSN pattern - REDACTED
- Credit card pattern - REDACTED
- India PAN - REDACTED
- India Aadhaar - REDACTED (with Verhoeff checksum validation)

> **Note:** PII detection now defaults to `redact` action instead of `block` (Issue #891).
> To restore blocking behavior, set `PII_ACTION=block` in your environment.

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

## Next Steps

- [Policies Example](../policies/) - Create custom policies
- [Code Governance](../code-governance/) - Detect secrets in code
- [Gateway Mode](../integrations/gateway-mode/) - Full LLM integration
