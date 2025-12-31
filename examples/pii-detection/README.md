# PII Detection Examples

Demonstrates AxonFlow's built-in PII (Personally Identifiable Information) detection capabilities.

## What This Example Shows

AxonFlow detects and blocks requests containing sensitive PII patterns:

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
- SSN pattern - BLOCKED
- Credit card pattern - BLOCKED
- India PAN - BLOCKED
- India Aadhaar - BLOCKED (with Verhoeff checksum validation)

## How It Works

1. Client sends query to AxonFlow
2. Policy engine scans for PII patterns
3. If PII detected, request is blocked before reaching LLM
4. Block reason indicates which PII type was detected

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
