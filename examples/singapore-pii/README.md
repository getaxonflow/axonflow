# Singapore PII Detection Examples

This example demonstrates AxonFlow's Singapore PII detection capabilities for MAS FEAT compliance. Available in Community Edition.

## Detected Patterns

| Pattern | Format | Action | Severity |
|---------|--------|--------|----------|
| **NRIC** | [STFGM]XXXXXXX[A-Z] | Redact | Critical |
| **FIN** | [FG]XXXXXXX[A-Z] | Redact | Critical |
| **UEN** | 8-9 digits + letter | Redact | High |
| **Phone** | +65 XXXX XXXX | Redact | Medium |
| **Postal** | 6 digits (01-82 range) | Warn | Low |

## Prerequisites

1. AxonFlow stack running (Community or Enterprise)
2. SDK installed for your language

## Quick Start

### Go

```bash
cd go
go run main.go
```

### Python

```bash
cd python
pip install axonflow
python demo.py
```

### TypeScript

```bash
cd typescript
npm install
npx ts-node demo.ts
```

### HTTP (curl)

```bash
# Test NRIC detection
curl -X POST http://localhost:8080/api/v1/policy/check \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: local-dev-org" \
  -d '{"query": "Customer NRIC is S1234567D"}'
```

## Expected Results

### NRIC Detection

**Input:**
```
Customer NRIC is S1234567D
```

**Result:**
- Action: `redact`
- Policy: `sys_pii_singapore_nric`
- Redacted output: `Customer NRIC is [REDACTED]`

### FIN Detection

**Input:**
```
Foreigner FIN: F9876543A
```

**Result:**
- Action: `redact`
- Policy: `sys_pii_singapore_fin`

### UEN Detection

**Input:**
```
Company UEN: 201812345K
```

**Result:**
- Action: `redact`
- Policy: `sys_pii_singapore_uen`

### Phone Detection

**Input:**
```
Contact: +65 9123 4567
```

**Result:**
- Action: `redact`
- Policy: `sys_pii_singapore_phone`

### Postal Code Detection

**Input:**
```
Address: Singapore 238877
```

**Result:**
- Action: `warn` (logged but not blocked)
- Policy: `sys_pii_singapore_postal`

## MAS FEAT Context

The Monetary Authority of Singapore (MAS) requires financial institutions to implement the FEAT (Fairness, Ethics, Accountability, Transparency) principles for AI. Singapore PII detection is a foundational capability for:

- **Fairness**: Ensuring PII is not used in discriminatory ways
- **Accountability**: Audit trail of PII access and redaction
- **Transparency**: Clear policies about what data is collected

## Enterprise Features

Enterprise Edition adds:

- **Checksum Validation**: Validate NRIC/FIN checksums (not just pattern matching)
- **AI System Registry**: Register and track AI systems for MAS reporting
- **FEAT Assessments**: Structured assessment workflows
- **Kill Switches**: Emergency stop mechanisms for AI systems

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent endpoint |
| `AXONFLOW_CLIENT_ID` | `singapore-pii-example` | Client identifier |
| `AXONFLOW_CLIENT_SECRET` | (empty) | Optional for Community |
| `PII_ACTION` | `redact` | Override PII action globally |

## Related Documentation

- [MAS FEAT Guidelines](https://docs.getaxonflow.com/docs/compliance/mas-feat)
- [PII Detection Overview](https://docs.getaxonflow.com/docs/security/pii-detection)
- [Policy Configuration](https://docs.getaxonflow.com/docs/policies/overview)
