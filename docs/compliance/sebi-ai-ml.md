# SEBI AI/ML Guidelines Compliance

*Last updated: July 2026 | **Platform:** 9.14.0 · **SDKs:** 9.0.0*

AxonFlow provides compliance support for the Securities and Exchange Board of India's **Framework for AI/ML in Securities Markets** (June 2025 Consultation Paper) and the Digital Personal Data Protection Act (DPDP) 2023, for regulated entities in India's capital markets.

## Overview

SEBI's AI/ML Framework establishes governance requirements for AI systems used by market intermediaries, asset managers, and other regulated entities. AxonFlow's implementation covers the six pillars of SEBI's AI/ML governance framework:

| Pillar | AxonFlow Feature | Status |
|--------|------------------|--------|
| **Ethics** | Policy templates for ethical AI use | ✅ Available |
| **Accountability** | Decision chain tracing | ✅ Available |
| **Transparency** | Audit logging & export API | ✅ Available |
| **Auditability** | 5-year retention, compliance exports | ✅ Available |
| **Data Privacy** | PAN & Aadhaar detection/redaction | ✅ Available |
| **Fairness** | Policy templates for bias detection | ✅ Available |

## Feature Availability

| Feature | Community | Enterprise |
|---------|:---------:|:----------:|
| PAN detection | Basic patterns | Full validation |
| Aadhaar detection | Basic patterns | Full validation |
| Audit Export API | - | Full workflow |
| 5-year Retention | - | Configurable |
| SEBI Export Format | - | Compliant |
| Compliance Dashboard | - | Full UI |

## Indian PII Detection

AxonFlow automatically detects and redacts Indian PII types to support DPDP Act 2023 compliance.

### Supported PII Types

| Type | Format | Severity | Validation |
|------|--------|----------|------------|
| **PAN** | `ABCDE1234F` | Critical | Entity type, checksum |
| **Aadhaar** | `1234 5678 9012` | Critical | Starting digit, Verhoeff |
| **Demat Account** | 16-digit | High | Depository participant account |
| **GSTIN** | 15-character | High | GST Identification Number |

### PAN (Permanent Account Number)

Indian PAN follows a specific 10-character format:
- Characters 1-3: Alphabetic (surname/name)
- Character 4: Entity type indicator
- Character 5: Name initial
- Characters 6-9: Sequential number
- Character 10: Alphabetic checksum

**Entity Type Indicators:**

| Character | Entity Type |
|-----------|-------------|
| P | Individual |
| C | Company |
| H | Hindu Undivided Family |
| A | Association of Persons |
| B | Body of Individuals |
| G | Government Agency |
| J | Artificial Juridical Person |
| L | Local Authority |
| F | Firm |
| T | Trust |

**Examples:**
```
ABCPD1234E  → Valid (Individual)
XYZCT5678G  → Valid (Company)
AB1CD2345E  → Invalid (digits in wrong position)
ABCXD1234E  → Invalid (invalid entity type X)
```

### Aadhaar

Indian Aadhaar numbers are 12-digit unique identifiers:
- First digit: 2-9 (cannot start with 0 or 1)
- Remaining 11 digits: Any digit 0-9
- Optional spaces after every 4 digits

**Format Patterns Detected:**
- `1234 5678 9012` (spaced)
- `123456789012` (continuous)
- `Aadhaar: 123456789012` (with label)
- `UID: 234567890123` (with UID label)

**Examples:**
```
2345 6789 0123  → Valid (starts with 2)
987654321098    → Valid (starts with 9)
0123 4567 8901  → Invalid (starts with 0)
1234 5678 901   → Invalid (only 11 digits)
```

## Policy Templates

AxonFlow includes pre-built policy templates for SEBI AI/ML guidelines (Enterprise):

| Template | Category | Description |
|----------|----------|-------------|
| `sebi-aiml-ethics` | SEBI Compliance | Core ethical AI principles |
| `sebi-aiml-accountability` | SEBI Compliance | Decision accountability |
| `sebi-aiml-transparency` | SEBI Compliance | Disclosure requirements |
| `sebi-aiml-fairness` | SEBI Compliance | Anti-discrimination |
| `dpdp-pan-redaction` | Data Privacy | PAN detection & redaction |
| `dpdp-aadhaar-redaction` | Data Privacy | Aadhaar detection & redaction |
| `sebi-hitl-oversight` | Human Oversight | HITL for high-risk decisions |

### Applying Templates

```bash
# List available SEBI templates
curl -X GET "https://your-axonflow-host/api/v1/templates?category=sebi" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: your-tenant"
# Alternative: -H "Authorization: Basic <base64(client_id:client_secret)>"

# Apply a template
curl -X POST "https://your-axonflow-host/api/v1/templates/sebi-aiml-ethics/apply" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: your-tenant" \
  -H "Content-Type: application/json" \
  -d '{"priority": 100}'
```

## API Endpoints (Enterprise)

All SEBI compliance APIs are available at `/api/v1/sebi/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/audit/export` | POST | Create audit export |
| `/audit/export/{id}` | GET | Get export status |
| `/audit/retention` | GET | Retention status |
| `/audit/readiness` | GET | Compliance readiness check |
| `/dashboard` | GET | Compliance dashboard |

## Audit Retention

SEBI AI/ML Guidelines require a minimum 5-year retention period for all AI/ML decision records. AxonFlow's audit retention is configurable per organization and data type.

### Default Retention Periods

| Data Type | Default Retention | Framework |
|-----------|-------------------|-----------|
| Policy violations | 5 years (1825 days) | SEBI AI/ML |
| Agent audit logs | 5 years (1825 days) | SEBI AI/ML |
| LLM call audits | 5 years (1825 days) | SEBI AI/ML |
| Gateway contexts | 5 years (1825 days) | SEBI AI/ML |
| Decision chain | 7 years (2555 days) | EU AI Act |
| HITL oversight | 5 years (1825 days) | SEBI AI/ML |

### Checking Retention Status (Enterprise)

```bash
curl -X GET "https://your-axonflow-host/api/v1/sebi/audit/retention" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: your-tenant"
```

Response:
```json
{
  "framework": "SEBI_AI_ML",
  "compliance_status": "COMPLIANT",
  "status": [
    {
      "data_type": "policy_violations",
      "retention_days": 1825,
      "total_records": 15420,
      "oldest_record": "2021-01-15T10:30:00Z",
      "compliance_status": "COMPLIANT"
    }
  ]
}
```

## Audit Export API (Enterprise)

The SEBI Audit Export API provides regulatory-ready exports for SEBI submissions.

### Create an Export

```bash
curl -X POST "https://your-axonflow-host/api/v1/sebi/audit/export" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2025-01-01T00:00:00Z",
    "end_date": "2025-12-31T23:59:59Z",
    "data_types": ["policy_violations", "llm_calls", "decision_chain"],
    "format": "json",
    "framework": "SEBI_AI_ML",
    "redact_pii": true
  }'
```

### Export Data Types

| Data Type | Description | Included Fields |
|-----------|-------------|-----------------|
| `policy_violations` | All policy violations | ID, timestamp, type, severity, action |
| `llm_calls` | LLM call records | Request ID, provider, model, tokens, cost |
| `decision_chain` | Decision tracing | Decision type, confidence, rationale |
| `hitl_oversight` | Human reviews | Reviewer, decision, notes, time |
| `pii_redactions` | PII redaction logs | PII type, method, location |

### Export Formats

- **JSON** (default): For programmatic access and integration
- **CSV**: For spreadsheet analysis and reporting
- **XML**: For legacy system compatibility

### Compliance Readiness Check

```bash
curl -X GET "https://your-axonflow-host/api/v1/sebi/audit/readiness" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret"
```

Response:
```json
{
  "ready": true,
  "score": 95,
  "checks": [
    {"name": "Retention Configuration", "status": "pass"},
    {"name": "PII Detection Policies", "status": "pass"},
    {"name": "Human Oversight", "status": "pass"},
    {"name": "Audit Logging", "status": "pass"},
    {"name": "Decision Chain Tracing", "status": "warning"}
  ],
  "recommendations": [
    "Enable decision chain tracing to maintain full audit trail of AI decisions"
  ]
}
```

## Human-in-the-Loop (HITL) Configuration

SEBI guidelines require human oversight for high-risk AI/ML decisions. AxonFlow's HITL system supports configurable triggers.

### HITL Triggers

| Trigger | Description | SEBI Requirement |
|---------|-------------|------------------|
| High-risk score | Risk score > threshold | Accountability |
| Financial amount | Transaction > limit | Ethics |
| Sensitive data | PII detected | Data Privacy |
| Model confidence | Confidence < threshold | Transparency |
| Explicit request | User requests review | Fairness |

### Configuring HITL (Enterprise)

```bash
curl -X POST "https://your-axonflow-host/api/v1/hitl/config" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "triggers": {
      "risk_score_threshold": 0.8,
      "financial_amount_threshold": 1000000,
      "pii_types": ["pan", "aadhaar"]
    },
    "timeout_minutes": 60,
    "escalation_enabled": true
  }'
```

## SDK Integration

Once SEBI policy templates are applied, all LLM calls routed through AxonFlow are automatically subject to PII detection and audit logging.

**curl:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/query/execute" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "user_token": "analyst-789",
    "query": "Generate risk assessment for portfolio containing PAN ABCPD1234E",
    "request_type": "risk_analysis",
    "context": {"department": "compliance"}
  }'
```

**Go:**

```go
import "github.com/getaxonflow/axonflow-sdk-go/v9"

client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "https://your-axonflow-host",
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
})

// All LLM calls are automatically subject to SEBI PII detection policies
response, err := client.ProxyLLMCall(
    "analyst-789",
    "Generate risk assessment for portfolio containing PAN ABCPD1234E",
    "risk_analysis",
    map[string]interface{}{"department": "compliance"},
)
if err != nil {
    log.Fatalf("proxy call failed: %v", err)
}
// PAN is detected and redacted before reaching the LLM provider
fmt.Printf("Response: %v\n", response.Data)
```

**Python:**

```python
from axonflow import AxonFlow

client = AxonFlow(
    endpoint="https://your-axonflow-host",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

# All LLM calls are automatically subject to SEBI PII detection policies
response = client.proxy_llm_call(
    user_token="analyst-789",
    query="Generate risk assessment for portfolio containing PAN ABCPD1234E",
    request_type="risk_analysis",
    context={"department": "compliance"},
)
# PAN is detected and redacted before reaching the LLM provider
print(f"Response: {response.data}")
```

**TypeScript:**

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'https://your-axonflow-host',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

const response = await client.proxyLLMCall({
  userToken: 'analyst-789',
  query: 'Generate risk assessment for portfolio containing PAN ABCPD1234E',
  requestType: 'risk_analysis',
  context: { department: 'compliance' },
);
// PAN is detected and redacted before reaching the LLM provider
```

**Java:**

```java
import com.getaxonflow.sdk.AxonFlowClient;

AxonFlowClient client = AxonFlowClient.builder()
    .endpoint("https://your-axonflow-host")
    .clientId("your-client-id")
    .clientSecret("your-client-secret")
    .build();

var response = client.proxyLlmCall(
    "analyst-789",
    "Generate risk assessment for portfolio containing PAN ABCPD1234E",
    "risk_analysis",
    Map.of("department", "compliance")
);
// PAN is detected and redacted before reaching the LLM provider
```

## Database Schema

SEBI compliance extends the core audit tables:

- `audit_logs` - Extended with SEBI retention policy
- `static_policies` - SEBI policy templates (banking-industry migration `300_sebi_ai_ml_templates.sql`)

## Getting Started (Enterprise)

1. Deploy AxonFlow Enterprise
2. Run migrations (includes `300_sebi_ai_ml_templates.sql`)
3. Configure audit retention (minimum 5 years for SEBI)
4. Enable SEBI policy templates
5. Set up export schedule

## Compliance Checklist

### Required (All Organizations)

- [ ] AI systems registered with compliance team
- [ ] Enable PAN detection policy
- [ ] Enable Aadhaar detection policy
- [ ] Configure 5-year audit retention
- [ ] Enable decision chain tracing
- [ ] Configure audit logging for all AI/ML operations

### Recommended (Financial Services)

- [ ] Enable HITL for high-risk decisions
- [ ] Apply SEBI AI/ML ethics template
- [ ] Board oversight established for high-risk AI
- [ ] Set up real-time violation alerts
- [ ] Enable model confidence thresholds

### Optional Enhancements

- [ ] Configure 7-year retention (EU AI Act alignment)
- [ ] Enable PII redaction for external auditor exports
- [ ] Set up HITL escalation workflows
- [ ] Configure compliance dashboards

## References

- [RBI FREE-AI Compliance](./rbi-free-ai.md) - RBI banking compliance
- [EU AI Act Compliance](./eu-ai-act.md) - EU AI Act compliance guide
- [AxonFlow PII Detection](../guides/pii-detection.md)
- [AxonFlow Policy Templates API](../reference/policy-templates.md)
- [API Reference](../api/orchestrator-api.yaml) - OpenAPI specification
- [SEBI AI/ML Guidelines Consultation Paper (June 2025)](https://www.sebi.gov.in/)
- [Digital Personal Data Protection Act 2023](https://www.meity.gov.in/dpdp-act-2023)

## Support

For enterprise deployment assistance, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).
