# SEBI AI/ML Guidelines Compliance

*Last updated: February 2026 | AxonFlow Platform v4.1.0 | SDKs v3.2.0*

AxonFlow provides compliance support for the Securities and Exchange Board of India's **Framework for AI/ML in Securities Markets** for regulated entities in India's capital markets.

## Overview

SEBI's AI/ML Framework establishes governance requirements for AI systems used by market intermediaries, asset managers, and other regulated entities. AxonFlow's SEBI compliance module helps meet these requirements through:

- **Audit Export** - 5-year retention with SEBI-compliant export format
- **PII Detection** - India-specific financial identifiers (PAN, Aadhaar)
- **Decision Audit Trail** - Full traceability for AI-driven decisions
- **Policy Templates** - Pre-built SEBI compliance policies

## Feature Availability

| Feature | Community | Enterprise |
|---------|:---------:|:----------:|
| PAN detection | Basic patterns | Full validation |
| Aadhaar detection | Basic patterns | Full validation |
| Audit Export API | - | Full workflow |
| 5-year Retention | - | Configurable |
| SEBI Export Format | - | Compliant |
| Compliance Dashboard | - | Full UI |

## API Endpoints (Enterprise)

All SEBI compliance APIs are available at `/api/v1/sebi/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/audit/export` | POST | Create audit export |
| `/audit/export/{id}` | GET | Get export status |
| `/audit/retention` | GET | Retention status |
| `/audit/readiness` | GET | Compliance readiness check |
| `/dashboard` | GET | Compliance dashboard |

## PII Detection

SEBI-relevant PII types detected:

| Type | Format | Description |
|------|--------|-------------|
| PAN | ABCDE1234F | Permanent Account Number |
| Aadhaar | 1234 5678 9012 | 12-digit UIDAI with Verhoeff |
| Demat Account | 16-digit | Depository participant account |
| GSTIN | 15-character | GST Identification Number |

## Policy Templates

Pre-built SEBI compliance policies cover:

- PAN detection and redaction
- Aadhaar detection and masking
- Investment advice disclosure
- Algorithmic trading oversight
- Client data protection
- Transaction audit logging

## Database Schema

SEBI compliance extends the core audit tables:

- `audit_logs` - Extended with SEBI retention policy
- `static_policies` - SEBI policy templates (migration 300)

## Getting Started

### Enterprise Deployment

1. Deploy AxonFlow Enterprise
2. Run migrations (includes 300_sebi_ai_ml_templates.sql)
3. Configure audit retention (minimum 5 years for SEBI)
4. Enable SEBI policy templates
5. Set up export schedule

### Configuration

```bash
# Enable SEBI compliance features
SEBI_COMPLIANCE_ENABLED=true
SEBI_AUDIT_RETENTION_YEARS=5
SEBI_EXPORT_FORMAT=sebi_v1
```

## API Examples

### Audit Export (curl)

```bash
# Create a SEBI-compliant audit export
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
# Alternative auth: -H "Authorization: Basic <base64(client_id:client_secret)>"
```

### Compliance Readiness Check (curl)

```bash
curl -X GET "https://your-axonflow-host/api/v1/sebi/audit/readiness" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret"
```

### Proxy LLM Call with SEBI Policies (curl)

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

### SDK Integration

**Go:**

```go
import "github.com/getaxonflow/axonflow-sdk-go/v3/axonflow"

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
fmt.Printf("Response: %s\n", response.Output)
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
print(f"Response: {response.output}")
```

**TypeScript:**

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'https://your-axonflow-host',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

const response = await client.proxyLLMCall(
  'analyst-789',
  'Generate risk assessment for portfolio containing PAN ABCPD1234E',
  'risk_analysis',
  { department: 'compliance' },
);
// PAN is detected and redacted before reaching the LLM provider
```

**Java:**

```java
import com.axonflow.sdk.AxonFlowClient;

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

## Compliance Checklist

- [ ] AI systems registered with compliance team
- [ ] PII detection enabled for PAN/Aadhaar
- [ ] Audit logging enabled with 5-year retention
- [ ] Export procedures documented
- [ ] Board oversight established for high-risk AI

## Documentation

- [SEBI Compliance (PII & HITL details)](./sebi-compliance.md) - Indian PII detection details and HITL configuration
- [RBI FREE-AI Compliance](./rbi-free-ai.md) - RBI banking compliance
- [EU AI Act Compliance](./eu-ai-act.md) - EU AI Act compliance guide
- [API Reference](../api/orchestrator-api.yaml) - OpenAPI specification
- [SEBI AI/ML Framework](https://www.sebi.gov.in/) - Official SEBI guidelines

## Support

For enterprise deployment assistance, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).
