# SEBI AI/ML Compliance Guide

This guide covers AxonFlow's compliance features for the Securities and Exchange Board of India (SEBI) AI/ML Guidelines (June 2025 Consultation Paper) and the Digital Personal Data Protection Act (DPDP) 2023.

## Overview

AxonFlow provides comprehensive compliance support for organizations operating in the Indian financial services sector. Our implementation covers the six pillars of SEBI's AI/ML governance framework:

| Pillar | AxonFlow Feature | Status |
|--------|------------------|--------|
| **Ethics** | Policy templates for ethical AI use | ✅ Available |
| **Accountability** | Decision chain tracing | ✅ Available |
| **Transparency** | Audit logging & export API | ✅ Available |
| **Auditability** | 5-year retention, compliance exports | ✅ Available |
| **Data Privacy** | PAN & Aadhaar detection/redaction | ✅ Available |
| **Fairness** | Policy templates for bias detection | ✅ Available |

## Indian PII Detection

AxonFlow automatically detects and redacts Indian PII types to ensure DPDP Act 2023 compliance.

### Supported PII Types

| Type | Format | Severity | Validation |
|------|--------|----------|------------|
| **PAN** | `ABCDE1234F` | Critical | Entity type, checksum |
| **Aadhaar** | `1234 5678 9012` | Critical | Starting digit, Verhoeff |

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

## Policy Templates for SEBI Compliance

AxonFlow includes pre-built policy templates for SEBI AI/ML guidelines. These are available as Enterprise features.

### Available Templates

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
curl -X GET "https://api.getaxonflow.com/api/v1/templates?category=sebi" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: your-tenant"

# Apply a template
curl -X POST "https://api.getaxonflow.com/api/v1/templates/sebi-aiml-ethics/apply" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: your-tenant" \
  -H "Content-Type: application/json" \
  -d '{"priority": 100}'
```

## Audit Retention Configuration

SEBI AI/ML Guidelines require a minimum 5-year retention period for all AI/ML decision records. AxonFlow's audit retention system is configurable per organization and data type.

### Default Retention Periods

| Data Type | Default Retention | Framework |
|-----------|-------------------|-----------|
| Policy violations | 5 years (1825 days) | SEBI AI/ML |
| Agent audit logs | 5 years (1825 days) | SEBI AI/ML |
| LLM call audits | 5 years (1825 days) | SEBI AI/ML |
| Gateway contexts | 5 years (1825 days) | SEBI AI/ML |
| Decision chain | 7 years (2555 days) | EU AI Act |
| HITL oversight | 5 years (1825 days) | SEBI AI/ML |

### Configuring Retention (Enterprise)

```sql
-- Set custom retention for an organization
INSERT INTO audit_retention_config (
    org_id, data_type, retention_days, compliance_framework
) VALUES (
    123, 'policy_violations', 2555, 'SEBI_DPDP_COMBINED'
) ON CONFLICT (org_id, data_type) DO UPDATE
SET retention_days = EXCLUDED.retention_days,
    updated_at = CURRENT_TIMESTAMP;
```

### Checking Retention Status (Enterprise API)

```bash
# Check retention status
curl -X GET "https://api.getaxonflow.com/api/v1/sebi/audit/retention" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Org-ID: 123"
```

Response:
```json
{
  "org_id": 123,
  "framework": "SEBI_AI_ML",
  "compliance_status": "COMPLIANT",
  "status": [
    {
      "data_type": "policy_violations",
      "retention_days": 1825,
      "total_records": 15420,
      "oldest_record": "2020-01-15T10:30:00Z",
      "compliance_status": "COMPLIANT"
    }
  ]
}
```

## Audit Export API (Enterprise)

The SEBI Audit Export API provides regulatory-ready exports for SEBI submissions.

### Export Audit Data

```bash
curl -X POST "https://api.getaxonflow.com/api/v1/sebi/audit/export" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Org-ID: 123" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-12-31T23:59:59Z",
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
curl -X GET "https://api.getaxonflow.com/api/v1/sebi/audit/readiness" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Org-ID: 123"
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
# Enable HITL for high-risk decisions
curl -X POST "https://api.getaxonflow.com/api/v1/hitl/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Org-ID: 123" \
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

## Compliance Checklist

Use this checklist to verify SEBI AI/ML compliance:

### Required (All Organizations)

- [ ] Enable PAN detection policy
- [ ] Enable Aadhaar detection policy
- [ ] Configure 5-year audit retention
- [ ] Enable decision chain tracing
- [ ] Configure audit logging for all AI/ML operations

### Recommended (Financial Services)

- [ ] Enable HITL for high-risk decisions
- [ ] Apply SEBI AI/ML ethics template
- [ ] Configure automated compliance reporting
- [ ] Set up real-time violation alerts
- [ ] Enable model confidence thresholds

### Optional Enhancements

- [ ] Configure 7-year retention (EU AI Act alignment)
- [ ] Enable PII redaction for external auditor exports
- [ ] Set up HITL escalation workflows
- [ ] Configure compliance dashboards

## API Reference

| Endpoint | Method | Description | Enterprise |
|----------|--------|-------------|------------|
| `/api/v1/templates?category=sebi` | GET | List SEBI templates | Yes |
| `/api/v1/templates/{id}/apply` | POST | Apply SEBI template | Yes |
| `/api/v1/sebi/audit/export` | POST | Export audit data | Yes |
| `/api/v1/sebi/audit/export/{id}` | GET | Get export status | Yes |
| `/api/v1/sebi/audit/retention` | GET | Check retention status | Yes |
| `/api/v1/sebi/audit/readiness` | GET | Compliance readiness | Yes |

## References

- [SEBI AI/ML Guidelines Consultation Paper (June 2025)](https://www.sebi.gov.in/)
- [Digital Personal Data Protection Act 2023](https://www.meity.gov.in/dpdp-act-2023)
- [AxonFlow PII Detection](./PII_DETECTION.md)
- [AxonFlow Policy Templates API](./POLICY_TEMPLATES_API.md)
