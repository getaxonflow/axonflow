# SEBI AI/ML Guidelines Compliance

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

## Compliance Checklist

- [ ] AI systems registered with compliance team
- [ ] PII detection enabled for PAN/Aadhaar
- [ ] Audit logging enabled with 5-year retention
- [ ] Export procedures documented
- [ ] Board oversight established for high-risk AI

## Documentation

- [API Reference](../api/orchestrator-api.yaml) - OpenAPI specification
- [SEBI AI/ML Framework](https://www.sebi.gov.in/) - Official SEBI guidelines

## Support

For enterprise deployment assistance, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).
