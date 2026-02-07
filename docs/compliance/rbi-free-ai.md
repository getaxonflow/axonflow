# RBI FREE-AI Framework Compliance

AxonFlow provides comprehensive compliance support for the Reserve Bank of India's **Framework for Responsible and Ethical Enablement of AI (FREE-AI)** guidelines for Indian banking institutions.

## Overview

The RBI FREE-AI Framework (August 2025) establishes governance requirements for AI systems in regulated financial entities. AxonFlow's RBI compliance module helps banks meet these requirements through:

- **AI System Registry** - Track and manage all AI/ML systems with board approval workflows
- **Model Validation** - Independent and development validation tracking
- **Incident Management** - AI incident reporting with severity-based escalation
- **Kill Switch** - Emergency AI disable with full audit trail
- **Board Reporting** - Quarterly and annual compliance reports
- **Audit Export** - 7-year retention with RBI-compliant export format
- **PII Detection** - 11 India-specific PII types (Aadhaar, PAN, UPI, etc.)

## Feature Availability

| Feature | Community | Enterprise |
|---------|:---------:|:----------:|
| India PII detection (Aadhaar, PAN) | Basic patterns | Full validation |
| AI System Registry API | - | Full CRUD |
| Model Validation tracking | - | Full workflow |
| Incident Management | - | Full workflow |
| Kill Switch | - | Full workflow |
| Board Reporting | - | Full workflow |
| 7-year Audit Export | - | RBI format |
| Policy Templates | Basic | Full library |

## API Endpoints (Enterprise)

All RBI compliance APIs are available at `/api/v1/rbi/`:

| Endpoint | Description |
|----------|-------------|
| `GET/POST /ai-systems` | AI System Registry |
| `GET/POST /validations` | Model Validation records |
| `GET/POST /incidents` | Incident Management |
| `GET/POST /killswitches` | Kill Switch control |
| `GET/POST /reports` | Board Reports |
| `GET/POST /audit-exports` | Audit data export |
| `GET /policies/templates` | RBI policy templates |
| `GET /dashboard` | Compliance dashboard |

## PII Detection Types

The following India-specific PII types are detected:

| Type | Severity | Description |
|------|----------|-------------|
| Aadhaar | Critical | 12-digit UIDAI number with Verhoeff checksum |
| PAN | Critical | Permanent Account Number (ABCDE1234F) |
| UPI ID | Critical | Virtual Payment Address (user@provider) |
| Bank Account | Critical | Indian bank account numbers |
| IFSC | High | Bank branch identifier |
| GSTIN | High | GST Identification Number |
| Voter ID | High | Electoral Photo Identity Card (EPIC) |
| Driving License | High | State-issued DL number |
| Passport | High | Indian passport number |
| Mobile | High | 10-digit Indian mobile (+91) |
| Pincode | Medium | 6-digit postal code |

## Policy Templates

Pre-built RBI compliance policies are available for:

- UPI ID detection and redaction
- Indian mobile number protection
- GSTIN protection for B2B
- High-risk AI decision oversight (Section 2.4)
- AI explainability logging (Section 2.5)
- Fairness monitoring (Section 2.3)
- Model validation status (Section 3.2)
- Board reporting triggers (Section 6.1)

## Database Schema

RBI compliance uses dedicated tables (migration 301):

- `rbi_ai_system_registry` - AI system inventory
- `rbi_model_validations` - Validation records
- `rbi_ai_incidents` - Incident tracking
- `rbi_kill_switch` - Kill switch state
- `rbi_kill_switch_history` - Immutable audit trail
- `rbi_board_reports` - Board reporting

## Getting Started

### Enterprise Deployment

1. Deploy AxonFlow Enterprise with RBI module enabled
2. Run database migrations (includes 301_rbi_free_ai_compliance.sql)
3. Configure PII detection thresholds
4. Register AI systems in the registry
5. Set up board reporting schedule

### Configuration

```bash
# Enable RBI compliance features
RBI_COMPLIANCE_ENABLED=true
RBI_PII_MIN_CONFIDENCE=0.6
RBI_AUDIT_RETENTION_YEARS=7
```

## Documentation

- [Full RBI FREE-AI Compliance Guide](../RBI_FREE_AI_COMPLIANCE.md) - Detailed implementation guide
- [RBI FREE-AI Framework](https://www.rbi.org.in/) - Official RBI guidelines
- [API Reference](../api/orchestrator-api.yaml) - OpenAPI specification

## Support

For enterprise deployment assistance, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).
