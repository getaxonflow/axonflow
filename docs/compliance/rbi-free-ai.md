# RBI FREE-AI Framework Compliance

*Last updated: July 2026 | **Platform:** 9.14.0 · **SDKs:** 9.0.0*

AxonFlow provides comprehensive compliance support for the Reserve Bank of India's **Framework for Responsible and Ethical Enablement of AI (FREE-AI)** (August 2025) for Indian banking and financial services institutions.

## Overview

The RBI FREE-AI Framework establishes governance requirements for AI systems in regulated financial entities. AxonFlow's RBI compliance module helps banks meet these requirements through:

| Requirement | AxonFlow Feature |
|-------------|------------------|
| **AI System Registry** | Centralized AI inventory with risk categorization and board approval workflows |
| **Model Validation** | Independent and development validation tracking |
| **Incident Management** | AI incident tracking with severity-based escalation and board notification |
| **Kill Switch** | Emergency stop with full audit trail |
| **Board Reporting** | Quarterly and annual compliance reports |
| **Audit Export** | 10-year retention, RBI-compliant exports |
| **PII Detection** | 11 India-specific PII types (Aadhaar, PAN, UPI, etc.) |
| **Policy Templates** | Pre-built RBI compliance policies |

## Feature Availability

| Feature | Community | Enterprise |
|---------|:---------:|:----------:|
| India PII detection (Aadhaar, PAN) | Basic patterns | Full validation |
| AI System Registry API | - | Full CRUD |
| Model Validation tracking | - | Full workflow |
| Incident Management | - | Full workflow |
| Kill Switch | - | Full workflow |
| Board Reporting | - | Full workflow |
| 10-year Audit Export | - | RBI format |
| Policy Templates | Basic | Full library |

## Key Features (Enterprise)

All RBI compliance APIs are available at `/api/v1/rbi/`. All examples authenticate with `X-Client-Id`/`X-Client-Secret` headers; `Authorization: Basic <base64(client_id:client_secret)>` also works.

### 1. AI System Registry

Per RBI FREE-AI Section 2.1, all AI systems must be registered with board approval before production deployment.

**Risk Categories:**
- **High**: Loan approval, algorithmic trading, credit scoring
- **Medium**: Fraud detection, customer segmentation
- **Low**: Chatbots, FAQ systems, document summarization

**API Endpoints:**
```
GET  /api/v1/rbi/ai-systems          # List registered systems
POST /api/v1/rbi/ai-systems          # Register new system
GET  /api/v1/rbi/ai-systems/{id}     # Get system details
PUT  /api/v1/rbi/ai-systems/{id}     # Update system
GET  /api/v1/rbi/ai-systems/summary  # Registry summary
```

**Example: Register a new AI system:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/ai-systems" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Credit Scoring Engine",
    "risk_category": "high",
    "description": "ML-based credit scoring for retail loans",
    "owner": "risk-analytics@bank.example",
    "board_approval_date": "2025-11-15",
    "model_type": "gradient_boosting",
    "data_sources": ["bureau_data", "transaction_history"]
  }'
```

### 2. Model Validation

Per RBI FREE-AI Section 3.2, AI models require independent validation before deployment.

**Validation Types:**
- `development` - Internal testing validation
- `independent` - Third-party validation
- `periodic` - Ongoing performance validation

**API Endpoints:**
```
GET  /api/v1/rbi/validations         # List validations
POST /api/v1/rbi/validations         # Record new validation
GET  /api/v1/rbi/validations/{id}    # Get validation details
PUT  /api/v1/rbi/validations/{id}    # Update validation status
```

**Example: Record a model validation:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/validations" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "credit-scoring-engine",
    "validation_type": "independent",
    "validator": "external-audit-firm@example.com",
    "result": "passed",
    "findings": "Model performance within acceptable thresholds",
    "next_validation_date": "2026-06-15"
  }'
```

### 3. Incident Management

Per RBI FREE-AI Section 5.1, AI incidents must be tracked and reported to the board (and RBI for high-severity incidents).

**Severity Levels:**
- **Critical**: System-wide failures, data breaches, financial impact >₹1Cr
- **High**: Significant errors, compliance violations
- **Medium**: Performance degradation, minor errors
- **Low**: Isolated issues, enhancement requests

**API Endpoints:**
```
GET  /api/v1/rbi/incidents              # List incidents
POST /api/v1/rbi/incidents              # Report new incident
GET  /api/v1/rbi/incidents/{id}         # Get incident details
PUT  /api/v1/rbi/incidents/{id}         # Update incident
POST /api/v1/rbi/incidents/{id}/resolve # Resolve incident
```

**Example: Report an AI incident:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/incidents" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "credit-scoring-engine",
    "severity": "high",
    "description": "Model producing anomalous approval rates for segment X",
    "reported_by": "risk-officer@bank.example",
    "impact": "Potential over-approval of high-risk loans"
  }'
```

### 4. Kill Switch

Per RBI FREE-AI Section 2.4, organizations must maintain the ability to immediately halt AI operations.

**Activation Reasons:**
- `safety` - Safety concern detected
- `compliance` - Regulatory compliance issue
- `performance` - Performance degradation
- `security` - Security incident
- `manual` - Manual override by authorized personnel

**API Endpoints:**
```
GET  /api/v1/rbi/killswitches                 # List kill switches
POST /api/v1/rbi/killswitches                 # Activate kill switch
GET  /api/v1/rbi/killswitches/{id}            # Get status
POST /api/v1/rbi/killswitches/{id}/deactivate # Deactivate
```

**Example: Activate emergency kill switch:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/killswitches" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "credit-scoring-engine",
    "reason": "compliance",
    "activated_by": "chief-risk-officer@bank.example",
    "notes": "RBI audit finding - immediate halt required"
  }'
```

### 5. Board Reporting

Per RBI FREE-AI Section 6.1, quarterly reports must be submitted to the board.

**Report Types:**
- `quarterly` - Standard quarterly report
- `annual` - Annual comprehensive review
- `incident` - Incident-specific report
- `audit` - Audit response report

**API Endpoints:**
```
GET  /api/v1/rbi/reports              # List reports
POST /api/v1/rbi/reports              # Generate report
GET  /api/v1/rbi/reports/{id}         # Get report details
POST /api/v1/rbi/reports/{id}/submit  # Submit to board
```

**Example: Generate quarterly board report:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/reports" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "quarterly",
    "quarter": "Q4-2025",
    "include_sections": ["ai_systems", "incidents", "validations", "pii_stats"]
  }'
```

**Compliance issues surfaced in every report:**

The generated report computes a compliance score and a list of compliance issues. Beyond overdue validations, critical incidents, and active kill switches, the report explicitly flags **notifications that are legally required but have not been sent**:

- `regulatory_notification` (severity `critical`) — one or more AI incidents require an RBI notification (`rbi_notification_required = true`) that has not been sent (`rbi_notified = false`). This is independent of incident status: a critical incident that was already resolved but never reported to RBI is still flagged.
- `board_notification` (severity `high`) — one or more AI incidents require a board notification that has not been sent.

These are derived at generation time from the incident notification state, so an unsent-but-required notification can never silently disappear into the generic open-incident count.

### 6. Audit Export

Per RBI FREE-AI requirements, audit trails must be retained for 10 years.

**Export Formats:**
- `json` - Structured JSON export
- `csv` - CSV for spreadsheet analysis

**API Endpoints:**
```
GET  /api/v1/rbi/audit-exports               # List exports
POST /api/v1/rbi/audit-exports               # Create export
GET  /api/v1/rbi/audit-exports/{id}          # Get export status
GET  /api/v1/rbi/audit-exports/{id}/download # Download export
```

**Example: Create a 10-year compliant audit export:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/rbi/audit-exports" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2016-01-01T00:00:00Z",
    "end_date": "2025-12-31T23:59:59Z",
    "format": "json",
    "include_pii_redaction_log": true
  }'
```

## Indian PII Detection

AxonFlow automatically detects and redacts 11 types of Indian PII to support RBI data protection compliance.

### Supported PII Types

| Type | Format | Severity | Example |
|------|--------|----------|---------|
| **UPI ID** | `user@provider` | Critical | `john@paytm` |
| **Aadhaar** | `1234 5678 9012` | Critical | `2345 6789 0123` |
| **PAN** | `ABCDE1234F` | Critical | `ABCPD1234E` |
| **Bank Account** | 9-18 digits | Critical | `1234567890123456` |
| **IFSC** | `BANK0123456` | High | `HDFC0001234` |
| **GSTIN** | `22AAAAA0000A1Z5` | High | `27AABCU9603R1ZM` |
| **Voter ID** | `ABC1234567` | High | `XYZ1234567` |
| **Driving License** | State + Number | High | `MH-0120130012345` |
| **Passport** | `A1234567` | High | `J1234567` |
| **Phone** | `+91 XXXXXXXXXX` | Medium | `+91 9876543210` |
| **Pincode** | 6 digits | Low | `400001` |

### UPI Virtual Payment Address (VPA)

Format: `username@provider`

**Known Providers:**
- `@paytm`, `@ybl` (PhonePe), `@okhdfcbank`, `@okicici`, `@oksbi`
- `@axl` (Axis), `@ibl` (ICICI), `@upi` (NPCI)

**Examples:**
```
john.doe@paytm     → Valid UPI ID
9876543210@ybl     → Valid UPI ID (phone-based)
user@unknown       → May be valid (custom handle)
```

### IFSC Code

Format: `BANK0BRANCH` (11 characters)

- Characters 1-4: Bank code (alphabetic)
- Character 5: Always `0` (zero)
- Characters 6-11: Branch code (alphanumeric)

**Examples:**
```
HDFC0001234  → Valid (HDFC Bank)
SBIN0012345  → Valid (State Bank of India)
ICIC0000001  → Valid (ICICI Bank)
```

### GSTIN (Goods and Services Tax Identification Number)

Format: `SSAAAAANNNNANAN` (15 characters)

- Characters 1-2: State code (01-37)
- Characters 3-12: PAN
- Character 13: Entity number (1-9, A-Z)
- Character 14: `Z` (default)
- Character 15: Checksum

**Examples:**
```
27AABCU9603R1ZM  → Valid (Maharashtra)
06BZAHM6385P6Z2  → Valid (Haryana)
```

## Policy Templates

AxonFlow includes pre-built policy templates for RBI FREE-AI compliance:

### PII Detection Policies

| Policy ID | Description |
|-----------|-------------|
| `rbi_upi_id_detection` | Detect UPI Virtual Payment Addresses |
| `rbi_mobile_number_detection` | Detect Indian mobile numbers |
| `rbi_gstin_detection` | Detect GST Identification Numbers |
| `rbi_passport_detection` | Detect Indian passport numbers |
| `rbi_voter_id_detection` | Detect Voter ID (EPIC) numbers |
| `rbi_driving_license_detection` | Detect driving license numbers |
| `rbi_pincode_detection` | Detect postal PIN codes |

### Compliance Policies

| Policy ID | RBI Section | Description |
|-----------|-------------|-------------|
| `rbi_high_risk_ai_oversight` | 2.4 | Human oversight for high-risk AI |
| `rbi_ai_explainability` | 2.5 | AI decision explanation |
| `rbi_ai_fairness_monitoring` | 2.3 | Bias detection in AI models |
| `rbi_model_validation_required` | 3.2 | Model validation enforcement |
| `rbi_board_reporting_required` | 6.1 | Board reporting compliance |

## SDK Integration

Once RBI policy templates are applied, all LLM calls routed through AxonFlow are automatically subject to PII detection and audit logging.

**curl:**

```bash
curl -X POST "https://your-axonflow-host/api/v1/query/execute" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "user_token": "banker-456",
    "query": "Assess credit risk for customer with Aadhaar 2345 6789 0123",
    "request_type": "credit_assessment",
    "context": {"department": "retail_banking"}
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

response, err := client.ProxyLLMCall(
    "banker-456",
    "Assess credit risk for customer with Aadhaar 2345 6789 0123",
    "credit_assessment",
    map[string]interface{}{"department": "retail_banking"},
)
// Aadhaar number will be detected and redacted per RBI policy
```

**Python:**

```python
from axonflow import AxonFlow

client = AxonFlow(
    endpoint="https://your-axonflow-host",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

response = client.proxy_llm_call(
    user_token="banker-456",
    query="Assess credit risk for customer with Aadhaar 2345 6789 0123",
    request_type="credit_assessment",
    context={"department": "retail_banking"},
)
# Aadhaar number will be detected and redacted per RBI policy
```

## Database Schema

RBI compliance uses dedicated tables (banking-industry migration `301_rbi_free_ai_compliance.sql`):

- `rbi_ai_system_registry` - AI system inventory
- `rbi_model_validations` - Validation records
- `rbi_ai_incidents` - Incident tracking
- `rbi_kill_switches` - Kill switch state
- `rbi_kill_switch_history` - Immutable kill switch audit trail
- `rbi_board_reports` - Board reporting
- `rbi_audit_exports` - Audit export records

## Getting Started (Enterprise)

1. Deploy AxonFlow Enterprise (the RBI module initializes automatically in Enterprise builds)
2. Run database migrations (includes `301_rbi_free_ai_compliance.sql` and `302_rbi_free_ai_templates.sql`)
3. Register AI systems in the registry
4. Set up board reporting schedule

Module defaults: PII detection minimum confidence 0.5, PII validation enabled, audit export base path `/tmp/rbi-audit-exports` (cloud storage backends supported).

## Compliance Checklist

- [ ] All AI systems registered in the registry
- [ ] Risk categorization assigned to each system
- [ ] Board approval documented for high-risk systems
- [ ] Independent validation completed before production
- [ ] Incident management process established
- [ ] Kill switch tested and documented
- [ ] Quarterly board reports generated
- [ ] 10-year audit retention configured
- [ ] PII detection enabled for all AI interactions
- [ ] Human oversight configured for high-risk decisions

## Documentation

- [SEBI Compliance](./sebi-ai-ml.md) - SEBI AI/ML guidelines
- [EU AI Act Compliance](./eu-ai-act.md) - EU AI Act compliance guide
- [API Reference](../api/orchestrator-api.yaml) - OpenAPI specification
- [RBI FREE-AI Framework](https://www.rbi.org.in/) - Official RBI guidelines

## Support

For enterprise deployment assistance, contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com).
