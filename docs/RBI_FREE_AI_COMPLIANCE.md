# RBI FREE-AI Framework Compliance Guide

This guide covers AxonFlow's compliance features for the Reserve Bank of India (RBI) Framework for Responsible and Ethical Enablement of AI (FREE-AI) published in August 2025.

## Overview

AxonFlow provides comprehensive compliance support for organizations in the Indian banking and financial services sector. Our implementation covers all key requirements of the RBI FREE-AI Framework:

| Requirement | AxonFlow Feature | Status |
|-------------|------------------|--------|
| **AI System Registry** | Centralized AI inventory with risk categorization | Available |
| **Model Validation** | Independent validation tracking | Available |
| **Incident Management** | AI incident tracking with board notification | Available |
| **Kill Switch** | Emergency stop with audit trail | Available |
| **Board Reporting** | Quarterly compliance reports | Available |
| **Audit Export** | 10-year retention, RBI-compliant exports | Available |
| **PII Detection** | India-specific PII detection (11 types) | Available |
| **Policy Templates** | Pre-built RBI compliance policies | Available |

## Key Features

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

### 6. Audit Export

Per RBI FREE-AI requirements, audit trails must be retained for 10 years.

**Export Formats:**
- `json` - Structured JSON export
- `csv` - CSV for spreadsheet analysis

**API Endpoints:**
```
GET  /api/v1/rbi/audit-exports              # List exports
POST /api/v1/rbi/audit-exports              # Create export
GET  /api/v1/rbi/audit-exports/{id}         # Get export status
GET  /api/v1/rbi/audit-exports/{id}/download # Download export
```

## Indian PII Detection

AxonFlow automatically detects and redacts 11 types of Indian PII to ensure RBI data protection compliance.

### Supported PII Types

| Type | Format | Severity | Example |
|------|--------|----------|---------|
| **UPI ID** | `user@provider` | Critical | `john@paytm` |
| **Aadhaar** | `1234 5678 9012` | Critical | `2345 6789 0123` |
| **PAN** | `ABCDE1234F` | Critical | `ABCPD1234E` |
| **IFSC** | `BANK0123456` | High | `HDFC0001234` |
| **Bank Account** | `9-18 digits` | Critical | `1234567890123456` |
| **GSTIN** | `22AAAAA0000A1Z5` | High | `27AABCU9603R1ZM` |
| **Voter ID** | `ABC1234567` | High | `XYZ1234567` |
| **Driving License** | `State + Number` | High | `MH-0120130012345` |
| **Passport** | `A1234567` | High | `J1234567` |
| **Phone** | `+91 XXXXXXXXXX` | Medium | `+91 9876543210` |
| **Pincode** | `6 digits` | Low | `400001` |

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

## Database Schema

The RBI FREE-AI module creates the following tables:

```sql
rbi_ai_system_registry    -- AI system inventory
rbi_model_validations     -- Validation records
rbi_ai_incidents          -- Incident tracking
rbi_kill_switch           -- Emergency stop records
rbi_board_reports         -- Board reporting
rbi_audit_exports         -- Audit export records
```

## Configuration

### Environment Variables

```bash
# RBI Module Configuration
RBI_AUDIT_RETENTION_YEARS=10       # Retention period (default: 10)
RBI_EXPORT_PATH=/tmp/rbi-exports   # Export directory
RBI_PII_MIN_CONFIDENCE=0.5         # PII detection threshold
```

### OSS vs Enterprise

| Feature | OSS | Enterprise |
|---------|-----|------------|
| PII Detection (Aadhaar, PAN) | Included | Included |
| Policy Templates | Included | Included |
| AI System Registry | - | Included |
| Model Validation Tracking | - | Included |
| Incident Management | - | Included |
| Kill Switch | - | Included |
| Board Reporting | - | Included |
| Audit Export API | - | Included |

## Compliance Checklist

Use this checklist to verify RBI FREE-AI compliance:

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

## Related Documentation

- [SEBI Compliance Guide](./SEBI_COMPLIANCE.md) - SEBI AI/ML Guidelines
- [EU AI Act Compliance](./EU_AI_ACT_COMPLIANCE.md) - EU AI Act compliance
- [API Reference](./api/orchestrator-api.yaml) - OpenAPI specification

## Support

For questions about RBI FREE-AI compliance:
- Enterprise customers: Contact your account manager
- Technical issues: Open a GitHub issue
