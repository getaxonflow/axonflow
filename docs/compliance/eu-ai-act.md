# EU AI Act Compliance Guide

AxonFlow provides comprehensive support for EU AI Act compliance. This guide covers the key features and APIs available for organizations operating AI systems in the European Union.

## Overview

The EU AI Act (Regulation 2024/1689) establishes harmonized rules for AI systems in the EU market. AxonFlow Enterprise Edition includes features to help organizations comply with:

- **Article 9**: Risk Management Systems
- **Article 10**: Data and Data Governance
- **Article 11**: Technical Documentation
- **Article 12**: Record-keeping
- **Article 13**: Transparency and Provision of Information
- **Article 14**: Human Oversight
- **Article 15**: Accuracy, Robustness and Cybersecurity
- **Article 17**: Quality Management System
- **Article 43**: Conformity Assessment

## Feature Summary

| Feature | Article | Community | Enterprise |
|---------|---------|-----|------------|
| Decision Chain Tracing | 12, 13 | ✅ | ✅ |
| Transparency Headers | 13 | ✅ | ✅ |
| Audit Retention Config | 12 | ✅ | ✅ |
| Human-in-the-Loop (HITL) | 14 | ❌ | ✅ |
| EU AI Act Export Format | 11, 12 | ❌ | ✅ |
| Emergency Circuit Breaker | 15 | ❌ | ✅ |
| Accuracy Metrics | 9, 15 | ❌ | ✅ |
| Bias Detection | 9, 10 | ❌ | ✅ |
| Conformity Assessment | 43 | ❌ | ✅ |

## Decision Chain Tracing

Every AI decision is automatically traced with full context, enabling complete auditability.

### Response Headers

All AI responses include transparency headers:

```http
X-AI-Decision-ID: dec-20251207-12345
X-AI-Trace-ID: trace-abc123
X-AI-Model: claude-3-5-sonnet-20241022
X-AI-Processing-Time-Ms: 1234
X-AI-Confidence: 0.95
X-AI-Human-Oversight: none
X-AI-Data-Sources: internal-db,customer-data
```

### Audit Log Format

Decision chains are stored in a structured format:

```json
{
  "decision_id": "dec-20251207-12345",
  "trace_id": "trace-abc123",
  "timestamp": "2025-12-07T12:34:56Z",
  "org_id": "org-123",
  "agent_id": "agent-456",
  "input": {
    "type": "customer_support",
    "anonymized": true
  },
  "output": {
    "decision": "approved",
    "confidence": 0.95
  },
  "model": {
    "provider": "anthropic",
    "model_id": "claude-3-5-sonnet-20241022"
  },
  "human_oversight": {
    "required": false,
    "reviewer": null
  }
}
```

## Human-in-the-Loop (HITL) (Enterprise)

For high-risk decisions, AxonFlow supports human oversight workflows.

### Configuration

Enable HITL in your policy:

```yaml
policy:
  human_oversight:
    enabled: true
    trigger_conditions:
      - confidence_below: 0.8
      - risk_score_above: 0.7
      - decision_type:
          - loan_approval
          - medical_recommendation
    reviewer_assignment:
      method: round_robin
      pool: compliance_team
    sla:
      response_time_minutes: 60
      escalation_after_minutes: 120
```

### API Endpoints

```http
# List pending decisions
GET /api/v1/hitl/decisions?status=pending&org_id=org-123

# Get decision details
GET /api/v1/hitl/decisions/{id}

# Approve decision
POST /api/v1/hitl/decisions/{id}/approve
{
  "approved_by": "reviewer@company.com",
  "comments": "Verified against policy guidelines"
}

# Reject decision
POST /api/v1/hitl/decisions/{id}/reject
{
  "rejected_by": "reviewer@company.com",
  "reason": "Missing required documentation"
}

# Get HITL metrics
GET /api/v1/hitl/metrics?org_id=org-123
```

## Audit Retention (Enterprise)

Configure audit data retention to meet regulatory requirements.

### Configuration

```yaml
audit:
  retention:
    # EU AI Act Article 12 requires minimum 6 months
    decision_logs_days: 2555  # 7 years for high-risk AI
    model_versions_days: 3650 # 10 years
    compliance_reports_days: 3650

  # Storage configuration
  storage:
    type: s3
    bucket: company-ai-audit
    encryption: AES-256

  # Export settings
  export:
    formats: [json, xml, csv]
    schedule: daily
```

### API Endpoints

```http
# Get retention status
GET /api/v1/audit/retention/status?org_id=org-123

# Export audit data
POST /api/v1/audit/export
{
  "org_id": "org-123",
  "format": "eu_ai_act",
  "date_range": {
    "start": "2025-01-01",
    "end": "2025-12-31"
  }
}

# Get export status
GET /api/v1/audit/export/{export_id}
```

## EU AI Act Export Format (Enterprise)

Export audit data in the format specified by EU AI Act technical standards.

### Export Structure

```json
{
  "export_metadata": {
    "format_version": "1.0",
    "regulation": "EU_AI_ACT_2024_1689",
    "generated_at": "2025-12-07T12:00:00Z",
    "org_id": "org-123"
  },
  "system_info": {
    "provider": "AxonFlow Enterprise",
    "version": "3.2.0",
    "deployment_type": "in_vpc"
  },
  "decisions": [...],
  "human_oversight_events": [...],
  "accuracy_metrics": {...},
  "bias_assessments": [...],
  "conformity_status": {...}
}
```

## Emergency Circuit Breaker (Enterprise)

Immediately halt AI operations when critical issues are detected.

### Configuration

```yaml
circuit_breaker:
  enabled: true
  triggers:
    - accuracy_below: 0.7
    - bias_score_above: 0.5
    - error_rate_above: 0.1
    - manual_activation: true

  actions:
    - halt_all_decisions
    - notify_stakeholders
    - escalate_to_compliance

  notifications:
    email: compliance@company.com
    webhook: https://alerts.company.com/ai-circuit-breaker
```

### API Endpoints

```http
# Activate circuit breaker
POST /api/v1/circuit-breaker/activate
{
  "org_id": "org-123",
  "reason": "Detected bias in loan decisions",
  "activated_by": "compliance@company.com"
}

# Check circuit breaker status
GET /api/v1/circuit-breaker/status?org_id=org-123

# Deactivate circuit breaker
POST /api/v1/circuit-breaker/deactivate
{
  "org_id": "org-123",
  "deactivated_by": "compliance@company.com",
  "resolution": "Bias detected in training data, model retrained"
}
```

## Accuracy Metrics & Bias Detection (Enterprise)

Monitor AI system accuracy and detect potential biases.

### Accuracy Metrics

```http
# Record a metric
POST /api/v1/accuracy/metrics
{
  "org_id": "org-123",
  "agent_id": "agent-456",
  "metric_type": "accuracy",
  "value": 0.95,
  "context": {
    "task_type": "classification",
    "dataset": "validation_set_2025q4"
  }
}

# Get metrics summary
GET /api/v1/accuracy/metrics?org_id=org-123&period=30d

# Get compliance summary
GET /api/v1/accuracy/compliance-summary?org_id=org-123
```

### Bias Detection

```http
# Record bias assessment
POST /api/v1/accuracy/bias
{
  "org_id": "org-123",
  "agent_id": "agent-456",
  "category": "gender",
  "bias_score": 0.12,
  "sample_size": 10000,
  "details": {
    "male_approval_rate": 0.78,
    "female_approval_rate": 0.69
  }
}

# Get bias alerts
GET /api/v1/accuracy/alerts?org_id=org-123&severity=critical
```

## Conformity Assessment (Enterprise)

Manage EU AI Act conformity assessments per Article 43.

### Assessment Workflow

1. **Create Assessment**: Initialize a new conformity assessment
2. **Start Assessment**: Begin the compliance checking process
3. **Complete Checks**: Evaluate each Article requirement
4. **Add Findings**: Document non-compliance issues
5. **Submit for Review**: Request approval from compliance officer
6. **Approve/Reject**: Final decision on conformity status

### API Endpoints

```http
# Create assessment
POST /api/v1/conformity/assessments
{
  "org_id": "org-123",
  "name": "Q4 2025 Conformity Assessment",
  "type": "self_assessment",
  "risk_category": "high"
}

# Start assessment
POST /api/v1/conformity/assessments/{id}/start

# Update compliance check
PUT /api/v1/conformity/assessments/{id}/checks/{checkId}
{
  "status": "pass",
  "score": 95.0,
  "evidence": "Documentation available at /docs/article-12-compliance.pdf",
  "checked_by": "compliance@company.com"
}

# Add finding
POST /api/v1/conformity/assessments/{id}/findings
{
  "title": "Incomplete audit trail",
  "severity": "high",
  "article": "article_12",
  "description": "Audit logs missing for batch processing",
  "remediation": "Enable batch audit logging in config"
}

# Submit for review
POST /api/v1/conformity/assessments/{id}/submit

# Approve assessment
POST /api/v1/conformity/assessments/{id}/approve
{
  "approved_by": "ciso@company.com",
  "comments": "All checks verified"
}

# Get compliance summary
GET /api/v1/conformity/summary?org_id=org-123
```

### Assessment Types

| Type | Description | Applicable |
|------|-------------|------------|
| `self_assessment` | Internal compliance review | All high-risk AI |
| `third_party` | External auditor assessment | Certain categories |
| `notified_body` | Assessment by EU notified body | Biometric, critical infrastructure |
| `market_surveillance` | Authority-initiated review | Post-deployment |

### Risk Categories

| Category | Description | Requirements |
|----------|-------------|--------------|
| `unacceptable` | Prohibited AI systems | Not allowed in EU |
| `high` | High-risk AI systems | Full conformity assessment |
| `limited` | Limited risk systems | Transparency obligations |
| `minimal` | Minimal risk systems | Voluntary codes |

## Prometheus Metrics

AxonFlow exposes Prometheus metrics for compliance monitoring:

```
# HITL metrics
hitl_decisions_total{org_id, status}
hitl_decision_latency_seconds{org_id, quantile}
hitl_queue_depth{org_id}

# Accuracy metrics
accuracy_score{org_id, agent_id, metric_type}
bias_score{org_id, agent_id, category}
accuracy_alerts_total{org_id, severity}

# Circuit breaker metrics
circuit_breaker_state{org_id}
circuit_breaker_activations_total{org_id, reason}

# Conformity metrics
conformity_assessments_total{org_id, type, risk_category}
conformity_assessment_status{org_id, status}
conformity_compliance_score{org_id, article}
```

## Getting Started

1. **Enable EU AI Act features** in your AxonFlow configuration
2. **Configure HITL policies** for high-risk decisions
3. **Set up audit retention** per regulatory requirements
4. **Run conformity assessment** before deployment
5. **Monitor metrics** for ongoing compliance

For detailed setup instructions, see the [Enterprise Installation Guide](/docs/enterprise/installation.md).

## Related Documentation

- [PII Detection](../guides/pii-detection.md)
- [SEBI Compliance](./sebi-compliance.md)
- [Policy Templates](../reference/policy-templates.md)
