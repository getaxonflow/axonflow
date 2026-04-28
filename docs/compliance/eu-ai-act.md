# EU AI Act Compliance Guide

*Last updated: April 2026 | AxonFlow Platform v6.0.0 | SDKs: Python v6.1.0, Go v5.1.0, TypeScript v5.1.0, Java v5.1.0*

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
X-AI-Decision-ID: dec-20260207-12345
X-AI-Trace-ID: trace-abc123
X-AI-Model: claude-sonnet-4-20250514
X-AI-Processing-Time-Ms: 1234
X-AI-Confidence: 0.95
X-AI-Human-Oversight: none
X-AI-Data-Sources: internal-db,customer-data
```

### Audit Log Format

Decision chains are stored in a structured format:

```json
{
  "decision_id": "dec-20260207-12345",
  "trace_id": "trace-abc123",
  "timestamp": "2026-02-07T12:34:56Z",
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
    "model_id": "claude-sonnet-4-20250514"
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

```bash
# List pending HITL decisions
curl -X GET "https://your-axonflow-host/api/v1/hitl/decisions?status=pending&org_id=org-123" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret"
# Alternative auth: -H "Authorization: Basic <base64(client_id:client_secret)>"

# Approve a decision
curl -X POST "https://your-axonflow-host/api/v1/hitl/decisions/{id}/approve" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "approved_by": "reviewer@company.com",
    "comments": "Verified against policy guidelines"
  }'

# Reject a decision
curl -X POST "https://your-axonflow-host/api/v1/hitl/decisions/{id}/reject" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "rejected_by": "reviewer@company.com",
    "reason": "Missing required documentation"
  }'

# Get HITL metrics
curl -X GET "https://your-axonflow-host/api/v1/hitl/metrics?org_id=org-123" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret"
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

```bash
# List exports
curl -X GET "https://your-axonflow-host/api/v1/euaiact/export" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Create export request
curl -X POST "https://your-axonflow-host/api/v1/euaiact/export" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123" \
  -H "Content-Type: application/json" \
  -d '{
    "export_type": "full_audit",
    "format": "json",
    "date_from": "2025-01-01T00:00:00Z",
    "date_to": "2025-12-31T23:59:59Z",
    "model_ids": ["model-123", "model-456"]
  }'

# Get export status
curl -X GET "https://your-axonflow-host/api/v1/euaiact/export/{id}" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Download export
curl -X GET "https://your-axonflow-host/api/v1/euaiact/export/{id}/download" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"
```

### Export Types

| Type | Description |
|------|-------------|
| `full_audit` | Complete audit trail with all decisions |
| `conformity_evidence` | Evidence for conformity assessment |
| `hitl_summary` | Human-in-the-loop decision summary |
| `decision_chain` | Full decision chain with context |
| `policy_violations` | Policy violation records |
| `accuracy_metrics` | Model accuracy and bias metrics |

## EU AI Act Export Format (Enterprise)

Export audit data in the format specified by EU AI Act technical standards.

### Export Structure

```json
{
  "export_metadata": {
    "format_version": "1.0",
    "regulation": "EU_AI_ACT_2024_1689",
    "generated_at": "2026-02-07T12:00:00Z",
    "org_id": "org-123"
  },
  "system_info": {
    "provider": "AxonFlow Enterprise",
    "version": "4.2.0",
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

```bash
# Activate circuit breaker
curl -X POST "https://your-axonflow-host/api/v1/circuit-breaker/activate" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "org-123",
    "reason": "Detected bias in loan decisions",
    "activated_by": "compliance@company.com"
  }'

# Check circuit breaker status
curl -X GET "https://your-axonflow-host/api/v1/circuit-breaker/status?org_id=org-123" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret"

# Deactivate circuit breaker
curl -X POST "https://your-axonflow-host/api/v1/circuit-breaker/deactivate" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "org-123",
    "deactivated_by": "compliance@company.com",
    "resolution": "Bias detected in training data, model retrained"
  }'
```

## Accuracy Metrics & Bias Detection (Enterprise)

Monitor AI system accuracy and detect potential biases.

### Accuracy Metrics

```bash
# Get accuracy summary
curl -X GET "https://your-axonflow-host/api/v1/euaiact/accuracy" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Record a metric
curl -X POST "https://your-axonflow-host/api/v1/euaiact/accuracy/record" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "model-456",
    "metric_type": "precision",
    "value": 0.95,
    "sample_size": 10000,
    "context": {
      "task_type": "classification",
      "dataset": "validation_set_2025q4"
    }
  }'

# Get accuracy history
curl -X GET "https://your-axonflow-host/api/v1/euaiact/accuracy/history?model_id=model-456&period=30d" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"
```

### Bias Detection

```bash
# Record bias measurement
curl -X POST "https://your-axonflow-host/api/v1/euaiact/accuracy/bias" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "model-456",
    "category": "gender",
    "group_metrics": {
      "male": {"count": 5000, "positive_rate": 0.78},
      "female": {"count": 5000, "positive_rate": 0.69}
    }
  }'

# Get alerts (including bias alerts)
curl -X GET "https://your-axonflow-host/api/v1/euaiact/accuracy/alerts" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Acknowledge alert
curl -X PUT "https://your-axonflow-host/api/v1/euaiact/accuracy/alerts/{id}" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "acknowledged",
    "acknowledged_by": "compliance@company.com"
  }'
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

```bash
# List assessments
curl -X GET "https://your-axonflow-host/api/v1/euaiact/conformity" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Create assessment
curl -X POST "https://your-axonflow-host/api/v1/euaiact/conformity" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 2026 Conformity Assessment",
    "assessment_type": "self_assessment",
    "risk_category": "high",
    "system_name": "Customer Support AI",
    "system_version": "1.0.0"
  }'

# Get assessment details
curl -X GET "https://your-axonflow-host/api/v1/euaiact/conformity/{id}" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Submit for review
curl -X POST "https://your-axonflow-host/api/v1/euaiact/conformity/{id}/submit" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123"

# Approve assessment
curl -X POST "https://your-axonflow-host/api/v1/euaiact/conformity/{id}/approve" \
  -H "X-Client-Id: your-client-id" \
  -H "X-Client-Secret: your-client-secret" \
  -H "X-Org-ID: org-123" \
  -H "Content-Type: application/json" \
  -d '{
    "approved_by": "ciso@company.com",
    "comments": "All checks verified"
  }'
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

## SDK Integration

Proxy LLM calls through AxonFlow with EU AI Act compliance policies applied automatically. Decision chains, transparency headers, and audit logs are generated for every request.

**Go:**

```go
import "github.com/getaxonflow/axonflow-sdk-go/v6/axonflow"

client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "https://your-axonflow-host",
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
})

response, err := client.ProxyLLMCall(
    "user-eu-001",
    "Assess this loan application for regulatory compliance",
    "loan_assessment",
    map[string]interface{}{"region": "eu", "risk_level": "high"},
)
// Decision chain trace ID is available in response headers
// HITL will be triggered if confidence < threshold per policy
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
    user_token="user-eu-001",
    query="Assess this loan application for regulatory compliance",
    request_type="loan_assessment",
    context={"region": "eu", "risk_level": "high"},
)
# Decision chain trace ID is available in response headers
# HITL will be triggered if confidence < threshold per policy
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
  'user-eu-001',
  'Assess this loan application for regulatory compliance',
  'loan_assessment',
  { region: 'eu', risk_level: 'high' },
);
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
    "user-eu-001",
    "Assess this loan application for regulatory compliance",
    "loan_assessment",
    Map.of("region", "eu", "risk_level", "high")
);
```

## Getting Started

1. **Enable EU AI Act features** in your AxonFlow configuration
2. **Configure HITL policies** for high-risk decisions
3. **Set up audit retention** per regulatory requirements
4. **Run conformity assessment** before deployment
5. **Monitor metrics** for ongoing compliance

For detailed setup instructions, see the [Enterprise Deployment Guide](https://enterprise-docs.getaxonflow.com/docs/deployment-guide/).

## Related Documentation

- [PII Detection](../guides/pii-detection.md)
- [SEBI Compliance](./sebi-compliance.md)
- [Policy Templates](../reference/policy-templates.md)
