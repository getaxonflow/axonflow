# Policy Management - CRUD Operations

Manage AxonFlow policies programmatically.

## Policy Types

AxonFlow has two types of policies:

### Static Policies (Agent)

Pattern-based rules evaluated at the Agent level:

- SQL injection detection
- PII detection (SSN, credit cards, etc.)
- Prompt injection detection
- Content filtering

**Endpoint:** `GET /api/v1/static-policies`

### Dynamic Policies (Orchestrator)

Condition-based rules with complex logic:

- RBAC (Role-Based Access Control)
- Risk scoring thresholds
- Rate limiting
- Cost optimization
- Tenant-specific rules

**Endpoint:** `/api/v1/policies` (CRUD operations)

## Quick Start

### 1. Start AxonFlow

```bash
docker compose up -d
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Run the Example

```bash
python main.py
```

## API Reference

### List Static Policies

```bash
curl -H "X-Tenant-ID: test-org-001" \
  http://localhost:8080/api/v1/static-policies
```

### List Dynamic Policies

```bash
curl -H "X-Tenant-ID: test-org-001" \
  http://localhost:8081/api/v1/policies/dynamic
```

### Create Policy

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: test-org-001" \
  -d '{
    "name": "high-risk-block",
    "description": "Block queries with high risk score",
    "enabled": true,
    "conditions": {
      "risk_score": {"gt": 0.8}
    },
    "action": "block",
    "priority": 100
  }' \
  http://localhost:8081/api/v1/policies
```

### Update Policy

```bash
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: test-org-001" \
  -d '{
    "description": "Updated description",
    "enabled": false
  }' \
  http://localhost:8081/api/v1/policies/{policy_id}
```

### Delete Policy

```bash
curl -X DELETE \
  -H "X-Tenant-ID: test-org-001" \
  http://localhost:8081/api/v1/policies/{policy_id}
```

## Policy Structure

```python
{
    "name": "policy-name",           # Unique identifier
    "description": "What it does",   # Human-readable description
    "enabled": True,                 # Active or disabled
    "conditions": {                  # When to apply
        "risk_score": {"gt": 0.8},
        "user_role": {"in": ["admin", "developer"]},
        "department": {"eq": "engineering"}
    },
    "action": "block",              # What to do (block, allow, redact, audit)
    "priority": 100,                # Order of evaluation (higher = first)
    "metadata": {                   # Custom data
        "created_by": "admin",
        "category": "security"
    }
}
```

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `{"department": {"eq": "engineering"}}` |
| `ne` | Not equals | `{"status": {"ne": "blocked"}}` |
| `gt` | Greater than | `{"risk_score": {"gt": 0.8}}` |
| `gte` | Greater or equal | `{"priority": {"gte": 5}}` |
| `lt` | Less than | `{"cost": {"lt": 100}}` |
| `lte` | Less or equal | `{"attempts": {"lte": 3}}` |
| `in` | In list | `{"role": {"in": ["admin", "dev"]}}` |
| `nin` | Not in list | `{"env": {"nin": ["test", "dev"]}}` |
| `contains` | String contains | `{"query": {"contains": "SELECT"}}` |
| `regex` | Regex match | `{"email": {"regex": "@company.com$"}}` |

## Policy Actions

| Action | Description |
|--------|-------------|
| `block` | Reject the request |
| `allow` | Allow the request |
| `redact` | Mask sensitive data in response |
| `audit` | Log but allow through |
| `escalate` | Send to HITL (Human-in-the-Loop) queue |

## Example Policies

### Block High-Risk Queries

```json
{
  "name": "block-high-risk",
  "conditions": {"risk_score": {"gt": 0.9}},
  "action": "block"
}
```

### Restrict by Department

```json
{
  "name": "finance-only",
  "description": "Only finance team can access financial data",
  "conditions": {
    "query_category": {"eq": "financial"},
    "department": {"ne": "finance"}
  },
  "action": "block"
}
```

### Rate Limit by Role

```json
{
  "name": "developer-rate-limit",
  "conditions": {
    "user_role": {"eq": "developer"},
    "requests_per_minute": {"gt": 100}
  },
  "action": "block"
}
```

### Audit Sensitive Queries

```json
{
  "name": "audit-pii-access",
  "conditions": {
    "data_classification": {"in": ["pii", "phi", "pci"]}
  },
  "action": "audit"
}
```

## Files

```
policies/crud/
├── main.py          # Python CRUD example
├── requirements.txt
├── .env.example
└── README.md
```

## Next Steps

- [Gateway Mode](../../integrations/gateway-mode/) - Pre-check policies before LLM calls
- [Proxy Mode](../../integrations/proxy-mode/) - Automatic policy enforcement
