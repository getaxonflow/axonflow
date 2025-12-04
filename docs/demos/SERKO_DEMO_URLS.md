# Serko Demo URLs Quick Reference

**Purpose:** One-page reference for all URLs needed during the Serko demo
**Print this page** for quick access during the presentation

---

## Primary Demo URLs (Use These)

| Service | URL | Notes |
|---------|-----|-------|
| **Travel Demo** | https://travel-eu.getaxonflow.com | Main demo application |
| **Customer Portal** | https://app.getaxonflow.com | Audit logs & compliance |
| **Documentation** | https://docs.getaxonflow.com | Reference during Q&A |

---

## Backup/Staging URLs

Use these if primary URLs are unavailable:

| Service | Staging URL | Notes |
|---------|-------------|-------|
| Travel Demo | https://travel-staging-eu.getaxonflow.com | EU staging environment |
| Customer Portal | https://app-staging.getaxonflow.com | Staging portal |
| Agent Health | https://staging-eu.getaxonflow.com/health | Health check endpoint |

---

## Health Check Endpoints

Quick verification URLs (append to any service):

| Endpoint | Expected Response |
|----------|-------------------|
| `/health` | `{"status":"healthy"}` |
| `/api/health` | `{"status":"ok"}` |
| `/readiness` | `{"ready":true}` |

---

## Demo Credentials

| Environment | Email | Password |
|-------------|-------|----------|
| Demo Admin | demo@serko.com | *Retrieve from AWS Secrets Manager* |
| Staging Admin | staging@getaxonflow.com | *Retrieve from AWS Secrets Manager* |

**To retrieve credentials:**
```bash
aws secretsmanager get-secret-value \
  --secret-id axonflow/demo/credentials \
  --region eu-central-1 \
  --query SecretString \
  --output text | jq .
```

---

## Direct Navigation Links

### Customer Portal Pages

| Page | Direct URL |
|------|------------|
| Audit Logs | https://app.getaxonflow.com/audit |
| Policies | https://app.getaxonflow.com/policies |
| Dashboard | https://app.getaxonflow.com/dashboard |
| Settings | https://app.getaxonflow.com/settings |

### Documentation Pages

| Topic | Direct URL |
|-------|------------|
| EU AI Act Guide | https://docs.getaxonflow.com/compliance/eu-ai-act |
| SDK Reference | https://docs.getaxonflow.com/sdk |
| Go SDK | https://docs.getaxonflow.com/sdk/go |
| Python SDK | https://docs.getaxonflow.com/sdk/python |
| Policy Language | https://docs.getaxonflow.com/policies/syntax |

---

## Demo Scenario Details

### Scenario 1: Sarah Thompson

| Field | Value |
|-------|-------|
| Demo User | Sarah Thompson |
| Company | TechGlobal NZ |
| Booking | Auckland → Paris, 7 days, Luxury |
| Value | €8,500 |
| Policy Triggered | `eu_ai_act_high_value_transaction` |
| Expected Action | ALERT - Manual approval required |

### Scenario 2: James Wilson

| Field | Value |
|-------|-------|
| Demo User | James Wilson |
| Company | Kiwi Exports Ltd |
| Booking | Auckland → Frankfurt, 5 days, Moderate |
| Passport | LA987654 → LA****54 (redacted) |
| Policy Triggered | `eu_gdpr_cross_border_pii` |
| Expected Action | REDACT - Passport masked |

---

## API Endpoints (For Technical Deep-Dive)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/plan` | POST | Trip planning request |
| `/api/health` | GET | Health check |
| `/api/audit/search` | GET | Audit log search |
| `/api/audit/export` | GET | Export audit logs |
| `/api/compliance/summary` | GET | Compliance dashboard |

---

## Region Information

| Region | AWS Region | Endpoint Base |
|--------|------------|---------------|
| EU (Primary) | eu-central-1 | `.getaxonflow.com` |
| US | us-east-1 | `.us.getaxonflow.com` |
| APAC | ap-southeast-1 | `.apac.getaxonflow.com` |

**Note:** All demo URLs use EU region by default for data residency.

---

## Support & Escalation

| Type | Contact |
|------|---------|
| Demo Issues | #sales-engineering (Slack) |
| Infrastructure | #eng-oncall (Slack) |
| Customer Portal | support@getaxonflow.com |

---

## Browser Tab Order (Recommended)

For smooth demo flow, open tabs in this order:

1. **Tab 1:** Travel Demo - https://travel-eu.getaxonflow.com
2. **Tab 2:** Customer Portal Audit - https://app.getaxonflow.com/audit
3. **Tab 3:** Documentation - https://docs.getaxonflow.com (optional, for Q&A)

---

## Quick Copy-Paste URLs

```
Travel Demo:        https://travel-eu.getaxonflow.com
Customer Portal:    https://app.getaxonflow.com
Audit Logs:         https://app.getaxonflow.com/audit
Documentation:      https://docs.getaxonflow.com
EU AI Act Guide:    https://docs.getaxonflow.com/compliance/eu-ai-act
```

---

*Quick reference for Serko VP Infrastructure Demo - December 2025*
