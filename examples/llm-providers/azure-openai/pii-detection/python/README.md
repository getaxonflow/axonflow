# Azure OpenAI PII Detection - Python

Demonstrates AxonFlow's PII detection with Azure OpenAI as the LLM provider.

## PII Types

With the shipped policy actions and no organization override (what this example validates):

| Type | Severity | Outcome |
|------|----------|---------|
| US Social Security Number (SSN) | Critical | Detected (`sys_pii_ssn`), warned, not blocked |
| Credit Card Number | Critical | Detected (`sys_pii_credit_card`), warned, not blocked |
| India Aadhaar Number | Critical | Not blocked |
| India PAN Number | Low | Not blocked |
| Email Address | Low | Not blocked |
| Phone Number | Low | Not blocked |

## Prerequisites

- AxonFlow running
- Python 3.10+

## Run

```bash
docker compose up -d

pip install -r requirements.txt
python main.py
```

## How It Works

1. AxonFlow scans queries for PII patterns before sending to Azure OpenAI
2. The matched policy's stored action decides. `sys_pii_ssn` and `sys_pii_credit_card` store `warn` for the request and `redact` for the response, so the request is forwarded and PII in the LLM response is redacted
3. To block PII, record an organization override of category `pii` with action `block` (Enterprise, customer portal API: `PUT /api/v1/detection-posture/pii` with `{"action":"block"}`), or change the policy's action. With that override recorded this example fails by design
4. All detections are reported in `policy_info.policies_evaluated`

> **Removed in v11:** `PII_ACTION` no longer sets an action. A deployment that still sets it keeps running; the agent logs a boot `WARN` and increments `axonflow_ignored_posture_env_total{name="PII_ACTION"}`.
