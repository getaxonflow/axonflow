# Azure OpenAI PII Detection - Python

Demonstrates AxonFlow's PII detection and blocking with Azure OpenAI as the LLM provider.

## PII Types

| Type | Severity | PII_ACTION=block |
|------|----------|-----------------|
| US Social Security Number (SSN) | Critical | Blocked |
| Credit Card Number | Critical | Blocked |
| India Aadhaar Number | Critical | Blocked |
| India PAN Number | Low | Detected, not blocked |
| Email Address | Low | Detected, not blocked |
| Phone Number | Low | Detected, not blocked |

## Prerequisites

- AxonFlow running with `PII_ACTION=block`
- Python 3.10+

## Run

```bash
# Start AxonFlow with PII blocking enabled
PII_ACTION=block docker compose up -d

pip install -r requirements.txt
python main.py
```

## How It Works

1. AxonFlow scans queries for PII patterns before sending to Azure OpenAI
2. The `PII_ACTION` environment variable controls enforcement:
   - `block` — reject requests containing critical PII (SSN, credit cards, Aadhaar)
   - `redact` (default) — redact PII before forwarding to LLM
   - `warn` / `log` — allow with warning or audit logging
3. All detections are logged for audit in `policy_info.policies_evaluated`
