# Azure OpenAI PII Detection - Python

Demonstrates AxonFlow's PII detection with Azure OpenAI as the LLM provider.

## PII Types Detected

- US Social Security Numbers (SSN)
- Credit Card Numbers
- India PAN Numbers
- India Aadhaar Numbers
- Email Addresses
- Phone Numbers (warning only)

## Prerequisites

- AxonFlow running with Azure OpenAI configured
- Python 3.8+

## Run

```bash
pip install -r requirements.txt
python main.py
```

## How It Works

1. AxonFlow scans queries for PII patterns before sending to Azure OpenAI
2. Blocked if sensitive PII found (SSN, credit cards, PAN, Aadhaar)
3. Warned but allowed for less sensitive PII (phone numbers)
4. All detections logged for audit
