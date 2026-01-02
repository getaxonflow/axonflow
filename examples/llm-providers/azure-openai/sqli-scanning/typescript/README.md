# Azure OpenAI SQL Injection Detection - TypeScript

Demonstrates AxonFlow's SQL injection detection with Azure OpenAI as the LLM provider.

## SQL Injection Types Detected

- Classic SQL injection (OR 1=1)
- DROP TABLE attacks
- UNION-based injection
- TRUNCATE attacks
- Malicious stored procedures

## Prerequisites

- AxonFlow running with Azure OpenAI configured
- Node.js 18+

## Run

```bash
npm install
npm start
```

## How It Works

1. AxonFlow scans queries for SQL injection patterns
2. Blocked if dangerous SQL detected
3. Safe SQL questions (like "how to write a query") are allowed
4. All detections logged for audit
