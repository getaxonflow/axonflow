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
2. The matched policy's stored action decides. Every shipped `sys_sqli_*` policy stores `warn`, so detected SQL injection is approved with a warning and the matched policy id is reported in the response's policy info; it is not blocked
3. To block it, record an organization override of category `sqli` with action `block` (Enterprise, customer portal API: `PUT /api/v1/detection-posture/sqli` with `{"action":"block"}`), or change the policy's action. With that override recorded this example fails by design. `SQLI_ACTION` no longer sets an action (v11)
4. Safe SQL questions (like "how to write a query") are allowed
5. All detections logged for audit
