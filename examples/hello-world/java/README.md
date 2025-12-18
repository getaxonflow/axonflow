# AxonFlow Hello World - Java

The simplest possible AxonFlow integration demonstrating policy validation without LLM calls.

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- Running AxonFlow Agent

## Setup

1. Start the AxonFlow stack:

```bash
# From repository root
docker-compose up -d
```

2. Set environment variables (optional):

```bash
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_LICENSE_KEY=your-license-key  # Required for cloud
```

## Run

```bash
mvn compile exec:java
```

## Expected Output

```
AxonFlow Hello World - Java
========================================

Test: Safe Query
  Query: What is the weather today?

  Result: APPROVED
  Request ID: req_abc123
  Test: PASS (expected approved)

Test: SQL Injection
  Query: SELECT * FROM users; DROP TABLE users;...

  Result: BLOCKED
  Reason: SQL injection detected
  Policies: sql_injection_prevention
  Test: PASS (expected blocked)

Test: PII (SSN)
  Query: Process payment for SSN 123-45-6789...

  Result: BLOCKED
  Reason: PII detected in request
  Policies: pii_ssn_detection
  Test: PASS (expected blocked)

========================================
Hello World Complete!

Next steps:
  - Gateway Mode: examples/integrations/gateway-mode/java/
  - Proxy Mode: examples/integrations/proxy-mode/java/
```

## What This Example Demonstrates

1. **Client Initialization** - Creating an AxonFlow client with configuration
2. **Policy Pre-Check** - Validating queries against governance policies
3. **Response Handling** - Checking approval status and policy matches

## Next Steps

- **Gateway Mode**: Full control with pre-check + LLM + audit workflow
- **Proxy Mode**: Simplified integration where AxonFlow handles LLM calls
