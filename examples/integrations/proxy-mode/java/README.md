# AxonFlow Proxy Mode - Java

Proxy Mode provides the simplest integration path. AxonFlow handles all the complexity:

- Policy enforcement (pre and post)
- LLM routing and failover
- Response auditing
- Token tracking

You simply send a request and receive a governed response.

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- Running AxonFlow Agent with configured LLM providers

## Setup

1. Start the AxonFlow stack:

```bash
# From repository root
docker-compose up -d
```

2. Set environment variables:

```bash
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_LICENSE_KEY=your-license-key  # Required for cloud
```

**Note**: Unlike Gateway Mode, Proxy Mode does not require an OpenAI API key on the client side. AxonFlow handles LLM calls server-side.

## Run

```bash
mvn compile exec:java
```

## Expected Output

```
AxonFlow Proxy Mode - Java Example

Example 1: Safe Query
============================================================
Query: "What are the key principles of clean code?"
User: user-123

Status: APPROVED
Response:
The key principles of clean code include:
1. Meaningful names - Use intention-revealing names
2. Small functions - Each function should do one thing
3. DRY (Don't Repeat Yourself) - Avoid duplication
...

Tokens: 42 prompt, 180 completion

Latency: 1523ms

Example 2: Query with PII (Expected: Blocked)
============================================================
Query: "Process refund for customer with SSN 123-45-6789"
User: user-456

Status: BLOCKED
Blocked by: pii_ssn_detection
Reason: Social Security Number detected in request

Latency: 5ms

Example 3: SQL Injection (Expected: Blocked)
============================================================
Query: "Show me users WHERE 1=1; DROP TABLE users;--"
User: user-789

Status: BLOCKED
Blocked by: sql_injection_prevention
Reason: SQL injection pattern detected

Latency: 3ms

Proxy Mode Demo Complete!
```

## Code Example

```java
AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
    .agentUrl("http://localhost:8080")
    .licenseKey("your-license-key")
    .build());

ClientResponse response = client.executeQuery(
    ClientRequest.builder()
        .userPrompt("What are best practices for code review?")
        .userId("user-123")
        .model("gpt-3.5-turbo")  // Optional: specify model
        .build()
);

if (response.isAllowed()) {
    System.out.println(response.getLlmResponse());
} else {
    System.out.println("Blocked: " + response.getBlockedReason());
}
```

## When to Use Proxy Mode

- You want the simplest possible integration (single API call)
- You're OK with AxonFlow managing LLM provider configuration
- You want automatic provider failover
- You need centralized LLM cost management

## Proxy Mode vs Gateway Mode

| Feature | Proxy Mode | Gateway Mode |
|---------|-----------|--------------|
| Complexity | Single API call | 3-step workflow |
| LLM Control | AxonFlow manages | You manage |
| Latency | Higher (includes LLM) | Lower overhead |
| Failover | Automatic | You implement |
| API Keys | Server-side only | Client-side |

## Alternatives

- **Gateway Mode**: Full control with pre-check + LLM + audit workflow
- See `examples/integrations/gateway-mode/java/`
