# AutoGen + AxonFlow Integration (Java SDK)

This example demonstrates how to add AxonFlow governance to AutoGen-style multi-agent workflows using the Java SDK.

## Features

- **Gateway Mode**: Full control over LLM provider with AxonFlow policy enforcement
- **Multi-Agent Support**: Track conversations across multiple agents
- **PII Detection**: Block requests containing sensitive data
- **SQL Injection Prevention**: Detect and block injection attempts
- **Audit Logging**: Log all LLM interactions for compliance

## Prerequisites

- Java 17+
- Maven 3.6+
- AxonFlow running locally (`docker compose up`)

## Quick Start

```bash
# From this directory
mvn compile exec:java
```

## How It Works

### Gateway Mode Flow

1. **Pre-LLM Check**: Call `getPolicyApprovedContext()` before your LLM call
2. **Policy Evaluation**: AxonFlow checks for PII, SQL injection, etc.
3. **Your LLM Call**: If approved, make your call to OpenAI/Anthropic/etc.
4. **Audit Logging**: Call `auditLLMCall()` to log the response

```java
// 1. Get policy approval
PolicyApprovedContext approved = client.getPolicyApprovedContext(
    userToken,
    query,
    "chat",
    context
);

if (approved.isApproved()) {
    // 2. Make your LLM call
    String response = callOpenAI(query);

    // 3. Audit the interaction
    client.auditLLMCall(
        approved.getRequestId(),
        "openai",
        "gpt-4",
        response,
        TokenUsage.of(inputTokens, outputTokens, totalTokens),
        null
    );
}
```

### AutoGen Integration Pattern

For AutoGen's GroupChat, wrap each agent's LLM call:

```java
class GovernedAgent {
    private AxonFlow axonflow;
    private String agentName;

    public String chat(String message, String conversationId) {
        Map<String, Object> context = Map.of(
            "agent_name", agentName,
            "conversation_id", conversationId,
            "framework", "autogen"
        );

        PolicyApprovedContext approved = axonflow.getPolicyApprovedContext(
            userToken, message, "chat", context
        );

        if (!approved.isApproved()) {
            return "[Blocked: " + approved.getBlockReason() + "]";
        }

        String response = callLLM(message);

        axonflow.auditLLMCall(approved.getRequestId(), ...);

        return response;
    }
}
```

## Expected Output

```
Checking AxonFlow at http://localhost:8080...
Status: healthy

============================================================
AutoGen + AxonFlow Gateway Mode Example (Java SDK)
============================================================

[Test 1] Safe query - Research request
----------------------------------------
Query: What are the best practices for secure API design?
Approved: true
Request ID: req_abc123
Response: Best practices for secure API design include...
Audit logged successfully!
✓ Safe query processed successfully!

[Test 2] Query with PII - SSN Detection
----------------------------------------
Query: Process payment for customer with SSN 123-45-6789
Blocked: true
Block reason: Social Security Number detected
✓ PII correctly detected and blocked!

[Test 3] SQL Injection - Should be blocked
----------------------------------------
Query: SELECT * FROM users WHERE id=1; DROP TABLE users;--
Blocked: true
Block reason: SQL injection attempt detected
✓ SQL injection correctly blocked!

[Test 4] Multi-Agent Conversation (AutoGen Style)
----------------------------------------
Agent 'planner': ✓ Processed and audited
Agent 'researcher': ✓ Processed and audited
Agent 'critic': ✓ Processed and audited

============================================================
All tests completed!
============================================================
```

## Related Examples

- [Python SDK Example](../governed_agent.py) - Proxy Mode integration
- [AutoGen Documentation](https://microsoft.github.io/autogen/)
- [AxonFlow Java SDK](https://docs.getaxonflow.com/sdk/java-getting-started)
