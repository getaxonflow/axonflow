# AxonFlow Gateway Mode - Java

Gateway Mode provides the lowest latency AI governance by separating policy enforcement from LLM calls.

## Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
├─────────────────────────────────────────────────────────────┤
│  1. Pre-check    →   2. LLM Call    →   3. Audit            │
│  (AxonFlow)          (Your Code)        (AxonFlow)          │
│  ~3-5ms              ~500-2000ms        ~2-3ms              │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- Running AxonFlow Agent
- OpenAI API key

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
export OPENAI_API_KEY=your-openai-key
```

## Run

```bash
mvn compile exec:java
```

## Expected Output

```
AxonFlow Gateway Mode - Java Example

Query: "What are best practices for AI model deployment?"
User: user-789
Context: {user_role=engineer, department=platform}

Step 1: Policy Pre-Check...
   Completed in 4ms
   Request ID: req_abc123
   Approved: true

Step 2: LLM Call (OpenAI)...
   Response received in 1234ms
   Tokens: 45 prompt, 150 completion

Step 3: Audit Logging...
   Audit logged in 3ms

============================================================
Results
============================================================

Response:
Best practices for AI model deployment include:
1. Implement proper model versioning and rollback capabilities
2. Use containerization (Docker) for consistent environments
3. Set up comprehensive monitoring and alerting
...

Latency Breakdown:
   Pre-check:  4ms
   LLM call:   1234ms
   Audit:      3ms
   -----------------
   Governance: 7ms (overhead)
   Total:      1241ms
```

## Key Benefits

- **Full Control**: Make LLM calls with your own parameters and providers
- **Low Overhead**: ~3-5ms governance overhead (less than 1% of typical LLM latency)
- **Complete Audit Trail**: Every interaction logged for compliance
- **Policy Enforcement**: Block risky requests before they reach the LLM

## Code Walkthrough

### Step 1: Pre-Check

```java
PolicyApprovalResult preCheck = axonflow.getPolicyApprovedContext(
    ClientRequest.builder()
        .userPrompt(query)
        .userId(userId)
        .metadata(context)
        .build()
);

if (!preCheck.isAllowed()) {
    // Request blocked by policy - handle gracefully
    System.out.println("Blocked: " + preCheck.getBlockedReason());
    return;
}
```

### Step 2: Your LLM Call

```java
// Use any LLM provider - OpenAI, Anthropic, Azure, etc.
ChatCompletionResult completion = openai.createChatCompletion(chatRequest);
```

### Step 3: Audit

```java
ClientResponse audit = axonflow.auditLLMCall(
    AuditRequest.builder()
        .requestId(preCheck.getRequestId())  // Link to pre-check
        .llmResponse(response)
        .model("gpt-3.5-turbo")
        .tokenUsage(TokenUsage.builder()
            .promptTokens(promptTokens)
            .completionTokens(completionTokens)
            .build())
        .latencyMs(llmLatency)
        .build()
);
```

## When to Use Gateway Mode

- You need full control over LLM parameters
- You're integrating with existing LLM infrastructure
- You require the lowest possible governance overhead
- You need to use multiple LLM providers

## Alternatives

- **Proxy Mode**: Simpler integration where AxonFlow handles LLM calls
- See `examples/integrations/proxy-mode/java/`
