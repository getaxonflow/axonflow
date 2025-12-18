# AxonFlow Spring Boot Example

Production-grade Spring Boot integration with AxonFlow AI Governance.

## Features

- Configuration via `application.yml` and environment variables
- Bean-managed AxonFlow client (singleton, thread-safe)
- Gateway Mode implementation in service layer
- RESTful API with governance metadata
- Comprehensive logging and error handling
- Actuator health endpoints

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- Running AxonFlow Agent
- OpenAI API key

## Quick Start

1. **Start the AxonFlow stack:**

```bash
# From repository root
docker-compose up -d
```

2. **Set environment variables:**

```bash
export AXONFLOW_AGENT_URL=http://localhost:8080
export AXONFLOW_LICENSE_KEY=your-license-key
export OPENAI_API_KEY=your-openai-key
```

3. **Run the application:**

```bash
mvn spring-boot:run
```

4. **Test the API:**

```bash
# Safe query
curl -X POST http://localhost:8081/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-123","query":"What is clean code?"}'

# PII query (should be blocked)
curl -X POST http://localhost:8081/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"userId":"user-456","query":"My SSN is 123-45-6789"}'
```

## Project Structure

```
spring-boot/
├── pom.xml
├── src/main/java/com/axonflow/examples/springboot/
│   ├── Application.java              # Spring Boot entry point
│   ├── config/
│   │   └── AxonFlowConfiguration.java   # Bean definitions
│   ├── service/
│   │   └── AIAssistantService.java      # Gateway Mode implementation
│   └── controller/
│       └── AIAssistantController.java   # REST API
└── src/main/resources/
    └── application.yml               # Configuration
```

## Configuration

### application.yml

```yaml
axonflow:
  agent-url: ${AXONFLOW_AGENT_URL:http://localhost:8080}
  license-key: ${AXONFLOW_LICENSE_KEY:}
  timeout-seconds: 60
  debug: false
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AXONFLOW_AGENT_URL` | AxonFlow Agent URL | `http://localhost:8080` |
| `AXONFLOW_LICENSE_KEY` | License key for cloud | (empty) |
| `AXONFLOW_DEBUG` | Enable debug logging | `false` |
| `OPENAI_API_KEY` | OpenAI API key | (required) |

## API Reference

### POST /api/v1/assistant/query

Process a query through governed AI.

**Request:**
```json
{
  "userId": "user-123",
  "query": "What are best practices for API design?",
  "context": {
    "department": "engineering",
    "role": "developer"
  }
}
```

**Success Response (200):**
```json
{
  "success": true,
  "blocked": false,
  "response": "Best practices for API design include...",
  "requestId": "req_abc123",
  "promptTokens": 45,
  "completionTokens": 200,
  "preCheckLatencyMs": 4,
  "llmLatencyMs": 1200,
  "auditLatencyMs": 3,
  "governanceOverheadMs": 7
}
```

**Blocked Response (403):**
```json
{
  "success": false,
  "blocked": true,
  "blockedReason": "PII detected in request",
  "matchedPolicies": ["pii_ssn_detection"],
  "preCheckLatencyMs": 3,
  "governanceOverheadMs": 3
}
```

### GET /api/v1/assistant/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "ai-assistant"
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Spring Boot Application                   │
├─────────────────────────────────────────────────────────────┤
│  Controller (REST API)                                       │
│      ↓                                                       │
│  Service Layer (AIAssistantService)                         │
│      ↓                                                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Gateway Mode Pipeline                                │    │
│  │  1. Pre-check (AxonFlow) → 2. LLM (OpenAI) → 3. Audit│    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Best Practices

### 1. Singleton Client

The `AxonFlow` client is thread-safe. Create it once as a Spring bean:

```java
@Bean
public AxonFlow axonFlowClient() {
    return AxonFlow.create(config);
}
```

### 2. Non-Fatal Audit Failures

Audit logging should not block the response:

```java
try {
    axonFlow.auditLLMCall(...);
} catch (AxonFlowException e) {
    log.warn("Audit failed (non-fatal): {}", e.getMessage());
}
```

### 3. Include Context

Pass relevant metadata for policy decisions:

```java
ClientRequest.builder()
    .userPrompt(query)
    .userId(userId)
    .metadata(Map.of(
        "department", "engineering",
        "role", "developer"
    ))
    .build();
```

### 4. Handle Blocked Requests Gracefully

```java
if (!preCheck.isAllowed()) {
    return ResponseEntity.status(403).body(
        new ErrorResponse(preCheck.getBlockedReason())
    );
}
```

## Next Steps

- **Spring Security Integration**: See `ee/examples/spring-security/`
- **Multi-Tenant Configuration**: See `ee/examples/multi-tenant/`
- **AWS Bedrock Integration**: See `ee/examples/llm-providers/bedrock/`
