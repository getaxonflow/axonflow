# Configurable Agents Guide

**Last Updated:** February 2026

**Platform Version:** v5.0.0

Configure Multi-Agent Planning (MAP) agents using YAML files instead of hardcoded templates.

## Overview

MAP v1.0 introduces user-configurable agents via YAML configuration files. This allows you to:

- Define custom agents for your domain
- Configure routing patterns to match queries to agents
- Customize execution modes (parallel vs sequential)
- Add domain-specific synthesis prompts

## Quick Start

### 1. Create Configuration Directory

```bash
mkdir -p ./agents
```

### 2. Create Domain Configuration

Create `./agents/travel.yaml`:

```yaml
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: travel-domain
  domain: travel
  description: "Travel planning agents"

spec:
  execution:
    default_mode: parallel
    max_parallel_tasks: 5
    timeout_seconds: 300

  agents:
    - name: flight-search
      description: "Searches for flights"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-sonnet-4
        temperature: 0.3
      prompt_template: |
        Search for flights: {{.query}}
        Consider budget constraints and preferences.

  routing:
    - pattern: "flight|fly|airline"
      agent: flight-search
      priority: 10

  synthesis:
    enabled: true
    prompt_template: |
      Create a comprehensive travel plan from all gathered information.
```

### 3. Start Orchestrator

The orchestrator automatically loads configs from `./agents/` on startup.

```bash
./orchestrator serve
# Output: [PlanningEngine] Loaded agent configs from ./agents: [travel]
```

## Configuration Schema

### Full Example

```yaml
apiVersion: axonflow.io/v1
kind: AgentConfig
metadata:
  name: my-domain
  domain: mydomain
  description: "My custom domain agents"

spec:
  execution:
    default_mode: parallel    # parallel, sequential, or auto
    max_parallel_tasks: 5     # Max concurrent tasks
    timeout_seconds: 300      # Per-task timeout
    hints: |
      Domain-specific execution hints for the planning engine.

  agents:
    # LLM-based agent
    - name: analyzer
      description: "Analyzes queries"
      type: llm-call
      llm:
        provider: anthropic
        model: claude-sonnet-4
        temperature: 0.3
        max_tokens: 2500
      prompt_template: |
        Analyze the following: {{.query}}

    # Connector-based agent
    - name: data-fetcher
      description: "Fetches data from external source"
      type: connector-call
      connector:
        name: my-connector
        operation: query

  routing:
    - pattern: "analyze|review|assess"
      agent: analyzer
      priority: 10
    - pattern: "fetch|get|retrieve"
      agent: data-fetcher
      priority: 8

  synthesis:
    enabled: true
    prompt_template: |
      Synthesize results from all agents into a final response.
```

### Field Reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `apiVersion` | Yes | - | Must be `axonflow.io/v1` |
| `kind` | Yes | - | Must be `AgentConfig` |
| `metadata.name` | Yes | - | Unique config identifier |
| `metadata.domain` | Yes | - | Domain key for routing |
| `spec.execution.default_mode` | No | `auto` | Execution strategy |
| `spec.execution.max_parallel_tasks` | No | `5` | Concurrency limit |
| `spec.execution.timeout_seconds` | No | `300` | Task timeout |
| `spec.agents` | Yes | - | List of agent definitions |
| `spec.routing` | No | - | Query-to-agent routing rules |
| `spec.synthesis.enabled` | No | `true` | Enable result synthesis |

## Agent Types

### LLM Call Agent

Uses an LLM provider to process queries:

```yaml
agents:
  - name: my-llm-agent
    type: llm-call
    llm:
      provider: anthropic      # anthropic, openai, bedrock
      model: claude-sonnet-4   # Model identifier
      temperature: 0.3         # 0.0-2.0, lower = more deterministic
      max_tokens: 2500         # Max response tokens
    prompt_template: |
      Process: {{.query}}
```

**Temperature Guide:**

| Range | Behavior | Use Cases |
|-------|----------|-----------|
| **0.0-0.3** | Highly deterministic, consistent, factual | Data retrieval, code generation, financial analysis, medical diagnosis |
| **0.4-0.7** | Balanced creativity and consistency | Recommendations, travel planning, general assistance |
| **0.8-1.2** | Creative, varied responses | Brainstorming, content writing, creative fiction |
| **1.3-2.0** | Very creative, potentially unpredictable | Experimental use, artistic content (rarely needed) |

### Connector Call Agent

Calls an MCP connector:

```yaml
agents:
  - name: my-connector-agent
    type: connector-call
    connector:
      name: amadeus-travel     # Connector name
      operation: query         # Operation type
```

## Routing Rules

Routing rules match queries to agents using regex patterns:

```yaml
routing:
  - pattern: "flight|fly|airline|airport"
    agent: flight-search
    priority: 10
  - pattern: "hotel|stay|accommodation"
    agent: hotel-search
    priority: 10
  - pattern: ".*"                          # Catch-all
    agent: general-assistant
    priority: 1
```

### How Routing Works

1. Query text is matched against all patterns (case-insensitive)
2. Matching rules are sorted by priority (highest first)
3. First match determines the agent
4. No match falls back to domain's default agent

### Pattern Examples

| Pattern | Matches |
|---------|---------|
| `flight\|fly` | "book a flight", "fly to Paris" |
| `hotel.*book` | "hotel booking", "book a hotel" |
| `\d+ day` | "5 day trip", "3 day vacation" |
| `.*` | Everything (catch-all) |

## Execution Modes

### Parallel (Default for Travel/Finance)

Independent tasks run concurrently:

```yaml
spec:
  execution:
    default_mode: parallel
    max_parallel_tasks: 5
```

Best for: Travel planning, financial analysis, research tasks.

### Sequential (Default for Healthcare)

Tasks run one after another:

```yaml
spec:
  execution:
    default_mode: sequential
```

Best for: Medical diagnosis, approval workflows, dependent tasks.

### Auto

Planning engine decides based on query analysis:

```yaml
spec:
  execution:
    default_mode: auto
```

## Config Loading Priority

The orchestrator searches for configs in this order:

1. `./agents/` (relative to working directory)
2. `/etc/axonflow/agents/` (system-wide)
3. `~/.axonflow/agents/` (user-specific)

## Hot Reload (Development)

During development, reload configs without restart:

```bash
curl -X POST http://localhost:8080/api/v1/agents/reload
```

Or programmatically:

```go
engine.ReloadAgentConfigs()
```

## SDK Examples

### Go SDK

Use the Go SDK to send queries that are routed to configurable agents:

```go
package main

import (
	"context"
	"fmt"
	"log"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	client, err := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     "http://localhost:8080",
		ClientID:     "demo-org",
		ClientSecret: "your-license-key",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Query routed to the travel domain's flight-search agent
	resp, err := client.ProxyLLMCall(
		"user-123",
		"Find flights from NYC to London in March",
		"chat",
		map[string]interface{}{
			"provider": "anthropic",
			"domain":   "travel",
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Response:", resp.Content)
	fmt.Println("Agent Used:", resp.Metadata["agent"])
}
```

### Python SDK

```python
from axonflow import AxonFlow

client = AxonFlow(
    endpoint="http://localhost:8080",
    client_id="demo-org",
    client_secret="your-license-key",
)

# Query routed to the travel domain's flight-search agent
response = client.proxy_llm_call(
    user_token="user-123",
    query="Find flights from NYC to London in March",
    request_type="chat",
    context={
        "provider": "anthropic",
        "domain": "travel",
    },
)
print(f"Response: {response.content}")
print(f"Agent Used: {response.metadata.get('agent')}")
```

### TypeScript SDK

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'demo-org',
  clientSecret: 'your-license-key',
});

// Query routed to the travel domain's flight-search agent
const response = await client.proxyLLMCall({
  userToken: 'user-123',
  query: 'Find flights from NYC to London in March',
  requestType: 'chat',
  context: {
    provider: 'anthropic',
    domain: 'travel',
  },
});
console.log('Response:', response.content);
console.log('Agent Used:', response.metadata?.agent);
```

### Java SDK

```java
import com.axonflow.sdk.AxonFlowClient;

AxonFlowClient client = AxonFlowClient.builder()
    .endpoint("http://localhost:8080")
    .clientId("demo-org")
    .clientSecret("your-license-key")
    .build();

// Query routed to the travel domain's flight-search agent
var response = client.proxyLlmCall(
    "user-123",
    "Find flights from NYC to London in March",
    "chat",
    Map.of("provider", "anthropic", "domain", "travel")
);
System.out.println("Response: " + response.getContent());
System.out.println("Agent Used: " + response.getMetadata().get("agent"));
```

### Authentication

All SDK examples above use `X-Client-Id` and `X-Client-Secret` headers for authentication (set via the `clientId`/`clientSecret` constructor parameters). Alternatively, you can use `Authorization: Basic` with Base64-encoded `clientId:clientSecret`.

### cURL

```bash
curl -X POST http://localhost:8080/api/v1/query/execute \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: demo-org" \
  -H "X-Client-Secret: your-license-key" \
  -d '{
    "user_token": "user-123",
    "query": "Find flights from NYC to London in March",
    "request_type": "chat",
    "context": {
      "provider": "anthropic",
      "domain": "travel"
    }
  }'
```

## Default Configurations

AxonFlow includes default configs for common domains:

| Domain | File | Mode | Agents |
|--------|------|------|--------|
| Travel | `travel.yaml` | parallel | 5 |
| Healthcare | `healthcare.yaml` | sequential | 5 |
| Finance | `finance.yaml` | parallel | 5 |
| Generic | `generic.yaml` | auto | 4 |

## Validation

Configs are validated on load:

- **API Version**: Must be `axonflow.io/v1`
- **Kind**: Must be `AgentConfig`
- **Domain**: Must be unique across all configs
- **Patterns**: Must be valid regex, no ReDoS vulnerabilities
- **Agents**: Must have name and type

Invalid configs prevent orchestrator startup with detailed error messages.

## Troubleshooting

### Config Not Loading

Check orchestrator logs for:
```
[PlanningEngine] Loaded agent configs from ./agents: [domain1 domain2]
```

If missing, verify:
- Config directory exists
- Files have `.yaml` or `.yml` extension
- YAML syntax is valid

### Routing Not Matching

Enable debug logging to see routing decisions:
```
[AgentRegistry] RouteTask: query="book flight" matched agent="flight-search" domain="travel"
```

### Invalid Regex Pattern

Error message will indicate the problematic pattern:
```
invalid routing pattern "(?=.*a)": regex compilation failed
```

## Best Practices

### Routing Rules

1. **Always include a fallback rule**: Add a catch-all pattern with lowest priority
   ```yaml
   routing:
     - pattern: "specific|keywords"
       agent: specific-agent
       priority: 10
     - pattern: ".*"              # Catches everything else
       agent: default-agent
       priority: 1
   ```

2. **Use specific patterns first**: Higher priority for more specific matches
3. **Test your patterns**: Verify regex matches expected queries before deployment

### Agent Configuration

1. **Use descriptive names**: `flight-search` instead of `agent1`
2. **Set appropriate temperatures**: Lower for factual tasks, higher for creative
3. **Limit max_tokens**: Prevent unexpectedly long responses

### Performance

1. **Set realistic timeouts**: Default is 300 seconds (5 minutes)
2. **Limit parallel tasks**: Consider downstream API rate limits

---

## Migration from Hardcoded Templates

Existing deployments work without changes. To migrate:

1. Create `./agents/` directory
2. Copy default configs or create custom ones
3. Restart orchestrator
4. Verify logs show configs loaded

The orchestrator automatically uses configs when available, falling back to hardcoded templates otherwise.

---

## Common Errors

### "duplicate domain 'X' found"

Two YAML files define the same domain. Each domain must be unique.

**Fix**: Remove duplicate or rename one domain.

### "invalid routing pattern: regex compilation failed"

Pattern contains invalid regex syntax.

**Fix**: Test pattern at [regex101.com](https://regex101.com) (select Go flavor).

### "pattern too long: max 1000 characters"

Routing pattern exceeds maximum length (security limit).

**Fix**: Simplify pattern or split into multiple rules.

### "agent 'X' not found in agents list"

Routing rule references non-existent agent.

**Fix**: Ensure agent name in routing matches an agent definition exactly.
