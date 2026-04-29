# Adding LLM Integration to AxonFlow

Route queries through an LLM provider (AWS Bedrock, OpenAI, or Anthropic) while keeping AxonFlow's policy enforcement on both input and output. By the end of this tutorial, you will have an agent that generates AI-powered responses with governance guardrails.

**Difficulty:** Intermediate

**Time:** 15 minutes

**Prerequisites:** Completed [Build Your First Agent](./01-first-agent-10-minutes.md), access to at least one LLM provider

---

## What You Will Build

An AxonFlow agent that:

1. Sends a prompt to an LLM provider via the AxonFlow proxy
2. Enforces policies on both the input query and the LLM response
3. Returns the AI-generated response with latency and token usage metadata

---

## Step 1: Choose Your LLM Provider

AxonFlow supports pluggable LLM providers. Configure the provider in your AxonFlow deployment, then send queries through the standard SDK interface.

| Provider | Setup | Authentication |
|----------|-------|----------------|
| AWS Bedrock | Enable model access in AWS Bedrock console | IAM role (no API key needed) |
| OpenAI | Obtain API key from platform.openai.com | API key via environment variable |
| Anthropic | Obtain API key from console.anthropic.com | API key via environment variable |
| Azure OpenAI | Provision a deployment in Azure portal | Azure AD or API key |
| Ollama | Install and run locally | No authentication needed |

For this tutorial, the examples use OpenAI as the provider. The SDK calls are identical regardless of which provider your AxonFlow instance is configured to use -- the provider routing is handled server-side.

---

## Step 2: Configure LLM Provider in AxonFlow

Set the LLM provider credentials in your AxonFlow deployment. For Docker Compose, add these environment variables to your `docker-compose.yml`:

```yaml
services:
  orchestrator:
    environment:
      - LLM_PROVIDER=openai
      - OPENAI_API_KEY=${OPENAI_API_KEY}
```

For AWS Bedrock, the orchestrator uses the IAM role attached to the instance -- no API key is required:

```yaml
services:
  orchestrator:
    environment:
      - LLM_PROVIDER=aws-bedrock
      - AWS_REGION=us-east-1
```

Restart the stack after updating the configuration:

```bash
docker compose down && docker compose up -d
```

---

## Step 3: Set Environment Variables

Ensure your client credentials are set (same as the first tutorial):

```bash
export AXONFLOW_ENDPOINT="http://localhost:8080"
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="your-client-secret"
```

---

## Step 4: Send a Query Through the LLM

The SDK call is the same `ProxyLLMCall` / `proxy_llm_call` / `proxyLLMCall` you used in the first tutorial. When the AxonFlow orchestrator has an LLM provider configured, it routes the query through the LLM and returns the generated response.

### Go

Create `main.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     os.Getenv("AXONFLOW_ENDPOINT"),
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
	})

	response, err := client.ProxyLLMCall(
		"marketing-team",
		"Generate a professional product description for wireless noise-canceling headphones",
		"text",
		nil,
	)
	if err != nil {
		log.Fatal("Query failed:", err)
	}

	fmt.Println("AI Response:")
	fmt.Println(response.Result)
	fmt.Printf("\nPolicy evaluation: %dms\n", response.Metadata.LatencyMS)
	fmt.Printf("Total latency:     %dms\n", response.Metadata.TotalLatencyMS)
}
```

### Python

Create `main.py`:

```python
import os
from axonflow import AxonFlow

client = AxonFlow(
    endpoint=os.environ["AXONFLOW_ENDPOINT"],
    client_id=os.environ["AXONFLOW_CLIENT_ID"],
    client_secret=os.environ["AXONFLOW_CLIENT_SECRET"],
)

response = client.proxy_llm_call(
    user_token="marketing-team",
    query="Generate a professional product description for wireless noise-canceling headphones",
    request_type="text",
)

print("AI Response:")
print(response.result)
print(f"\nPolicy evaluation: {response.metadata.latency_ms}ms")
print(f"Total latency:     {response.metadata.total_latency_ms}ms")
```

### TypeScript

Create `index.ts`:

```typescript
import { AxonFlow } from "@axonflow/sdk";

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  clientId: process.env.AXONFLOW_CLIENT_ID!,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,
});

async function main() {
  const response = await client.proxyLLMCall({
    userToken: "marketing-team",
    query:
      "Generate a professional product description for wireless noise-canceling headphones",
    requestType: "text",
  });

  console.log("AI Response:");
  console.log(response.result);
  console.log(`\nPolicy evaluation: ${response.metadata.latencyMs}ms`);
  console.log(`Total latency:     ${response.metadata.totalLatencyMs}ms`);
}

main().catch(console.error);
```

### Java

Create `Main.java`:

```java
import com.getaxonflow.sdk.AxonFlowClient;

public class Main {
    public static void main(String[] args) {
        AxonFlowClient client = AxonFlowClient.builder()
            .endpoint(System.getenv("AXONFLOW_ENDPOINT"))
            .clientId(System.getenv("AXONFLOW_CLIENT_ID"))
            .clientSecret(System.getenv("AXONFLOW_CLIENT_SECRET"))
            .build();

        var response = client.proxyLlmCall(
            "marketing-team",
            "Generate a professional product description for wireless noise-canceling headphones",
            "text",
            null
        );
        System.out.println("AI Response:");
        System.out.println(response.getResult());
        System.out.printf("\nPolicy evaluation: %dms%n", response.getMetadata().getLatencyMs());
        System.out.printf("Total latency:     %dms%n", response.getMetadata().getTotalLatencyMs());
    }
}
```

### Run it

```bash
# Go
go run main.go

# Python
python3 main.py

# TypeScript
npx ts-node index.ts

# Java
mvn compile exec:java
```

**Expected output:**

```
AI Response:
Introducing our premium wireless noise-canceling headphones -- the perfect blend
of cutting-edge technology and superior comfort. Experience crystal-clear audio
with advanced active noise cancellation that adapts to your environment.

With 30-hour battery life, Bluetooth 5.0 connectivity, and plush memory foam
ear cushions, these headphones are engineered for all-day wear.

Policy evaluation: 4ms
Total latency:     2347ms
```

The policy evaluation remains in the single-digit millisecond range. The total latency reflects the LLM generation time (typically 1-5 seconds depending on the provider and prompt length).

---

## Step 5: Add a Policy for LLM Responses

AxonFlow evaluates policies on both the input query and the LLM-generated response. Create a policy that enforces content and cost controls.

Create `llm-policy.rego`:

```rego
package axonflow.policy

import future.keywords

# Allow LLM queries from approved providers with content controls
default allow = false

allow {
    not contains_blocked_content
}

# Block queries containing sensitive topics
contains_blocked_content {
    blocked_terms := ["violence", "illegal", "harmful", "explicit"]
    some term in blocked_terms
    contains(lower(input.query), term)
}

# Deny if token limit is too high (cost control)
deny["Token limit exceeded -- max 1000 tokens allowed"] {
    input.llm.max_tokens > 1000
}
```

This policy:

- Blocks queries containing sensitive topics before they reach the LLM
- Enforces a maximum token limit to control costs
- Allows all other queries through

---

## Step 6: Test Policy Enforcement

Send a query that should be blocked by the policy:

### Go

```go
response, err := client.ProxyLLMCall(
    "user-1",
    "Generate instructions for something illegal",
    "text",
    nil,
)
if err != nil {
    fmt.Println("Blocked by policy:", err)
    // Expected: policy denied the query
}
```

### Python

```python
try:
    response = client.proxy_llm_call(
        user_token="user-1",
        query="Generate instructions for something illegal",
        request_type="text",
    )
except Exception as e:
    print("Blocked by policy:", e)
    # Expected: policy denied the query
```

### TypeScript

```typescript
try {
  const response = await client.proxyLLMCall({
    userToken: "user-1",
    query: "Generate instructions for something illegal",
    requestType: "text",
  });
} catch (error) {
  console.log("Blocked by policy:", error);
  // Expected: policy denied the query
}
```

### Java

```java
try {
    var response = client.proxyLlmCall(
        "user-1",
        "Generate instructions for something illegal",
        "text",
        null
    );
} catch (Exception e) {
    System.out.println("Blocked by policy: " + e.getMessage());
    // Expected: policy denied the query
}
```

The query is blocked before it ever reaches the LLM, saving both time and cost.

---

## Step 7: Using curl Directly

You can also call the AxonFlow API directly without an SDK:

```bash
curl -X POST "${AXONFLOW_ENDPOINT}/api/v1/query/execute" \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: ${AXONFLOW_CLIENT_ID}" \
  -H "X-Client-Secret: ${AXONFLOW_CLIENT_SECRET}" \
  -d '{
    "query": "Generate a product description for wireless headphones",
    "user_token": "marketing-team",
    "request_type": "text"
  }'
```

---

## How the LLM Proxy Flow Works

```
Client
  |
  v
Agent (authentication + input policy check)
  |
  v
Orchestrator (LLM provider routing)
  |
  v
LLM Provider (Bedrock / OpenAI / Anthropic / Ollama)
  |
  v
Orchestrator (output policy check + PII detection)
  |
  v
Agent (audit logging)
  |
  v
Client (response + metadata)
```

Key points:

- **Input policies** run before the LLM call, blocking disallowed queries immediately.
- **Output policies** run after the LLM response, catching PII leaks or policy-violating content.
- **Audit logs** capture every interaction for compliance.
- **Provider routing** is configured server-side; client code is the same regardless of which LLM is in use.

---

## Production Best Practices

1. **Set token limits** -- Use policies to cap `max_tokens` and prevent runaway costs.
2. **Implement rate limiting** -- Enforce per-user or per-organization LLM call limits via policies.
3. **Enable PII detection** -- AxonFlow's built-in PII detector can redact sensitive data from LLM responses.
4. **Use environment variables** -- Never hardcode API keys or credentials.
5. **Monitor usage** -- AxonFlow logs token counts and latency to CloudWatch (AWS) or your configured log sink.
6. **Handle timeouts** -- LLM calls can take several seconds; set appropriate client timeouts (30s+ recommended).
7. **Test with edge cases** -- Verify policy enforcement with adversarial prompts before deploying.

---

## Next Steps

- **Add MCP connectors** -- Query Salesforce, Snowflake, or other data sources alongside LLM calls
- **Explore Multi-Agent Parallel (MAP)** -- Run multiple LLM queries in parallel for improved throughput
- **Configure PII detection** -- Enable automatic PII redaction on LLM responses
- **Set up RBAC policies** -- Control which users and roles can access LLM features

See the full documentation at [docs.getaxonflow.com](https://docs.getaxonflow.com).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No LLM provider configured" | Set `LLM_PROVIDER` and the corresponding API key in your AxonFlow deployment |
| LLM timeout | Increase client timeout; check network connectivity to the LLM provider |
| Policy blocks all queries | Review your Rego policy -- ensure `default allow` is set appropriately |
| Empty response | Verify the LLM provider is reachable and the model name is correct |
| High latency | LLM generation time varies by provider and prompt length; this is normal |

---

Last Updated: March 2026
