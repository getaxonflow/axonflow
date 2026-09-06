# Build Your First AxonFlow Agent in 10 Minutes

Build a working AxonFlow agent with inline policy enforcement. By the end of this tutorial, you will send a query through the AxonFlow Agent and see sub-10ms policy evaluation in action.

**Difficulty:** Beginner

**Time:** 10 minutes

**Prerequisites:** AxonFlow deployed (via Docker Compose or CloudFormation), basic programming knowledge

---

## What You Will Build

A client application that:

1. Connects to a running AxonFlow Agent
2. Sends a natural language query with an inline policy
3. Receives a policy-evaluated response with latency metadata

---

## Prerequisites

Before starting, confirm you have:

- A running AxonFlow instance (see the [Getting Started Guide](../getting-started.md) for deployment options)
- Your **Agent Endpoint URL** (e.g., `http://localhost:8080` for local Docker, or from CloudFormation Outputs)
- Your **Client ID** and **Client Secret** (from CloudFormation Outputs or your deployment configuration)
- One of the following installed:
  - **Go 1.25+** (`go version`)
  - **Python 3.10+** (`python3 --version`)
  - **Node.js 18+** (`node --version`)
  - **Java 17+** and **Maven 3.8+** (`java --version`, `mvn --version`)

---

## Step 1: Project Setup

Choose your language and set up the project.

### Go

```bash
mkdir my-first-agent && cd my-first-agent
go mod init my-first-agent
go get github.com/getaxonflow/axonflow-sdk-go/v9
```

### Python

```bash
mkdir my-first-agent && cd my-first-agent
pip3 install axonflow==9.0.0
```

### TypeScript

```bash
mkdir my-first-agent && cd my-first-agent
npm init -y
npm install @axonflow/sdk
npm install --save-dev typescript @types/node ts-node
npx tsc --init
```

### Java

```bash
# For Maven projects, add to pom.xml:
# <dependency>
#     <groupId>com.getaxonflow</groupId>
#     <artifactId>axonflow-sdk</artifactId>
#     <version>9.3.0</version>
# </dependency>
```

---

## Step 2: Set Environment Variables

Store your credentials in environment variables rather than hardcoding them:

```bash
export AXONFLOW_ENDPOINT="http://localhost:8080"
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="your-client-secret"
```

> **Security:** Never commit credentials to version control. Use environment variables or a secrets manager in production.

---

## Step 3: Write the Agent Code

### Go

Create `main.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

func main() {
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     os.Getenv("AXONFLOW_ENDPOINT"),
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
	})

	response, err := client.ProxyLLMCall(
		"user-1",                           // userToken
		"What is the capital of France?",   // query
		"text",                             // requestType
		nil,                                // context (optional)
	)
	if err != nil {
		log.Fatal("Query failed:", err)
	}

	fmt.Println("Response:", response.Result)
	fmt.Printf("Policy evaluation latency: %dms\n", response.Metadata.LatencyMS)
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
    user_token="user-1",
    query="What is the capital of France?",
    request_type="text",
)

print("Response:", response.result)
print(f"Policy evaluation latency: {response.metadata.latency_ms}ms")
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
    userToken: "user-1",
    query: "What is the capital of France?",
    requestType: "text",
  });

  console.log("Response:", response.result);
  console.log(`Policy evaluation latency: ${response.metadata.latencyMs}ms`);
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
            "user-1",
            "What is the capital of France?",
            "text",
            null
        );
        System.out.println("Response: " + response.getResult());
        System.out.printf("Policy evaluation latency: %dms%n", response.getMetadata().getLatencyMs());
    }
}
```

---

## Step 4: Run It

### Go

```bash
go run main.go
```

### Python

```bash
python3 main.py
```

### TypeScript

```bash
npx ts-node index.ts
```

### Java

```bash
mvn compile exec:java
```

**Expected output:**

```
Response: The capital of France is Paris.
Policy evaluation latency: 4ms
```

The policy evaluation latency (typically under 10ms) is the time AxonFlow spent evaluating governance rules before allowing the query through. This is the core of AxonFlow's low-latency inline enforcement.

---

## What Just Happened?

When you sent the query, the following occurred:

1. **Authentication** -- The Agent validated your Client ID and Client Secret.
2. **Policy evaluation** -- The Agent compiled and evaluated the applicable policies (in ~4ms).
3. **Query processing** -- The query was processed and a response generated.
4. **Audit logging** -- The entire interaction was logged for compliance and audit trails.

```
Client  ──►  Agent  ──►  Policy Engine  ──►  Query Processing  ──►  Response
                              │
                         Audit Log
```

---

## Step 5: Try a Custom Inline Policy

You can pass a Rego policy inline to control what queries are allowed. Update your code to include a policy that blocks queries containing the word "secret":

### Go

```go
response, err := client.ProxyLLMCall(
    "user-1",
    "Tell me a secret",
    "text",
    map[string]interface{}{
        "policy": `
            package axonflow.policy
            default allow = true
            deny["Queries about secrets are blocked"] {
                contains(lower(input.query), "secret")
            }
        `,
    },
)
```

### Python

```python
response = client.proxy_llm_call(
    user_token="user-1",
    query="Tell me a secret",
    request_type="text",
    context={
        "policy": """
            package axonflow.policy
            default allow = true
            deny["Queries about secrets are blocked"] {
                contains(lower(input.query), "secret")
            }
        """
    },
)
```

### TypeScript

```typescript
const response = await client.proxyLLMCall({
  userToken: "user-1",
  query: "Tell me a secret",
  requestType: "text",
  context: {
    policy: `
      package axonflow.policy
      default allow = true
      deny["Queries about secrets are blocked"] {
        contains(lower(input.query), "secret")
      }
    `,
  },
});
```

### Java

```java
var response = client.proxyLlmCall(
    "user-1",
    "Tell me a secret",
    "text",
    java.util.Map.of("policy", """
        package axonflow.policy
        default allow = true
        deny["Queries about secrets are blocked"] {
            contains(lower(input.query), "secret")
        }
    """)
);
```

Run this and observe that the query is blocked by your policy.

---

## Next Steps

Now that you have a working agent:

- **[Add LLM Integration](./02-llm-integration.md)** -- Connect to AWS Bedrock, OpenAI, or other LLM providers
- **Add real policies** -- Implement RBAC, PII detection, and content filtering
- **Use MCP connectors** -- Query Salesforce, Snowflake, or other data sources
- **Explore Multi-Agent Parallel (MAP)** -- Run parallel queries for improved throughput

See the full documentation at [docs.getaxonflow.com](https://docs.getaxonflow.com).

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | Verify AxonFlow is running and `AXONFLOW_ENDPOINT` is correct |
| Authentication error | Check `AXONFLOW_CLIENT_ID` and `AXONFLOW_CLIENT_SECRET` values |
| Policy denied | Review the policy rules -- the default policy may be blocking your query |
| SDK import error | Verify the SDK is installed (`go get`, `pip3 install`, or `npm install`) |

---

## API Reference

The examples above use the SDK, which internally calls the AxonFlow Agent REST API:

```
POST /api/v1/query/execute
Headers:
  X-Client-Id: your-client-id
  X-Client-Secret: your-client-secret
  Content-Type: application/json
```

You can also authenticate with `Authorization: Basic` using base64-encoded `clientId:clientSecret`.

---

Last Updated: March 2026
