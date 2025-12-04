# Hello World - AxonFlow

**The simplest AxonFlow example** - Get started in 5 minutes.

---

## Overview

This is the absolute minimum code needed to use AxonFlow. Perfect for:
- Learning the basics
- Testing your AxonFlow deployment
- Understanding the request/response flow
- Verifying connectivity

**Time to complete:** 5 minutes
**Lines of code:** ~30 lines
**Prerequisites:** AxonFlow deployed

---

## What It Does

1. Connects to your AxonFlow deployment
2. Sends a simple query: "What is the capital of France?"
3. Enforces a basic policy (allow all)
4. Returns the response
5. Logs the latency

**Expected output:**
```
Response: The capital of France is Paris.
Latency: 4ms
```

---

## Quick Start

### TypeScript

```bash
cd typescript
npm install
npm start
```

### Go

```bash
cd go
go run main.go
```

---

## Code Examples

### TypeScript (30 lines)

```typescript
import { AxonFlowClient } from '@axonflow/sdk';

const client = new AxonFlowClient({
  endpoint: 'https://YOUR_AGENT_ENDPOINT',
  licenseKey: 'YOUR_LICENSE_KEY',
  organizationId: 'my-org'
});

async function main() {
  const response = await client.executeQuery({
    query: 'What is the capital of France?',
    policy: `
      package axonflow.policy
      default allow = true
    `
  });

  console.log('Response:', response.result);
  console.log('Latency:', response.metadata.latency_ms + 'ms');
}

main();
```

### Go (35 lines)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "github.com/axonflow/axonflow-go"
)

func main() {
    client, _ := axonflow.NewClient(axonflow.Config{
        Endpoint:       "https://YOUR_AGENT_ENDPOINT",
        LicenseKey:     "YOUR_LICENSE_KEY",
        OrganizationID: "my-org",
    })

    response, err := client.ExecuteQuery(context.Background(), &axonflow.QueryRequest{
        Query: "What is the capital of France?",
        Policy: `
            package axonflow.policy
            default allow = true
        `,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Response:", response.Result)
    fmt.Printf("Latency: %dms\n", response.Metadata.LatencyMS)
}
```

---

## Configuration

Before running, update the code with your credentials:

1. **Agent Endpoint** - From CloudFormation Outputs
2. **License Key** - From CloudFormation Outputs
3. **Organization ID** - Your organization identifier

**Example:**
```typescript
const client = new AxonFlowClient({
  endpoint: 'https://axonfl-AxonF-abc123.elb.us-east-1.amazonaws.com',
  licenseKey: 'AXON-V2-eyJ0aWVyIjoiUExVUyJ9-abc123',
  organizationId: 'my-company'
});
```

---

## Understanding the Code

### 1. Client Initialization

```typescript
const client = new AxonFlowClient({
  endpoint: 'https://YOUR_AGENT_ENDPOINT',
  licenseKey: 'YOUR_LICENSE_KEY',
  organizationId: 'my-org'
});
```

- **endpoint**: Your AxonFlow Agent endpoint (from CloudFormation)
- **licenseKey**: Authentication credential
- **organizationId**: Your organization identifier (used for audit logs)

### 2. Policy Definition

```rego
package axonflow.policy
default allow = true
```

- **package**: Required namespace for AxonFlow policies
- **default allow = true**: Allow all queries (permissive policy)
- **Policy language**: Open Policy Agent (OPA) Rego

### 3. Query Execution

```typescript
const response = await client.executeQuery({
  query: 'What is the capital of France?',
  policy: policyContent
});
```

- **query**: Natural language query
- **policy**: Policy rules for governance
- Returns **response** with result and metadata

### 4. Response Handling

```typescript
console.log('Response:', response.result);
console.log('Latency:', response.metadata.latency_ms + 'ms');
```

- **response.result**: Query result
- **response.metadata.latency_ms**: Policy evaluation latency (sub-10ms)
- **response.metadata.policy_decision**: "allow" or "deny"

---

## What Happens Under the Hood

```
1. Client sends query + policy to Agent
   ↓
2. Agent validates license key
   ↓
3. Agent compiles and evaluates policy (~4ms)
   ↓
4. Policy returns "allow"
   ↓
5. Agent processes query
   ↓
6. Response returned to client
   ↓
7. Audit log written to CloudWatch
```

**Performance:** Policy evaluation typically takes 3-5ms (sub-10ms P95).

---

## Troubleshooting

### Connection Failed

**Error:** `ECONNREFUSED` or timeout

**Solutions:**
1. Verify Agent Endpoint URL
2. Check security groups allow HTTPS (port 443)
3. Ensure ECS tasks are running
4. Test with curl:
   ```bash
   curl -k https://YOUR_AGENT_ENDPOINT/health
   ```

### Invalid License Key

**Error:** `License key validation failed`

**Solutions:**
1. Verify license key format: `AXON-V2-{base64}-{signature}`
2. Check license key hasn't expired
3. Ensure organization ID matches licensed tenant

### Slow Response

**Expected:** Sub-10ms policy evaluation

**If slower:**
1. Check CloudWatch metrics for agent CPU/memory
2. Verify network latency
3. Check policy complexity

---

## Next Steps

Now that you have a working AxonFlow query:

### 1. Add Real Policies

Replace `default allow = true` with real governance rules:

```rego
package axonflow.policy

# Only allow admins
allow {
    input.context.user_role == "admin"
}

# Block sensitive queries
deny["Sensitive operation not allowed"] {
    contains(lower(input.query), "delete all")
}
```

### 2. Add Context

Include user information for audit trails:

```typescript
const response = await client.executeQuery({
  query: 'Get customer data',
  policy: policyContent,
  context: {
    user_id: 'user-123',
    user_role: 'admin',
    department: 'engineering'
  }
});
```

### 3. Connect to LLM

Add AI capabilities:

```typescript
const response = await client.executeQuery({
  query: 'Generate a product description',
  policy: policyContent,
  llm: {
    provider: 'aws-bedrock',
    model: 'anthropic.claude-3-sonnet-20240229-v1:0'
  }
});
```

### 4. Use MCP Connectors

Query real data sources:

```typescript
const response = await client.executeQuery({
  query: 'Get opportunities from Salesforce',
  policy: policyContent,
  mcp: {
    connector: 'salesforce',
    operation: 'query'
  }
});
```

---

## Learn More

- **[First Agent Tutorial](/docs/tutorials/first-agent)** - Build your first agent in 10 minutes
- **[Workflow Examples](/docs/tutorials/workflow-examples)** - Production-ready patterns
- **[Policy Syntax](/docs/policies/syntax)** - Policy language reference
- **[Examples Overview](/docs/examples/overview)** - Browse all examples

---

## Files in This Example

```
hello-world/
├── README.md           # This file
├── typescript/
│   ├── package.json    # Dependencies
│   ├── index.ts        # Main code (30 lines)
│   └── .env.example    # Configuration template
└── go/
    ├── go.mod          # Dependencies
    ├── main.go         # Main code (35 lines)
    └── .env.example    # Configuration template
```

---

**This is the simplest possible AxonFlow example.** Perfect for getting started! 🚀
