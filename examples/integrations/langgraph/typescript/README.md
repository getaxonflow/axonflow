# LangGraph + AxonFlow Integration (TypeScript SDK)

This example demonstrates how to add AxonFlow governance to LangGraph-style stateful agent workflows using the TypeScript SDK.

## Features

- **Graph-Based Workflow**: Nodes connected by edges, like LangGraph
- **Per-Node Governance**: Policy enforcement at each node transition
- **State Management**: Track state across the entire workflow
- **PII Detection**: Block queries containing sensitive data
- **SQL Injection Prevention**: Detect and block injection attempts
- **Audit Logging**: Complete audit trail for compliance

## Prerequisites

- Node.js 18+
- AxonFlow running locally (`docker compose up`)

## Quick Start

```bash
# Install dependencies
npm install

# Run the example
npm start
```

## How It Works

### Graph Structure

```
┌─────────┐     ┌────────┐     ┌─────────┐
│  Input  │────►│ Router │────►│ Search  │────┐
│  Node   │     │  Node  │     │  Node   │    │
└─────────┘     └────────┘     └─────────┘    │
     │               │                         │
     │               │         ┌─────────┐    │
     │               └────────►│ Analyze │────┤
     │                         │  Node   │    │
     │                         └─────────┘    │
     │                                        ▼
     │                              ┌─────────────┐
     └─────────────────────────────►│   Respond   │
                                    │    Node     │
                                    └─────────────┘
```

### Per-Node Governance

Each node calls AxonFlow before processing:

```typescript
async function searchNode(state: GraphState, axonflow: AxonFlow): Promise<NodeResult> {
  // 1. Policy check before operation
  const result = await axonflow.getPolicyApprovedContext({
    userToken: "langgraph-user",
    query: `SEARCH: ${query}`,
    context: {
      node: "search",
      operation: "database_query",
      workflow: "research-assistant",
    },
  });

  if (!result.approved) {
    return { nextNode: null, blocked: true, blockReason: result.blockReason };
  }

  // 2. Perform the operation
  const searchResult = await performSearch(query);

  // 3. Audit the operation
  await axonflow.auditLLMCall({
    contextId: result.contextId,
    responseSummary: searchResult,
    provider: "internal",
    model: "search-v1",
    tokenUsage: { promptTokens: 10, completionTokens: 20, totalTokens: 30 },
    latencyMs: 50,
  });

  return { nextNode: "respond", state };
}
```

## Expected Output

```
LangGraph + AxonFlow Integration Example (TypeScript SDK)
============================================================

Checking AxonFlow at http://localhost:8080...
Status: healthy

============================================================
[Test 1] Safe Search Query
============================================================

Starting Graph Execution
============================================================

[Input Node] Processing: "Search for best practices in AI safety..."
[Input Node] ✓ Approved (Context: abc12345...)
[Router Node] Analyzing query intent...
[Router Node] ✓ Routing to: search
[Search Node] Executing governed search...
[Search Node] ✓ Search completed and audited
[Respond Node] Generating governed response...
[Respond Node] ✓ Response generated and audited

============================================================
[Test 3] Query with PII - Should be blocked
============================================================

[Input Node] Processing: "Search for customer with SSN 123-45-6789..."
[Input Node] BLOCKED: Social Security Number detected

⚠️  Workflow blocked at node "input"
   Reason: Social Security Number detected

✓ PII correctly detected and blocked!

============================================================
All tests completed!
============================================================
```

## Related Examples

- [Go SDK Example](../go/) - Same patterns in Go
- [LangGraph Documentation](https://python.langchain.com/docs/langgraph)
- [AxonFlow TypeScript SDK](https://docs.getaxonflow.com/sdk/typescript-getting-started)
