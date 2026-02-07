# LangGraph + AxonFlow Integration (Go SDK)

This example demonstrates how to add AxonFlow governance to LangGraph-style stateful agent workflows using the Go SDK.

## Features

- **Graph-Based Workflow**: Nodes connected by edges, like LangGraph
- **Per-Node Governance**: Policy enforcement at each node transition
- **State Management**: Track state across the entire workflow
- **PII Detection**: Block queries containing sensitive data
- **SQL Injection Prevention**: Detect and block injection attempts
- **Audit Logging**: Complete audit trail for compliance

## Prerequisites

- Go 1.21+
- AxonFlow running locally (`docker compose up`)

## Quick Start

```bash
# Download dependencies
go mod tidy

# Run the example
go run main.go
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

```go
func searchNode(state GraphState, client *axonflow.Client) NodeResult {
    // 1. Policy check before operation
    result, err := client.GetPolicyApprovedContext(
        "langgraph-user",
        fmt.Sprintf("SEARCH: %s", query),
        nil,
        map[string]interface{}{
            "node":      "search",
            "operation": "database_query",
            "workflow":  "research-assistant",
        },
    )

    if err != nil || !result.Approved {
        return NodeResult{Blocked: true, BlockReason: result.BlockReason}
    }

    // 2. Perform the operation
    searchResult := performSearch(query)

    // 3. Audit the operation
    client.AuditLLMCall(
        result.ContextID,
        searchResult,
        "internal",
        "search-v1",
        axonflow.TokenUsage{PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30},
        50,
        nil,
    )

    return NodeResult{NextNode: "respond", State: state}
}
```

## Expected Output

```
LangGraph + AxonFlow Integration Example (Go SDK)
============================================================

Checking AxonFlow at http://localhost:8080...
Status: healthy

============================================================
[Test 1] Safe Search Query
============================================================

Starting Graph Execution
============================================================

[Input Node] Processing: "Search for best practices in AI safety"
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

[Input Node] Processing: "Search for customer with SSN 123-45-6789"
[Input Node] BLOCKED: Social Security Number detected

⚠️  Workflow blocked at node "input"
   Reason: Social Security Number detected

✓ PII correctly detected and blocked!

============================================================
All tests completed!
============================================================
```

## Related Examples

- [TypeScript SDK Example](../typescript/) - Same patterns in TypeScript
- [LangGraph Documentation](https://python.langchain.com/docs/langgraph)
- [AxonFlow Go SDK](https://docs.getaxonflow.com/sdk/go-getting-started)
