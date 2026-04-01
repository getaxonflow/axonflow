# Claude Agent SDK + AxonFlow Governance

Demonstrates AxonFlow governance for custom MCP tools built with the Claude Agent SDK.

## How It Works

The Claude Agent SDK defines custom tools as MCP servers. AxonFlow governs these tools by calling `mcpCheckInput` before execution and `mcpCheckOutput` after.

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'your-client-id',
  clientSecret: 'your-secret',
});

// Before tool execution:
const inputCheck = await client.mcpCheckInput({
  connectorType: 'agent_sdk.get_temperature',
  statement: JSON.stringify(toolArgs),
  operation: 'query',
});

if (!inputCheck.allowed) {
  // Block the tool call
  return { error: inputCheck.blockReason };
}

// Execute the tool...
const result = await executeTool(toolArgs);

// After execution:
const outputCheck = await client.mcpCheckOutput({
  connectorType: 'agent_sdk.get_temperature',
  message: JSON.stringify(result),
});

if (outputCheck.redactedData) {
  // Return redacted result to Claude
  return outputCheck.redactedData;
}
```

## No SDK Changes Needed

The Claude Agent SDK uses MCP protocol. The existing AxonFlow TypeScript SDK `mcpCheckInput`/`mcpCheckOutput` methods already support any connector type string. No additional SDK code is needed.

## Links

- [Claude Agent SDK Documentation](https://docs.anthropic.com/en/docs/agents-and-tools/claude-agent-sdk)
- [AxonFlow MCP Policy Enforcement](https://docs.getaxonflow.com/docs/mcp/policy-enforcement/)
- [TypeScript SDK](https://docs.getaxonflow.com/docs/sdk/typescript-getting-started/)
