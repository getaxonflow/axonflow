/**
 * MCP Connector Example - Tests Orchestrator-to-Agent Routing
 *
 * This example tests the FULL MCP connector flow:
 *   SDK -> Orchestrator (port 8081) -> Agent (port 8080) -> Connector
 *
 * Usage:
 *   docker compose up -d  # Start AxonFlow
 *   cd examples/mcp-connectors/typescript
 *   npx ts-node index.ts
 */

interface OrchestratorRequest {
  request_id: string;
  query: string;
  request_type: string;
  user: {
    email: string;
    role: string;
    tenant_id: string;
  };
  client: {
    id: string;
    tenant_id: string;
  };
  context: Record<string, unknown>;
}

interface OrchestratorResponse {
  request_id: string;
  success: boolean;
  data?: {
    rows?: unknown[];
    connector?: string;
    row_count?: number;
  };
  error?: string;
  processing_time?: string;
}

async function main() {
  const orchestratorUrl = process.env.ORCHESTRATOR_URL || "http://localhost:8081";

  console.log("==============================================");
  console.log("MCP Connector Example - Orchestrator Routing");
  console.log("==============================================");
  console.log(`Orchestrator URL: ${orchestratorUrl}\n`);

  // Test 1: Query postgres connector through orchestrator
  console.log("Test 1: Query postgres connector via orchestrator...");

  const request: OrchestratorRequest = {
    request_id: `mcp-test-${Date.now()}`,
    query: "SELECT 1 as test_value, 'hello' as test_message",
    request_type: "mcp-query",
    user: {
      email: "test@example.com",
      role: "user",
      tenant_id: "default",
    },
    client: {
      id: "test-client",
      tenant_id: "default",
    },
    context: {
      connector: "postgres",
      params: {},
    },
  };

  try {
    const response = await fetch(`${orchestratorUrl}/api/v1/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    const result = (await response.json()) as OrchestratorResponse;

    if (result.success) {
      console.log("SUCCESS: MCP query through orchestrator worked!");
      console.log(`  Request ID: ${result.request_id}`);
      console.log(`  Processing Time: ${result.processing_time}`);
      if (result.data) {
        console.log(`  Rows returned: ${result.data.rows?.length || 0}`);
        console.log(`  Connector: ${result.data.connector}`);
      }
    } else {
      console.log(`FAILED: ${result.error}`);
      process.exit(1);
    }

    // Test 2: Query with database alias
    console.log("\nTest 2: Query 'database' connector (alias for postgres)...");

    request.request_id = `mcp-test-${Date.now()}`;
    request.context.connector = "database";

    const response2 = await fetch(`${orchestratorUrl}/api/v1/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    const result2 = (await response2.json()) as OrchestratorResponse;

    if (result2.success) {
      console.log("SUCCESS: Database alias connector worked!");
    } else {
      console.log(`FAILED: ${result2.error}`);
      process.exit(1);
    }

    console.log("\n==============================================");
    console.log("All MCP connector tests PASSED!");
    console.log("==============================================");
  } catch (error) {
    console.log(`FAILED: ${error}`);
    process.exit(1);
  }
}

main();
