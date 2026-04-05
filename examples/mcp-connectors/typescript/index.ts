/**
 * MCP Connector Example - Tests Agent Routing
 *
 * This example tests the FULL MCP connector flow:
 *   SDK -> Agent (port 8080) -> Connector
 *
 * Usage:
 *   docker compose up -d  # Start AxonFlow
 *   cd examples/mcp-connectors/typescript
 *   npx ts-node index.ts
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

interface AgentRequest {
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

interface AgentResponse {
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

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || "http://localhost:8080";

  console.log("==============================================");
  console.log("MCP Connector Example - Agent Routing");
  console.log("==============================================");
  console.log(`Agent URL: ${agentUrl}\n`);

  // Test 1: Query postgres connector through agent
  console.log("Test 1: Query postgres connector via agent...");

  const request: AgentRequest = {
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
    const response = await fetch(`${agentUrl}/api/v1/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    const result = (await response.json()) as AgentResponse;

    if (result.success) {
      console.log("SUCCESS: MCP query through agent worked!");
      console.log(`  Request ID: ${result.request_id}`);
      console.log(`  Processing Time: ${result.processing_time}`);
      if (result.data) {
        console.log(`  Rows returned: ${result.data.rows?.length || 0}`);
        console.log(`  Connector: ${result.data.connector}`);
      }
      assertCheck(result.request_id !== undefined && result.request_id !== "", "Response includes request_id");
      assertCheck(result.success === true, "Response indicates success");
      assertCheck(result.data !== undefined, "Response includes data object");
      assertCheck(result.data?.rows !== undefined && Array.isArray(result.data.rows), "Response data includes rows array");
      assertCheck(result.processing_time !== undefined, "Response includes processing_time");
    } else {
      console.log(`FAILED: ${result.error}`);
      failures.push(`MCP query through agent failed: ${result.error}`);
    }

    // Test 2: Query with database alias
    console.log("\nTest 2: Query 'database' connector (alias for postgres)...");

    request.request_id = `mcp-test-${Date.now()}`;
    request.context.connector = "database";

    const response2 = await fetch(`${agentUrl}/api/v1/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });

    const result2 = (await response2.json()) as AgentResponse;

    if (result2.success) {
      console.log("SUCCESS: Database alias connector worked!");
      assertCheck(result2.success === true, "Database alias connector returns success");
      assertCheck(result2.request_id !== undefined && result2.request_id !== "", "Database alias response includes request_id");
    } else {
      console.log(`FAILED: ${result2.error}`);
      failures.push(`Database alias connector failed: ${result2.error}`);
    }

    console.log("\n==============================================");
    if (failures.length === 0) {
      console.log("All MCP connector tests PASSED!");
    } else {
      console.log(`MCP connector tests completed with ${failures.length} failures`);
    }
    console.log("==============================================");
  } catch (error) {
    console.log(`FAILED: ${error}`);
    failures.push(`MCP connector test error: ${error}`);
  }

  // Final assertion summary
  if (failures.length > 0) {
    console.log(`\n=== ASSERTION FAILURES: ${failures.length} ===`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  } else {
    console.log("\n=== ALL ASSERTIONS PASSED ===");
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
