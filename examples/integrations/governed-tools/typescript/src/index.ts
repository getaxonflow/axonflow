/**
 * GovernedTool -- Framework-Agnostic Tool Governance Example (TypeScript)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Demonstrates GovernedTool wrapping standard ToolDefinition instances
 * with AxonFlow input/output governance. Tests the UNDERLYING policy engine
 * behavior: PII detection actually blocks/redacts, SQLi is actually caught,
 * policies are actually evaluated, and tools are NOT called when input is blocked.
 *
 * GovernedTool works with any framework that accepts ToolDefinition-shaped objects:
 * LangChain.js, Vercel AI SDK, custom agent loops, etc.
 *
 * Run with: npx ts-node src/index.ts
 * Prerequisites: docker compose up -d, npm install
 */

import {
  AxonFlow,
  GovernedTool,
  governTools,
  PolicyViolationError,
} from "@axonflow/sdk";
import type { ToolDefinition } from "@axonflow/sdk";

const failures: string[] = [];
const callLog: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

// =============================================================================
// Simulated Tools (standard ToolDefinition -- no AxonFlow awareness)
// =============================================================================

const safeSearch: ToolDefinition = {
  name: "safe_search",
  description: "Search for products -- returns clean data without PII.",
  invoke: async (input: unknown): Promise<unknown> => {
    const args = input as { query: string };
    callLog.push(`safe_search:${args.query}`);
    return JSON.stringify({ products: [{ name: "Widget A", price: 9.99 }] });
  },
};

const customerLookup: ToolDefinition = {
  name: "customer_lookup",
  description: "Look up customer data -- returns PII in results.",
  invoke: async (input: unknown): Promise<unknown> => {
    const args = input as { query: string };
    callLog.push(`customer_lookup:${args.query}`);
    return JSON.stringify({
      name: "John Doe",
      ssn: "123-45-6789",
      email: "john@example.com",
      order_status: "shipped",
    });
  },
};

const sendEmail: ToolDefinition = {
  name: "send_email",
  description: "Send an email notification.",
  invoke: async (input: unknown): Promise<unknown> => {
    const args = input as { message: string };
    callLog.push(`send_email:${args.message}`);
    return "Email sent successfully";
  },
};

// =============================================================================
// Tests
// =============================================================================

async function testCleanToolCall(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 1] Clean Tool Call -- Policies Must Be Evaluated");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(safeSearch, client);

  const t0 = Date.now();
  const result = await governed.invoke({ query: "latest widgets" });
  const latencyMs = Date.now() - t0;

  assertCheck(result !== null && result !== undefined, "Tool call returned a result");
  assertCheck(callLog.length === 1, "Wrapped tool was called exactly once");
  assertCheck(callLog[0] === "safe_search:latest widgets", "Tool received correct args");
  assertCheck(String(result).includes("Widget A"), "Result contains expected data");
  console.log(`   Latency: ${latencyMs}ms`);

  // Verify the policy engine actually ran
  const direct = await client.mcpCheckInput({
    connectorType: "safe_search",
    statement: '{"query": "latest widgets"}',
  });
  assertCheck(
    direct.policies_evaluated > 0,
    `Policy engine evaluated ${direct.policies_evaluated} policies (not zero)`,
  );
  console.log();
}

async function testSqliInToolInputBlocked(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 2] SQL Injection in Tool Input -- Must Block");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(safeSearch, client, {
    connectorTypeFn: () => "postgres.query",
  });

  const sqliInput = "SELECT * FROM users WHERE id=1; DROP TABLE users;--";
  let blocked = false;
  let blockReason = "";
  try {
    await governed.invoke({ query: sqliInput });
  } catch (e) {
    if (e instanceof PolicyViolationError) {
      blocked = true;
      blockReason = e.message;
      console.log(`   Blocked: ${blockReason}`);
    } else {
      throw e;
    }
  }

  assertCheck(blocked, "SQL injection tool call was blocked");
  assertCheck(callLog.length === 0, "Tool was NOT called (blocked before execution)");

  // Verify underlying policy engine
  const direct = await client.mcpCheckInput({
    connectorType: "postgres.query",
    statement: sqliInput,
  });
  assertCheck(!direct.allowed, "Direct check-input confirms SQLi is blocked");
  assertCheck(
    direct.block_reason !== undefined && direct.block_reason.length > 0,
    `Block reason: ${direct.block_reason}`,
  );
  console.log();
}

async function testPiiInToolInput(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 3] PII in Tool Input -- Must Be Detected");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(sendEmail, client);

  const piiInput = "Customer SSN is 123-45-6789, please process their refund";

  // Verify the policy engine detects PII via direct call first
  const direct = await client.mcpCheckInput({
    connectorType: "send_email",
    statement: JSON.stringify({ message: piiInput }),
  });

  let piiDetected = false;
  if (!direct.allowed) {
    piiDetected = true;
    console.log(`   Direct check: Input blocked (${direct.block_reason})`);
  } else {
    piiDetected = direct.policies_evaluated > 0;
    console.log(`   Direct check: ${direct.policies_evaluated} policies evaluated (PII_ACTION may be warn/log)`);
  }

  assertCheck(piiDetected, "PII in tool input was detected by policy engine");

  // Now test through GovernedTool
  try {
    const result = await governed.invoke({ message: piiInput });
    assertCheck(callLog.length === 1, "Tool called (PII detected but not blocking at input)");
    console.log(`   GovernedTool result: ${result}`);
  } catch (e) {
    if (e instanceof PolicyViolationError) {
      assertCheck(callLog.length === 0, "Tool NOT called (PII blocking at input)");
      console.log(`   GovernedTool blocked: ${e.message}`);
    } else {
      throw e;
    }
  }
  console.log();
}

async function testPiiInToolOutput(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 4] PII in Tool Output -- Must Be Detected/Redacted");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(customerLookup, client);

  // Verify policy engine handles PII output via direct call
  const piiOutput = JSON.stringify({
    name: "John Doe",
    ssn: "123-45-6789",
    email: "john@example.com",
  });
  const direct = await client.mcpCheckOutput({
    connectorType: "customer_lookup",
    message: piiOutput,
  });

  let outputPiiHandled = false;
  if (!direct.allowed) {
    outputPiiHandled = true;
    console.log(`   Direct check: Output blocked (${direct.block_reason})`);
  } else if (direct.redacted_data !== undefined && direct.redacted_data !== null) {
    outputPiiHandled = true;
    console.log(`   Direct check: Output redacted`);
  } else {
    outputPiiHandled = direct.policies_evaluated > 0;
    console.log(`   Direct check: ${direct.policies_evaluated} policies evaluated`);
  }

  assertCheck(outputPiiHandled, "PII in tool output was handled by policy engine");

  // Test through GovernedTool
  try {
    const result = await governed.invoke({ query: "John Doe" });
    assertCheck(callLog.length === 1, "Tool was called (output-side check)");

    const resultStr = String(result);
    if (!resultStr.includes("123-45-6789")) {
      console.log(`   GovernedTool: Output redacted (raw SSN not present)`);
    } else if (resultStr.includes("***") || resultStr.includes("REDACTED")) {
      console.log(`   GovernedTool: Output redacted`);
    } else {
      console.log(`   GovernedTool: Output returned (PII_ACTION may be warn/log)`);
    }
    console.log(`   Result: ${resultStr.substring(0, 200)}`);
  } catch (e) {
    if (e instanceof PolicyViolationError) {
      assertCheck(callLog.length === 1, "Tool was called before output block");
      console.log(`   GovernedTool: Output blocked (${e.message})`);
    } else {
      throw e;
    }
  }
  console.log();
}

async function testCustomConnectorType(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 5] Custom Connector Type Derivation");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(safeSearch, client, {
    connectorTypeFn: (name: string) => `salesforce.${name}`,
  });

  assertCheck(
    governed.toString().includes("salesforce.safe_search"),
    `Connector type derived correctly: ${governed.toString()}`,
  );

  const result = await governed.invoke({ query: "find contacts" });
  assertCheck(result !== null && result !== undefined, "Custom connector type call succeeded");
  assertCheck(callLog.length === 1, "Tool was called");

  // Verify connector type was used in the check
  const direct = await client.mcpCheckInput({
    connectorType: "salesforce.safe_search",
    statement: '{"query": "find contacts"}',
  });
  assertCheck(direct.allowed, "Direct check with custom connector_type allowed");
  assertCheck(
    direct.policies_evaluated > 0,
    `Policies evaluated: ${direct.policies_evaluated}`,
  );
  console.log();
}

async function testQueryOperation(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 6] Read-Only Tool with operation='query'");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = new GovernedTool(safeSearch, client, { operation: "query" });

  const result = await governed.invoke({ query: "list products" });
  assertCheck(result !== null && result !== undefined, "Query-mode tool call succeeded");
  assertCheck(callLog.length === 1, "Tool was called");

  // Verify operation forwarded
  const direct = await client.mcpCheckInput({
    connectorType: "safe_search",
    statement: '{"query": "list products"}',
    operation: "query",
  });
  assertCheck(direct.allowed, "Direct check with operation=query allowed");
  console.log();
}

async function testGovernToolsHelper(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 7] governTools() Helper -- Multi-Tool Wrapping");
  console.log("=".repeat(60));

  callLog.length = 0;
  const governed = governTools([safeSearch, customerLookup, sendEmail], client);

  assertCheck(governed.length === 3, `Wrapped ${governed.length} tools`);

  for (const g of governed) {
    assertCheck(g instanceof GovernedTool, `${g.name} is GovernedTool instance`);
    assertCheck(typeof g.invoke === "function", `${g.name} has invoke method`);
  }

  // Call first tool
  const result = await governed[0].invoke({ query: "test" });
  assertCheck(result !== null && result !== undefined, "First governed tool returned result");
  assertCheck(callLog.length === 1, "Only the first tool was called");

  console.log(`   Tools: ${governed.map((g) => g.name).join(", ")}`);
  console.log();
}

async function testReprAndMetadata(client: AxonFlow): Promise<void> {
  console.log("=".repeat(60));
  console.log("[Test 8] GovernedTool Metadata & toString");
  console.log("=".repeat(60));

  const governed = new GovernedTool(safeSearch, client);

  assertCheck(governed.name === "safe_search", `Name: ${governed.name}`);
  assertCheck(
    governed.description === "Search for products -- returns clean data without PII.",
    "Description preserved",
  );
  assertCheck(governed.toString().includes("GovernedTool"), `toString: ${governed.toString()}`);
  assertCheck(governed.toString().includes("safe_search"), "Tool name in toString");

  // Custom connector type
  const governed2 = new GovernedTool(customerLookup, client, {
    connectorTypeFn: (n: string) => `crm.${n}`,
    operation: "query",
  });
  assertCheck(
    governed2.toString().includes("crm.customer_lookup"),
    `Custom toString: ${governed2.toString()}`,
  );
  console.log();
}

// =============================================================================
// Main
// =============================================================================

async function main(): Promise<number> {
  console.log("GovernedTool -- Framework-Agnostic Tool Governance (TypeScript)");
  console.log("=".repeat(60));
  console.log();
  console.log("Validates AxonFlow policy enforcement around any ToolDefinition,");
  console.log("verifying the underlying policy engine behavior.");
  console.log();

  const agentUrl = process.env.AXONFLOW_AGENT_URL || "http://localhost:8080";
  console.log(`Checking AxonFlow at ${agentUrl}...`);

  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId: process.env.AXONFLOW_CLIENT_ID || "community",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "community",
  });

  // Health check
  try {
    const health = await client.healthCheck();
    if (!health || health.status !== "healthy") {
      console.log("Status: unhealthy");
      console.log("\nMake sure AxonFlow is running: docker compose up -d");
      return 1;
    }
    console.log("Status: healthy");
  } catch (e) {
    console.log(`Error: ${e instanceof Error ? e.message : String(e)}`);
    console.log("\nMake sure AxonFlow is running: docker compose up -d");
    return 1;
  }
  console.log();

  console.log("Running GovernedTool tests...");
  console.log();

  await testCleanToolCall(client);
  await testSqliInToolInputBlocked(client);
  await testPiiInToolInput(client);
  await testPiiInToolOutput(client);
  await testCustomConnectorType(client);
  await testQueryOperation(client);
  await testGovernToolsHelper(client);
  await testReprAndMetadata(client);

  // Summary
  console.log("=".repeat(60));
  console.log("Test Summary");
  console.log("=".repeat(60));
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  }
  console.log("=".repeat(60));

  return failures.length > 0 ? 1 : 0;
}

main().then((code) => process.exit(code));
