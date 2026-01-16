/**
 * MCP Audit Logging Example - TypeScript SDK
 *
 * This example demonstrates how MCP query operations are automatically
 * audited by AxonFlow. Every MCP query/execute operation is logged to
 * the mcp_query_audits table with policy evaluation results.
 *
 * What gets audited:
 *   - Request phase: SQLi detection, PII blocking
 *   - Response phase: PII redaction
 *   - Exfiltration checks: Row/volume limits
 *   - Final result: success/failure, duration
 *
 * Usage:
 *   docker compose up -d  # Start AxonFlow
 *   cd examples/mcp-audit/typescript
 *   npm install
 *   npx tsx index.ts
 */

import { AxonFlow } from "@axonflow/sdk";

async function main() {
  // Get configuration from environment
  const agentUrl = process.env.AGENT_URL || "http://localhost:8080";
  const clientId = process.env.CLIENT_ID || "demo-client";
  const clientSecret = process.env.CLIENT_SECRET || "demo-secret";

  console.log("==============================================");
  console.log("MCP Audit Logging Example - TypeScript SDK");
  console.log("==============================================");
  console.log(`Agent URL: ${agentUrl}`);
  console.log(`Client ID: ${clientId}`);
  console.log();

  // Create AxonFlow client
  const client = new AxonFlow({
    agentUrl,
    clientId,
    clientSecret,
  });

  // Test 1: Simple query (creates audit entry)
  console.log("Test 1: Execute simple MCP query...");
  console.log("----------------------------------------------");

  try {
    const result = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT 1 as test_value, 'hello' as test_message",
    });
    console.log("SUCCESS: Query executed");
    console.log(`  Row count: ${result.rowCount}`);
    console.log(`  Duration: ${result.durationMs}ms`);
    if (result.policyInfo) {
      console.log(`  Policies evaluated: ${result.policyInfo.policiesEvaluated}`);
      console.log(`  Blocked: ${result.policyInfo.blocked}`);
      console.log(`  Redacted fields: ${result.policyInfo.redactedFields}`);
    }
  } catch (e) {
    console.log(`Query error (expected if postgres not configured): ${e}`);
  }
  console.log();

  // Test 2: Query that may trigger PII detection
  console.log("Test 2: Execute query with potential PII fields...");
  console.log("----------------------------------------------");

  try {
    const result = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT email, phone, name FROM users LIMIT 5",
    });
    console.log("SUCCESS: Query executed");
    console.log(`  Row count: ${result.rowCount}`);
    if (result.policyInfo) {
      console.log(`  Policies evaluated: ${result.policyInfo.policiesEvaluated}`);
      if (result.policyInfo.redactedFields?.length) {
        console.log(`  PII REDACTED! Fields: ${result.policyInfo.redactedFields}`);
      }
    }
  } catch (e) {
    console.log(`Query error: ${e}`);
  }
  console.log();

  // Test 3: Query with SQLi pattern (should be blocked)
  console.log("Test 3: Execute query with SQLi pattern (should be blocked)...");
  console.log("----------------------------------------------");

  try {
    await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM users; DROP TABLE users;--",
    });
    console.log("Note: SQLi detection may not be enabled");
  } catch (e) {
    console.log(`Query blocked as expected: ${e}`);
    console.log("SUCCESS: SQLi attempt was blocked and audit logged");
  }
  console.log();

  // Test 4: Execute (INSERT) operation
  console.log("Test 4: Execute INSERT operation...");
  console.log("----------------------------------------------");

  try {
    const result = await client.mcpExecute({
      connector: "postgres",
      action: "INSERT",
      statement: "INSERT INTO audit_test (name) VALUES ('test')",
    });
    console.log("SUCCESS: Execute completed");
    console.log(`  Rows affected: ${result.rowsAffected}`);
    console.log(`  Duration: ${result.durationMs}ms`);
  } catch (e) {
    console.log(`Execute error (expected if table doesn't exist): ${e}`);
  }
  console.log();

  console.log("==============================================");
  console.log("MCP Audit Logging Tests Complete!");
  console.log("==============================================");
  console.log();
  console.log("All MCP operations above have been logged to the");
  console.log("mcp_query_audits table. Each entry includes:");
  console.log("  - audit_id: Unique identifier");
  console.log("  - tenant_id, client_id, user_id: Who made the request");
  console.log("  - connector_name, operation: What was requested");
  console.log("  - request_blocked, request_block_reason: If request was blocked");
  console.log("  - response_redacted, response_redacted_fields: If PII was redacted");
  console.log("  - exfil_exceeded, exfil_limit_type: If exfiltration limit hit");
  console.log("  - success, error_message: Final result");
  console.log("  - duration_ms: How long it took");

  await client.close();
}

main().catch(console.error);
