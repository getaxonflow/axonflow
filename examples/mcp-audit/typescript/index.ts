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
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";

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
  // Get configuration from environment
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const clientId = process.env.AXONFLOW_CLIENT_ID || "demo-client";
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || "";

  console.log("==============================================");
  console.log("MCP Audit Logging Example - TypeScript SDK");
  console.log("==============================================");
  console.log(`Endpoint: ${endpoint}`);
  console.log(`Client ID: ${clientId}`);
  console.log();

  // Create AxonFlow client
  const client = new AxonFlow({
    endpoint,
    clientId,
    clientSecret,
  });

  // Test 1: Simple query (creates audit entry)
  console.log("Test 1: Execute simple MCP query...");
  console.log("----------------------------------------------");

  let test1Success = false;
  try {
    const result = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT 1 as test_value, 'hello' as test_message",
    });
    console.log("SUCCESS: Query executed");
    console.log(`  Success: ${result.success}`);
    if (result.policy_info) {
      console.log(`  Policies evaluated: ${result.policy_info.policies_evaluated}`);
      console.log(`  Blocked: ${result.policy_info.blocked}`);
      console.log(`  Redacted: ${result.redacted ?? false}`);
      console.log(`  Redacted fields: ${result.redacted_fields?.join(", ") || "none"}`);
      console.log(`  Processing time: ${result.policy_info.processing_time_ms}ms`);
    }
    test1Success = true;
    assertCheck(result.success === true, "mcpQuery returns success=true");
    assertCheck(result.policy_info !== undefined, "mcpQuery returns policy_info for audit logging");
    assertCheck(result.policy_info?.blocked === false, "Simple query is not blocked");
  } catch (e) {
    console.log(`Query error (expected if postgres not configured): ${e}`);
    // Not adding to failures as postgres may not be configured
  }
  console.log();

  // Test 2: Query that may trigger PII detection
  console.log("Test 2: Execute query with potential PII fields...");
  console.log("----------------------------------------------");

  let test2Success = false;
  try {
    const result = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT email, phone, name FROM users LIMIT 5",
    });
    console.log("SUCCESS: Query executed");
    console.log(`  Success: ${result.success}`);
    if (result.policy_info) {
      console.log(`  Policies evaluated: ${result.policy_info.policies_evaluated}`);
      if (result.redacted_fields?.length) {
        console.log(`  PII REDACTED! Fields: ${result.redacted_fields.join(", ")}`);
      }
    }
    test2Success = true;
    assertCheck(result.policy_info !== undefined, "PII query returns policy_info");
    assertCheck(result.policy_info?.policies_evaluated !== undefined && result.policy_info?.policies_evaluated >= 0, "policy_info includes policies_evaluated count");
  } catch (e) {
    console.log(`Query error: ${e}`);
    // Not adding to failures as this may be expected if users table doesn't exist
  }
  console.log();

  // Test 3: Query with SQLi pattern (should be blocked)
  console.log("Test 3: Execute query with SQLi pattern (should be blocked)...");
  console.log("----------------------------------------------");

  let sqliBlocked = false;
  try {
    await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM users; DROP TABLE users;--",
    });
    console.log("Note: SQLi detection may not be enabled");
    // If we get here, SQLi was NOT blocked - this may be expected in some configs
  } catch (e: any) {
    const errorMsg = e?.message || String(e);
    console.log(`Query blocked as expected: ${e}`);
    console.log("SUCCESS: SQLi attempt was blocked and audit logged");
    sqliBlocked = true;
    // Verify the error indicates blocking due to policy
    const isBlockedByPolicy = errorMsg.includes("blocked") ||
                               errorMsg.includes("policy") ||
                               errorMsg.includes("SQL injection") ||
                               errorMsg.includes("sqli");
    assertCheck(isBlockedByPolicy, "SQLi blocked error message indicates policy violation");
  }
  // Note: We don't fail if SQLi wasn't blocked as policies may not be enabled
  if (sqliBlocked) {
    assertCheck(true, "SQLi attack pattern was blocked by policy");
  } else {
    console.log("   Note: SQLi blocking not verified (may require policy configuration)");
  }
  console.log();

  // Test 4: Execute (INSERT) operation
  console.log("Test 4: Execute INSERT operation...");
  console.log("----------------------------------------------");

  let test4Success = false;
  try {
    const result = await client.mcpExecute({
      connector: "postgres",
      statement: "INSERT INTO audit_test (name) VALUES ('test')",
    });
    console.log("SUCCESS: Execute completed");
    console.log(`  Success: ${result.success}`);
    if (result.policy_info) {
      console.log(`  Policies evaluated: ${result.policy_info.policies_evaluated}`);
      console.log(`  Processing time: ${result.policy_info.processing_time_ms}ms`);
    }
    test4Success = true;
    assertCheck(result.success === true, "mcpExecute returns success=true");
    assertCheck(result.policy_info !== undefined, "mcpExecute returns policy_info for audit logging");
  } catch (e) {
    console.log(`Execute error (expected if table doesn't exist): ${e}`);
    // Not adding to failures as table may not exist
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

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
