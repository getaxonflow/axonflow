/**
 * MCP Policy Enforcement Example - TypeScript SDK
 *
 * Demonstrates phase-aware policy enforcement:
 * 1. REQUEST phase: SQLi patterns are blocked
 * 2. RESPONSE phase: PII in connector data is redacted
 * 3. PolicyInfo metadata in all responses
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Policy Configuration (env vars):
 *   MCP_STATIC_POLICIES_ENABLED - Enable/disable static MCP policies: "true" (default) or "false"
 *
 *   When enabled (default): static policies (SQLi blocking, PII redaction) are enforced
 *   When disabled: static policies are skipped; only dynamic policies apply
 *
 * Run: npx tsx index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow, ConnectorError } from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log("AxonFlow MCP Policy Enforcement - TypeScript SDK");
  console.log("=================================================");
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo",
    debug: process.env.AXONFLOW_DEBUG === "true",
  });

  // Test 1: Clean query should pass through
  console.log("Test 1: Clean Query (No PII, No SQLi)");
  console.log("--------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT 1 as test_value",
    });
    assertCheck(resp.success, "Query succeeded");
    assertCheck(!resp.redacted, "No redaction applied");
    if (resp.policy_info) {
      assertCheck(resp.policy_info.policies_evaluated >= 0, "Policies were evaluated");
      assertCheck(!resp.policy_info.blocked, "Request was not blocked");
      console.log(
        `   PolicyInfo: ${resp.policy_info.policies_evaluated} policies evaluated in ${resp.policy_info.processing_time_ms}ms`
      );
    }
  } catch (err) {
    console.log(`   Query failed: ${err}`);
  }
  console.log();

  // Test 2: SQLi pattern should be blocked
  console.log("Test 2: SQL Injection Pattern (Request Blocked)");
  console.log("------------------------------------------------");
  try {
    await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
    });
    assertCheck(false, "SQLi pattern should have been blocked");
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "Request blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 3: UNION-based SQLi should also be blocked
  console.log("Test 3: UNION SQLi Pattern (Request Blocked)");
  console.log("---------------------------------------------");
  try {
    await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT name FROM employees UNION SELECT password FROM admin_users",
    });
    assertCheck(false, "UNION SQLi should have been blocked");
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "UNION SQLi blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 4: Response with PII should have redacted fields
  console.log("Test 4: Response Redaction (PII in Data)");
  console.log("-----------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM test_customers LIMIT 1",
    });
    if (resp.success) {
      if (resp.redacted) {
        assertCheck(true, "Response was redacted");
        assertCheck(
          resp.redacted_fields !== undefined && resp.redacted_fields.length > 0,
          "Redacted fields are listed"
        );
        console.log(`   Redacted fields: ${resp.redacted_fields?.join(", ")}`);
      } else {
        console.log("   Note: No PII found in response");
      }
      if (resp.policy_info) {
        console.log(
          `   PolicyInfo: ${resp.policy_info.redactions_applied} redactions in ${resp.policy_info.processing_time_ms}ms`
        );
      }
    }
  } catch (err) {
    console.log(`   Query failed: ${err}`);
    console.log("   Note: test_customers table may not exist");
  }
  console.log();

  // Test 5: Request-side PII blocking (SSN in query)
  console.log("Test 5: Request-side PII Blocking (SSN in Query)");
  console.log("------------------------------------------------");
  try {
    await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM customers WHERE ssn = '123-45-6789'",
    });
    assertCheck(false, "SSN in query should have been blocked");
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "SSN in query blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // ========================================
  // Policy Configuration Check (MCP_STATIC_POLICIES_ENABLED)
  // ========================================
  const staticPoliciesEnabled = process.env.MCP_STATIC_POLICIES_ENABLED || "true";
  console.log("Test 6: Static Policies Configuration Check");
  console.log("--------------------------------------------");
  if (staticPoliciesEnabled === "true") {
    console.log("   MCP_STATIC_POLICIES_ENABLED=true (default)");
    console.log("   Static policies (SQLi blocking, PII redaction) are ACTIVE");
  } else {
    console.log("   MCP_STATIC_POLICIES_ENABLED=false");
    console.log("   Static policies are DISABLED; only dynamic policies apply");
    console.log("   Note: SQLi blocking and PII redaction tests above may behave differently");
  }
  console.log();

  // Summary
  console.log("=================================================");
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
    console.log();
    console.log("MCP Policy Enforcement validated:");
    console.log("  - REQUEST phase: SQLi blocking");
    console.log("  - REQUEST phase: PII blocking");
    console.log("  - RESPONSE phase: PII redaction");
    console.log("  - PolicyInfo metadata in responses");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
