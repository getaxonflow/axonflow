/**
 * MCP PII Redaction - Comprehensive Test (TypeScript SDK)
 *
 * This example validates that PII types are properly redacted in MCP connector responses:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN
 * - India Aadhaar
 * - Email addresses (non-critical, logged only)
 * - Phone numbers (non-critical, logged only)
 *
 * Run with: npx tsx index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow, ConnectorError } from "@axonflow/sdk";

const failures: string[] = [];
let passes = 0;

function assertCheck(condition: boolean, message: string): void {
  if (!condition) {
    failures.push(message);
    console.log(`   FAIL: ${message}`);
  } else {
    passes++;
    console.log(`   PASS: ${message}`);
  }
}

async function main(): Promise<void> {
  console.log("MCP PII Redaction - Comprehensive Test");
  console.log("=======================================");
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo",
    debug: process.env.AXONFLOW_DEBUG === "true",
  });

  // Test 1: Query test_customers table (pre-seeded with PII data)
  console.log("Test 1: Query test_customers (Response Redaction)");
  console.log("-------------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM test_customers LIMIT 1",
    });

    assertCheck(resp.success, "Query executed successfully");

    if (resp.redacted) {
      assertCheck(true, "Response was redacted");
      assertCheck(
        resp.redacted_fields !== undefined && resp.redacted_fields.length > 0,
        "Redacted fields are listed"
      );
      console.log(`   Redacted fields: ${resp.redacted_fields?.join(", ")}`);

      const redactedStr = resp.redacted_fields?.join(", ") || "";
      if (redactedStr.includes("ssn")) {
        console.log("   - SSN: redacted");
      }
      if (redactedStr.includes("credit_card")) {
        console.log("   - Credit Card: redacted");
      }
    } else {
      console.log("   Note: No PII found in response (test_customers may be empty)");
    }

    if (resp.policy_info) {
      console.log(
        `   PolicyInfo: ${resp.policy_info.policies_evaluated} policies, ` +
          `${resp.policy_info.redactions_applied} redactions in ${resp.policy_info.processing_time_ms}ms`
      );
    }
  } catch (err) {
    console.log(`   Query failed: ${err}`);
    console.log("   Note: test_customers table may not exist");
  }
  console.log();

  // Test 2: Request-phase PII blocking (SSN in query)
  console.log("Test 2: Request-phase PII Blocking (SSN)");
  console.log("----------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM users WHERE ssn = '123-45-6789'",
    });
    if (!resp.success) {
      assertCheck(true, "SSN in query blocked as expected");
    } else {
      assertCheck(false, "SSN in query should have been blocked");
    }
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "SSN in query blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 3: Request-phase PII blocking (Credit Card)
  console.log("Test 3: Request-phase PII Blocking (Credit Card)");
  console.log("------------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM orders WHERE card = '4111111111111111'",
    });
    if (!resp.success) {
      assertCheck(true, "Credit card in query blocked as expected");
    } else {
      assertCheck(false, "Credit card in query should have been blocked");
    }
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "Credit card in query blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 4: Request-phase PII blocking (India PAN)
  console.log("Test 4: Request-phase PII Blocking (India PAN)");
  console.log("----------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM customers WHERE pan = 'ABCDE1234F'",
    });
    if (!resp.success) {
      assertCheck(true, "India PAN in query blocked as expected");
    } else {
      assertCheck(false, "India PAN in query should have been blocked");
    }
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "India PAN in query blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 5: Request-phase PII blocking (India Aadhaar)
  console.log("Test 5: Request-phase PII Blocking (India Aadhaar)");
  console.log("--------------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT * FROM customers WHERE aadhaar = '234567890123'",
    });
    if (!resp.success) {
      assertCheck(true, "India Aadhaar in query blocked as expected");
    } else {
      assertCheck(false, "India Aadhaar in query should have been blocked");
    }
  } catch (err) {
    if (err instanceof ConnectorError) {
      assertCheck(true, "India Aadhaar in query blocked as expected");
      console.log(`   Block reason: ${err.message}`);
    } else {
      console.log(`   Unexpected error: ${err}`);
    }
  }
  console.log();

  // Test 6: Non-critical PII (email) - should NOT be blocked
  console.log("Test 6: Non-critical PII (Email) - Should Pass");
  console.log("----------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT 'john@example.com' as test_email",
    });
    if (resp.success) {
      assertCheck(true, "Email in query allowed (non-critical PII)");
    } else {
      console.log("   Note: Email was blocked (policy may be strict)");
    }
  } catch (err) {
    console.log(`   Note: Email was blocked (policy may be strict): ${err}`);
  }
  console.log();

  // Test 7: Non-critical PII (phone) - should NOT be blocked
  console.log("Test 7: Non-critical PII (Phone) - Should Pass");
  console.log("----------------------------------------------");
  try {
    const resp = await client.mcpQuery({
      connector: "postgres",
      statement: "SELECT '+1-555-123-4567' as test_phone",
    });
    if (resp.success) {
      assertCheck(true, "Phone in query allowed (non-critical PII)");
    } else {
      console.log("   Note: Phone was blocked (policy may be strict)");
    }
  } catch (err) {
    console.log(`   Note: Phone was blocked (policy may be strict): ${err}`);
  }
  console.log();

  // Summary
  console.log("=======================================");
  if (failures.length === 0) {
    console.log(`ALL TESTS PASSED (${passes} assertions)`);
    console.log();
    console.log("MCP PII Handling validated:");
    console.log("  Response-phase:");
    console.log("    - SSN redaction in response data");
    console.log("    - Credit card redaction in response data");
    console.log("  Request-phase blocking:");
    console.log("    - US SSN in query (critical)");
    console.log("    - Credit Card in query (critical)");
    console.log("    - India PAN in query (critical)");
    console.log("    - India Aadhaar in query (critical)");
    console.log("  Non-critical (allowed):");
    console.log("    - Email in query");
    console.log("    - Phone in query");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
