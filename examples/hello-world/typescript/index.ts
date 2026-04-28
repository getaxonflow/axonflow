/**
 * AxonFlow Hello World - TypeScript
 *
 * The simplest example of using AxonFlow SDK. Tests policy evaluation
 * (no LLM call): safe query is approved, SQL injection is blocked,
 * PII (SSN) is approved with redaction. Mirrors the Go/Python/Java
 * hello-world variants.
 *
 * For Gateway Mode (pre-check + LLM call + audit), see
 *   examples/integrations/gateway-mode/typescript/
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

const axonflow = new AxonFlow({
  endpoint:
    process.env.AXONFLOW_ENDPOINT ||
    process.env.AXONFLOW_AGENT_URL ||
    "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo-secret",
});

const userToken = process.env.AXONFLOW_USER_TOKEN || "hello-world-user";

async function main() {
  console.log("AxonFlow Hello World - TypeScript");
  console.log("========================================\n");

  // Test 1: Safe Query - should be approved
  console.log("Test 1: Safe Query");
  console.log("------------------");
  try {
    const r = await axonflow.getPolicyApprovedContext({
      userToken,
      query: "What is the weather today?",
    });
    assertCheck(r.approved === true, "Safe query is approved");
    assertCheck(typeof r.contextId === "string" && r.contextId !== "", "Safe query returns context ID");
  } catch (err) {
    failures.push(`Safe query unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  }
  console.log();

  // Test 2: SQL Injection - should be blocked
  console.log("Test 2: SQL Injection");
  console.log("---------------------");
  try {
    const r = await axonflow.getPolicyApprovedContext({
      userToken,
      query: "SELECT * FROM users; DROP TABLE users;",
    });
    assertCheck(r.approved === false, "SQLi query is blocked");
    assertCheck(typeof r.blockReason === "string" && r.blockReason !== "", "SQLi query has block reason");
    if (r.blockReason) console.log(`   Block reason: ${r.blockReason}`);
  } catch (err) {
    failures.push(`SQLi query unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  }
  console.log();

  // Test 3: PII (SSN) - should be approved (redact mode)
  console.log("Test 3: PII (SSN)");
  console.log("-----------------");
  try {
    const r = await axonflow.getPolicyApprovedContext({
      userToken,
      query: "Process payment for SSN 123-45-6789",
    });
    assertCheck(r.approved === true, "PII query is approved (redact mode)");
    assertCheck(Array.isArray(r.policies) && r.policies.length > 0, "PII query triggers policy detection");
    if (r.policies?.length) console.log(`   Policies: ${r.policies.join(", ")}`);
  } catch (err) {
    failures.push(`PII query unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  }
  console.log();

  console.log("========================================");
  if (failures.length === 0) {
    console.log("✓ ALL TESTS PASSED");
    process.exit(0);
  } else {
    console.log(`❌ ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => console.log(`   - ${f}`));
    process.exit(1);
  }
}

main();
