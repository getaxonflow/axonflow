/**
 * AxonFlow SQL Injection Detection - TypeScript
 *
 * Demonstrates AxonFlow's SQLi detection capabilities:
 * - DROP/DELETE/TRUNCATE statements
 * - UNION SELECT attacks
 * - Boolean-based injection (OR 1=1)
 * - Comment injection
 * - Stacked queries
 * - Time-based blind SQLi
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
}

const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "sqli-detection-demo",
});

async function main() {
  console.log("AxonFlow SQL Injection Detection - TypeScript");
  console.log("=".repeat(40));
  console.log();

  const testCases: TestCase[] = [
    {
      name: "Safe Query",
      query: "Find users who signed up in the last 30 days",
      shouldBlock: false,
    },
    {
      name: "DROP TABLE",
      query: "SELECT * FROM users; DROP TABLE users;--",
      shouldBlock: true,
    },
    {
      name: "UNION SELECT",
      query: "Get user where id = 1 UNION SELECT password FROM admin",
      shouldBlock: true,
    },
    {
      name: "Boolean Injection (OR 1=1)",
      query: "SELECT * FROM users WHERE username='' OR '1'='1'",
      shouldBlock: true,
    },
    {
      name: "Comment Injection",
      query: "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
      shouldBlock: false, // Comment injection not currently detected by default policies
    },
    {
      name: "Stacked Queries",
      query: "SELECT name FROM users; DELETE FROM audit_log;",
      shouldBlock: true,
    },
    {
      name: "Truncate Statement",
      query: "SELECT * FROM data; TRUNCATE TABLE logs;",
      shouldBlock: true,
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const test of testCases) {
    console.log(`Test: ${test.name}`);
    const queryPreview =
      test.query.length > 60 ? test.query.substring(0, 60) + "..." : test.query;
    console.log(`  Query: ${queryPreview}`);

    try {
      const result = await axonflow.getPolicyApprovedContext({
        userToken: "sqli-detection-user",
        query: test.query,
      });

      const wasBlocked = !result.approved;

      if (wasBlocked) {
        console.log(`  Result: BLOCKED`);
        console.log(`  Reason: ${result.blockReason}`);
      } else {
        console.log(`  Result: APPROVED`);
        console.log(`  Context ID: ${result.contextId}`);
      }

      if (result.policies && result.policies.length > 0) {
        console.log(`  Policies: ${result.policies.join(", ")}`);
      }

      if (wasBlocked === test.shouldBlock) {
        console.log(`  Test: PASS`);
        passed++;
      } else {
        const expected = test.shouldBlock ? "blocked" : "approved";
        console.log(`  Test: FAIL (expected ${expected})`);
        failed++;
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      console.log(`  Result: ERROR - ${errorMessage}`);
      failed++;
    }

    console.log();
  }

  console.log("=".repeat(40));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log();

  if (failed > 0) {
    console.log("Some tests failed. Check your AxonFlow policy configuration.");
    process.exit(1);
  }

  console.log("All SQLi detection tests passed!");
}

main();
