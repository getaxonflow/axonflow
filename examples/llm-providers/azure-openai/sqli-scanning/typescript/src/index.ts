/**
 * Azure OpenAI SQL Injection Detection Example
 *
 * Demonstrates AxonFlow's SQL injection scanning with Azure OpenAI as the LLM provider.
 *
 * v11: the stored policy action decides. Every shipped sys_sqli_* policy stores
 * "warn", so AxonFlow detects SQL injection and reports the matched policy in
 * policyInfo.policiesEvaluated, but does NOT block it. To block SQL injection,
 * record an organization override of category "sqli" with action "block"
 * (PUT /api/v1/detection-posture/sqli on the customer portal API, Enterprise) or
 * change the policy's action. This example validates the shipped actions with no
 * override recorded. SQLI_ACTION no longer sets an action.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow, PolicyViolationError } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
  expectDetected?: boolean;
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

async function main(): Promise<void> {
  console.log("AxonFlow SQL Injection Detection with Azure OpenAI - TypeScript");
  console.log("=".repeat(60));
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "azure-sqli-demo",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  });

  const testCases: TestCase[] = [
    {
      name: "Safe Query",
      query: "What are the best practices for Azure OpenAI?",
      shouldBlock: false,
    },
    // SQL injection warns by default: detected, not blocked.
    {
      name: "Classic SQL Injection",
      query: "SELECT * FROM users WHERE id = 1 OR 1=1",
      shouldBlock: false,
      expectDetected: true,
    },
    {
      name: "DROP TABLE Attack",
      query: "DROP TABLE users; SELECT * FROM admin;",
      shouldBlock: false,
      expectDetected: true,
    },
    {
      name: "Union-based Injection",
      query: "SELECT name FROM products UNION SELECT password FROM users",
      shouldBlock: false,
      expectDetected: true,
    },
    {
      name: "Comment-based Injection",
      query: "SELECT * FROM users WHERE name = 'admin'--",
      shouldBlock: false,
    },
    {
      name: "Truncate Attack",
      query: "TRUNCATE TABLE customer_data;",
      shouldBlock: false,
      expectDetected: true,
    },
    {
      name: "Legitimate SQL Question",
      query: "How do I write a SQL query to join two tables?",
      shouldBlock: false,
    },
  ];

  for (const tc of testCases) {
    console.log(`--- ${tc.name} ---`);
    console.log(`Query: ${tc.query.substring(0, 50)}...`);

    try {
      const response = await client.proxyLLMCall({
        userToken: "sqli-test-user",
        query: tc.query,
        requestType: "chat",
        context: { provider: "azure-openai" },
      });

      const blocked = response.blocked;

      // Assert blocking behavior matches expectation
      assertCheck(
        blocked === tc.shouldBlock,
        `${tc.name}: blocked=${blocked}, expected=${tc.shouldBlock}`
      );

      // Assert response has required fields
      assertCheck(
        response.success !== undefined,
        `${tc.name}: response has success field`
      );

      if (blocked) {
        // Assert blocked responses have a reason
        assertCheck(
          response.blockReason !== undefined && response.blockReason !== "",
          `${tc.name}: blocked response has blockReason`
        );
        console.log(`  Reason: ${response.blockReason}`);
        console.log("  (not the shipped outcome: an org sqli=block override or an edited policy action is in force)");
      } else {
        // Assert allowed responses have data
        assertCheck(
          response.data !== undefined,
          `${tc.name}: allowed response has data`
        );
        const detected = (response.policyInfo?.policiesEvaluated ?? []).filter((p) =>
          p.startsWith("sys_sqli_")
        );
        if (detected.length > 0) {
          console.log(`  SQLi WARNED: ${detected.join(", ")}`);
        }
        if (tc.expectDetected) {
          assertCheck(
            detected.length > 0,
            `${tc.name}: sys_sqli_* policy detected (stored action: warn)`
          );
        }
      }
    } catch (error) {
      // PolicyViolationError means the request was blocked
      if (error instanceof PolicyViolationError) {
        const blocked = true;

        // Assert blocking behavior matches expectation
        assertCheck(
          blocked === tc.shouldBlock,
          `${tc.name}: blocked=${blocked}, expected=${tc.shouldBlock}`
        );

        // Assert error has message
        assertCheck(
          error.message !== undefined && error.message !== "",
          `${tc.name}: PolicyViolationError has message`
        );
        console.log(`  Reason: ${error.message}`);
        console.log("  (not the shipped outcome: an org sqli=block override or an edited policy action is in force)");
      } else {
        console.log(`  Error: ${error}`);
        failures.push(`${tc.name}: unexpected error - ${error}`);
      }
    }

    console.log();
  }

  console.log("=".repeat(60));
  console.log(`Results: ${testCases.length - failures.length} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("Failures:");
    failures.forEach((f) => console.log(`  - ${f}`));
  }
  console.log("=".repeat(60));

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch(console.error);
