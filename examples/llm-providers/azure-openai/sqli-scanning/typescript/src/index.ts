/**
 * Azure OpenAI SQL Injection Detection Example
 *
 * Demonstrates AxonFlow's SQL injection scanning with Azure OpenAI as the LLM provider.
 * AxonFlow detects and blocks SQL injection attempts before they reach Azure.
 */

import { AxonFlow, PolicyViolationError } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
}

async function main(): Promise<void> {
  console.log("AxonFlow SQL Injection Detection with Azure OpenAI - TypeScript");
  console.log("=".repeat(60));
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    tenant: process.env.AXONFLOW_CLIENT_ID || "azure-sqli-demo",
    apiKey: process.env.AXONFLOW_CLIENT_SECRET,
    licenseKey: process.env.AXONFLOW_LICENSE_KEY,
  });

  const testCases: TestCase[] = [
    {
      name: "Safe Query",
      query: "What are the best practices for Azure OpenAI?",
      shouldBlock: false,
    },
    {
      name: "Classic SQL Injection",
      query: "SELECT * FROM users WHERE id = 1 OR 1=1",
      shouldBlock: true,
    },
    {
      name: "DROP TABLE Attack",
      query: "DROP TABLE users; SELECT * FROM admin;",
      shouldBlock: true,
    },
    {
      name: "Union-based Injection",
      query: "SELECT name FROM products UNION SELECT password FROM users",
      shouldBlock: true,
    },
    {
      name: "Comment-based Injection",
      query: "SELECT * FROM users WHERE name = 'admin'--",
      shouldBlock: true, // Blocked due to accessing users table
    },
    {
      name: "Truncate Attack",
      query: "TRUNCATE TABLE customer_data;",
      shouldBlock: true,
    },
    {
      name: "Legitimate SQL Question",
      query: "How do I write a SQL query to join two tables?",
      shouldBlock: false,
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const tc of testCases) {
    console.log(`--- ${tc.name} ---`);
    console.log(`Query: ${tc.query.substring(0, 50)}...`);

    try {
      const response = await client.executeQuery({
        userToken: "sqli-test-user",
        query: tc.query,
        requestType: "chat",
        context: { provider: "azure-openai" },
      });

      const blocked = response.blocked;
      const result = blocked === tc.shouldBlock ? "PASS" : "FAIL";

      if (result === "PASS") {
        passed++;
      } else {
        failed++;
      }

      console.log(`  Blocked: ${blocked} (expected: ${tc.shouldBlock}) - ${result}`);

      if (blocked && response.blockReason) {
        console.log(`  Reason: ${response.blockReason}`);
      }
    } catch (error) {
      // PolicyViolationError means the request was blocked
      if (error instanceof PolicyViolationError) {
        const blocked = true;
        const result = blocked === tc.shouldBlock ? "PASS" : "FAIL";

        if (result === "PASS") {
          passed++;
        } else {
          failed++;
        }

        console.log(`  Blocked: ${blocked} (expected: ${tc.shouldBlock}) - ${result}`);
        console.log(`  Reason: ${error.message}`);
      } else {
        console.log(`  Error: ${error}`);
        failed++;
      }
    }

    console.log();
  }

  console.log("=".repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(60));

  process.exit(failed === 0 ? 0 : 1);
}

main().catch(console.error);
