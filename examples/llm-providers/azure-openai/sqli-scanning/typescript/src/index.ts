/**
 * Azure OpenAI SQL Injection Detection Example
 *
 * Demonstrates AxonFlow's SQL injection scanning with Azure OpenAI as the LLM provider.
 * AxonFlow detects and blocks SQL injection attempts before they reach Azure.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow, PolicyViolationError } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
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
      } else {
        // Assert allowed responses have data
        assertCheck(
          response.data !== undefined,
          `${tc.name}: allowed response has data`
        );
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
