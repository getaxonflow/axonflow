/**
 * AxonFlow PII Detection - TypeScript
 *
 * Demonstrates AxonFlow's built-in PII detection:
 * - US Social Security Numbers (SSN)
 * - Credit Card numbers
 * - India PAN (Permanent Account Number)
 * - India Aadhaar numbers
 * - Email addresses
 * - Phone numbers
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
  piiType: string;
}

const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "pii-detection-demo",
});

async function main() {
  console.log("AxonFlow PII Detection - TypeScript");
  console.log("=".repeat(40));
  console.log();

  const testCases: TestCase[] = [
    {
      name: "Safe Query (No PII)",
      query: "What is the capital of France?",
      shouldBlock: false,
      piiType: "",
    },
    {
      name: "US Social Security Number",
      query: "Process refund for customer with SSN 123-45-6789",
      shouldBlock: true,
      piiType: "ssn",
    },
    {
      name: "Credit Card Number",
      query: "Charge card 4111-1111-1111-1111 for $99.99",
      shouldBlock: true,
      piiType: "credit_card",
    },
    {
      name: "India PAN",
      query: "Verify PAN number ABCDE1234F for tax filing",
      shouldBlock: true,
      piiType: "pan",
    },
    {
      name: "India Aadhaar",
      query: "Link Aadhaar 2345 6789 0123 to account",
      shouldBlock: true,
      piiType: "aadhaar",
    },
    {
      name: "Email Address",
      query: "Send invoice to john.doe@example.com",
      shouldBlock: true,
      piiType: "email",
    },
    {
      name: "Phone Number",
      query: "Call customer at +1-555-123-4567",
      shouldBlock: true,
      piiType: "phone",
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
        userToken: "pii-detection-user",
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

      // Verify expected behavior
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

  console.log("All PII detection tests passed!");
  console.log();
  console.log("Next steps:");
  console.log("  - Custom Policies: ../policies/");
  console.log("  - Code Governance: ../code-governance/");
}

main();
