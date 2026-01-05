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
 *
 * Default Behavior (Issue #891):
 *   PII detection defaults to "redact" mode - requests are APPROVED but flagged
 *   with requiresRedaction=true for downstream redaction by the Orchestrator.
 *   Set PII_ACTION=block to restore blocking behavior.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  expectRedact: boolean;
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
  console.log("Default Mode: redact (PII flagged for redaction, not blocked)");
  console.log();

  // PII test cases
  // expectRedact: true = critical PII (requiresRedaction=true)
  // expectRedact: false = non-critical or no PII (logged but not flagged)
  const testCases: TestCase[] = [
    {
      name: "Safe Query (No PII)",
      query: "What is the capital of France?",
      expectRedact: false,
    },
    {
      name: "US Social Security Number (Critical PII)",
      query: "Process refund for customer with SSN 123-45-6789",
      expectRedact: true,
    },
    {
      name: "Credit Card Number (Critical PII)",
      query: "Charge card 4111-1111-1111-1111 for $99.99",
      expectRedact: true,
    },
    {
      name: "India PAN (Critical PII)",
      query: "Verify PAN number ABCDE1234F for tax filing",
      expectRedact: true,
    },
    {
      name: "India Aadhaar (Critical PII)",
      query: "Link Aadhaar 2345 6789 0123 to account",
      expectRedact: true,
    },
    {
      name: "Email Address (Non-Critical PII)",
      query: "Send invoice to john.doe@gmail.com",
      expectRedact: false, // Medium severity - logged but not flagged
    },
    {
      name: "Phone Number (Non-Critical PII)",
      query: "Call customer at +1-555-123-4567",
      expectRedact: false, // Medium severity - logged but not flagged
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

      // Check if request was approved
      if (result.approved) {
        if (result.requiresRedaction) {
          console.log("  Result: APPROVED (requires redaction)");
        } else {
          console.log("  Result: APPROVED");
        }
        console.log(`  Context ID: ${result.contextId}`);
      } else {
        // Request was blocked (only if PII_ACTION=block)
        console.log("  Result: BLOCKED");
        console.log(`  Reason: ${result.blockReason}`);
      }

      if (result.policies && result.policies.length > 0) {
        console.log(`  Policies: ${result.policies.join(", ")}`);
      }

      // Get actual redaction status (blocked also counts as "requires handling")
      const actualRequiresRedaction =
        result.requiresRedaction || !result.approved;

      // Verify expected behavior
      if (test.expectRedact && actualRequiresRedaction) {
        console.log("  Test: PASS (PII detected, flagged for redaction)");
        passed++;
      } else if (
        !test.expectRedact &&
        !actualRequiresRedaction &&
        result.approved
      ) {
        console.log("  Test: PASS (no critical PII detected)");
        passed++;
      } else {
        const expected = test.expectRedact
          ? "requiresRedaction=true"
          : "no critical PII";
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
  console.log("Configuration:");
  console.log(
    "  - Default: PII_ACTION=redact (PII flagged for redaction, not blocked)"
  );
  console.log("  - To block PII: PII_ACTION=block docker compose up -d");
  console.log();
  console.log("Next steps:");
  console.log("  - Custom Policies: ../policies/");
  console.log("  - Code Governance: ../code-governance/");
}

main();
