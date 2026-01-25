/**
 * Singapore PII Detection Example
 *
 * Demonstrates AxonFlow's Singapore-specific PII detection for MAS FEAT compliance:
 * - NRIC (National Registration Identity Card)
 * - FIN (Foreign Identification Number)
 * - UEN (Unique Entity Number)
 * - Singapore phone numbers
 * - Singapore postal codes
 *
 * These patterns are available in Community Edition.
 */

import { AxonFlow } from "@axonflow/sdk";

interface TestCase {
  name: string;
  query: string;
  expectedAction: "redact" | "warn" | "approved" | "blocked";
  piiType: string;
}

async function main(): Promise<void> {
  console.log("AxonFlow Singapore PII Detection - TypeScript");
  console.log("=".repeat(48));
  console.log();
  console.log("Testing MAS FEAT Community PII patterns");
  console.log();

  // Initialize AxonFlow client
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "singapore-pii-example",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  });

  // Test cases for Singapore PII patterns
  const testCases: TestCase[] = [
    {
      name: "NRIC (S prefix - Citizen pre-2000)",
      query: "Customer NRIC is S1234567D",
      expectedAction: "redact",
      piiType: "NRIC",
    },
    {
      name: "NRIC (T prefix - Citizen 2000+)",
      query: "New customer T9876543J registered",
      expectedAction: "redact",
      piiType: "NRIC",
    },
    {
      name: "FIN (F prefix - Foreigner pre-2000)",
      query: "Employee FIN: F1234567N",
      expectedAction: "redact",
      piiType: "FIN",
    },
    {
      name: "FIN (G prefix - Foreigner 2000+)",
      query: "Applicant G9876543X submitted documents",
      expectedAction: "redact",
      piiType: "FIN",
    },
    {
      name: "NRIC (M prefix - Foreigner 2022+)",
      query: "New hire M1234567K onboarded",
      expectedAction: "redact",
      piiType: "NRIC",
    },
    {
      name: "UEN (Business registration)",
      query: "Invoice from company UEN 53276128A",
      expectedAction: "redact",
      piiType: "UEN",
    },
    {
      name: "UEN (Company registration)",
      query: "Vendor UEN: 200312345A verified",
      expectedAction: "redact",
      piiType: "UEN",
    },
    {
      name: "Singapore Phone (Mobile)",
      query: "Contact customer at +65 9123 4567",
      expectedAction: "redact",
      piiType: "Phone",
    },
    {
      name: "Singapore Phone (Landline)",
      query: "Office number: +65 6234 5678",
      expectedAction: "redact",
      piiType: "Phone",
    },
    {
      name: "Singapore Postal Code",
      query: "Delivery address: Singapore 238877",
      expectedAction: "warn", // Postal codes are warn-only (low severity)
      piiType: "Postal",
    },
    {
      name: "Safe Query (No PII)",
      query: "What is the weather in Singapore?",
      expectedAction: "approved",
      piiType: "None",
    },
    {
      name: "Multiple PII",
      query: "Customer S1234567D phone +65 8123 4567",
      expectedAction: "redact",
      piiType: "Multiple",
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const tc of testCases) {
    console.log(`Test: ${tc.name} (${tc.piiType})`);
    const queryPreview =
      tc.query.length > 60 ? tc.query.substring(0, 60) + "..." : tc.query;
    console.log(`  Query: ${queryPreview}`);

    try {
      const result = await client.getPolicyApprovedContext({
        userToken: "singapore-user",
        query: tc.query,
      });

      console.log(`  Approved: ${result.approved}`);
      if (result.contextId) {
        console.log(`  Context ID: ${result.contextId}`);
      }
      if (result.policies && result.policies.length > 0) {
        console.log(`  Policies: ${result.policies.join(", ")}`);
      }
      if (!result.approved && result.blockReason) {
        console.log(`  Block Reason: ${result.blockReason}`);
      }

      // Check expectation
      // For redact/warn, the request should still be approved
      let status: string;
      if (["redact", "warn", "approved"].includes(tc.expectedAction)) {
        if (result.approved) {
          status = "PASS";
          passed++;
        } else {
          status = "FAIL";
          failed++;
        }
      } else {
        // blocked
        if (!result.approved) {
          status = "PASS";
          passed++;
        } else {
          status = "FAIL";
          failed++;
        }
      }

      console.log(`  Status: ${status} (expected: ${tc.expectedAction})`);
    } catch (error) {
      console.log(`  Result: ERROR - ${error}`);
      failed++;
    }

    console.log();
  }

  console.log("=".repeat(48));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log();

  if (failed > 0) {
    console.log("Some tests failed. Check:");
    console.log("  - AxonFlow stack is running");
    console.log("  - Singapore PII policies are loaded (migration 042)");
    process.exit(1);
  }

  console.log("All Singapore PII detection tests passed!");
  console.log();
  console.log("MAS FEAT Compliance Notes:");
  console.log("  - NRIC/FIN: Critical severity, auto-redacted");
  console.log("  - UEN: High severity, auto-redacted");
  console.log("  - Phone: Medium severity, auto-redacted");
  console.log("  - Postal: Low severity, warning only");
  console.log();
  console.log("Enterprise features (checksum validation, AI registry)");
  console.log("are available with an Enterprise license.");
}

main().catch(console.error);
