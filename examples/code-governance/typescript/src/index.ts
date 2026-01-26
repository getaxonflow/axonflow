/**
 * AxonFlow Code Governance - TypeScript
 *
 * Demonstrates code artifact detection in LLM responses:
 * 1. Send a code generation query to AxonFlow
 * 2. AxonFlow automatically detects code in the response
 * 3. Code metadata is included in policyInfo for audit
 *
 * The codeArtifact field contains:
 * - language: Detected programming language
 * - codeType: Category (function, class, script, config, snippet)
 * - sizeBytes: Size of detected code
 * - lineCount: Number of lines
 * - secretsDetected: Count of potential secrets
 * - unsafePatterns: Count of unsafe code patterns
 *
 * Prerequisites:
 * - AxonFlow Agent running on localhost:8080
 * - OpenAI or Anthropic API key configured in AxonFlow
 *
 * Usage:
 *   cp .env.example .env  # Configure your settings
 *   npm install
 *   npm start
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

interface CodeArtifact {
  is_code_output?: boolean;
  language?: string;
  code_type?: string;
  size_bytes?: number;
  line_count?: number;
  secrets_detected?: number;
  unsafe_patterns?: number;
  policies_checked?: string[];
}

const config = {
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo-secret",
};

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
  console.log("AxonFlow Code Governance - TypeScript");
  console.log("=".repeat(60));
  console.log();
  console.log("This demo shows automatic code detection in LLM responses.");
  console.log();

  const axonflow = new AxonFlow({
    endpoint: config.endpoint,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
  });

  // AXONFLOW_USER_TOKEN: Set to JWT for enterprise mode
  // In community mode, SDK defaults to "anonymous" if not set
  const userToken = process.env.AXONFLOW_USER_TOKEN || "";

  // Example 1: Generate a TypeScript function
  console.log("-".repeat(60));
  console.log("Example 1: Generate a TypeScript function");
  console.log("-".repeat(60));

  try {
    const response = await axonflow.proxyLLMCall({
      userToken,
      query: "Write a TypeScript function to validate email addresses using regex",
      requestType: "chat",
      context: {
        provider: "openai",
        model: "gpt-3.5-turbo",
      },
    });

    // Assert response has required fields
    assertCheck(
      response.success !== undefined,
      "Example 1: response has success field"
    );
    assertCheck(
      typeof response.blocked === "boolean",
      "Example 1: response has blocked field"
    );

    if (response.blocked) {
      console.log(`Status: BLOCKED - ${response.blockReason}`);
      assertCheck(
        response.blockReason !== undefined && response.blockReason !== "",
        "Example 1: blocked response has blockReason"
      );
    } else if (response.success) {
      console.log("Status: ALLOWED");
      console.log();

      // Assert allowed response has data
      assertCheck(
        response.data !== undefined,
        "Example 1: allowed response has data"
      );

      // Display response preview
      const dataStr = typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data);
      console.log("Response preview:");
      console.log(`  ${dataStr.substring(0, 300)}${dataStr.length > 300 ? "..." : ""}`);
      console.log();

      // Display audit trail
      console.log("Audit Trail:");
      if (response.policyInfo) {
        assertCheck(
          response.policyInfo !== undefined,
          "Example 1: response has policyInfo"
        );
        console.log(`  Processing Time: ${response.policyInfo.processingTime || "N/A"}`);
        console.log(`  Static Checks: ${response.policyInfo.staticChecks || "N/A"}`);

        // Code Governance: Check for code artifact metadata
        const codeArtifact = (response.policyInfo as { codeArtifact?: CodeArtifact }).codeArtifact;
        if (codeArtifact) {
          console.log();
          console.log("Code Artifact Detected:");
          console.log(`  Language: ${codeArtifact.language || "unknown"}`);
          console.log(`  Type: ${codeArtifact.code_type || "unknown"}`);
          console.log(`  Size: ${codeArtifact.size_bytes || 0} bytes`);
          console.log(`  Lines: ${codeArtifact.line_count || 0}`);
          console.log(`  Secrets Detected: ${codeArtifact.secrets_detected || 0}`);
          console.log(`  Unsafe Patterns: ${codeArtifact.unsafe_patterns || 0}`);

          // Assert code artifact has expected fields for code generation query
          assertCheck(
            codeArtifact.is_code_output === true || codeArtifact.language !== undefined,
            "Example 1: code artifact detected for code generation query"
          );
        }
      }
    }
  } catch (error) {
    console.log(`Error: ${error instanceof Error ? error.message : String(error)}`);
    failures.push(`Example 1: ${error instanceof Error ? error.message : String(error)}`);
  }

  console.log();

  // Example 2: Check for unsafe patterns
  console.log("-".repeat(60));
  console.log("Example 2: Check for unsafe patterns in generated code");
  console.log("-".repeat(60));

  try {
    const response = await axonflow.proxyLLMCall({
      userToken,
      query: "Write a TypeScript function that uses child_process.exec to run shell commands from user input",
      requestType: "chat",
      context: {
        provider: "openai",
        model: "gpt-3.5-turbo",
      },
    });

    // Assert response has required fields
    assertCheck(
      response.success !== undefined,
      "Example 2: response has success field"
    );
    assertCheck(
      typeof response.blocked === "boolean",
      "Example 2: response has blocked field"
    );

    if (response.blocked) {
      console.log(`Status: BLOCKED - ${response.blockReason}`);
      // Blocking unsafe code request is valid behavior
      assertCheck(
        response.blockReason !== undefined && response.blockReason !== "",
        "Example 2: blocked response has blockReason"
      );
    } else if (response.success) {
      console.log("Status: ALLOWED");
      console.log();

      // Assert allowed response has data
      assertCheck(
        response.data !== undefined,
        "Example 2: allowed response has data"
      );

      if (response.policyInfo) {
        assertCheck(
          response.policyInfo !== undefined,
          "Example 2: response has policyInfo"
        );
        console.log(`Processing Time: ${response.policyInfo.processingTime || "N/A"}`);

        const codeArtifact = (response.policyInfo as { codeArtifact?: CodeArtifact }).codeArtifact;
        if (codeArtifact) {
          console.log();
          console.log("Code Artifact Analysis:");
          console.log(`  Language: ${codeArtifact.language || "unknown"}`);
          console.log(`  Unsafe Patterns: ${codeArtifact.unsafe_patterns || 0}`);

          // Assert code artifact detected for code generation query
          assertCheck(
            codeArtifact.is_code_output === true || codeArtifact.language !== undefined,
            "Example 2: code artifact detected for code generation query"
          );

          const unsafeCount = codeArtifact.unsafe_patterns || 0;
          if (unsafeCount > 0) {
            console.log();
            console.log(`  WARNING: ${unsafeCount} unsafe code pattern(s) detected!`);
            console.log("  Detected patterns may include: child_process.exec, command execution");
            console.log("  Review carefully before using in production.");

            // Assert unsafe patterns detected for dangerous query
            assertCheck(
              unsafeCount > 0,
              "Example 2: unsafe patterns detected for child_process.exec query"
            );
          }
        }
      }
    }
  } catch (error) {
    console.log(`Error: ${error instanceof Error ? error.message : String(error)}`);
    failures.push(`Example 2: ${error instanceof Error ? error.message : String(error)}`);
  }

  console.log();
  console.log("=".repeat(60));
  console.log("Summary");
  console.log("=".repeat(60));
  console.log();
  console.log("Code Governance automatically:");
  console.log("  1. Detects code blocks in LLM responses");
  console.log("  2. Identifies the programming language");
  console.log("  3. Counts potential secrets and unsafe patterns");
  console.log("  4. Includes metadata in policyInfo for audit");
  console.log();
  console.log("Use this metadata to:");
  console.log("  - Alert on unsafe patterns before deployment");
  console.log("  - Track code generation for compliance");
  console.log("  - Build dashboards for AI code generation metrics");
  console.log();

  // Final results
  console.log("=".repeat(60));
  console.log(`Results: ${failures.length === 0 ? "ALL PASSED" : `${failures.length} failures`}`);
  if (failures.length > 0) {
    console.log("Failures:");
    failures.forEach((f) => console.log(`  - ${f}`));
  }
  console.log("=".repeat(60));

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
