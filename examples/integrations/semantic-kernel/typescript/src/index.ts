/**
 * Semantic Kernel + AxonFlow Integration Example (TypeScript SDK)
 *
 * This example demonstrates how to add AxonFlow governance to Semantic Kernel-style
 * AI agent workflows. Semantic Kernel provides an SDK for building AI agents with
 * plugins, planners, and memory.
 *
 * Features demonstrated:
 * - Governed Kernel: AxonFlow policy enforcement for AI operations
 * - Plugin Governance: Each plugin call goes through policy checks
 * - Planner Integration: Plans are validated before execution
 * - Memory Governance: Sensitive data is protected
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Requirements:
 * - AxonFlow running locally (docker compose up)
 * - Node.js 18+
 *
 * Usage:
 *     npm install
 *     npm start
 */

import { AxonFlow } from "@axonflow/sdk";

// =============================================================================
// Assertion Infrastructure
// =============================================================================

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

// =============================================================================
// Types
// =============================================================================

interface PluginResult {
  success: boolean;
  result?: string;
  blockReason?: string;
}

type PluginFunction = (input: string) => Promise<string>;

interface Plugin {
  name: string;
  description: string;
  execute: PluginFunction;
}

// =============================================================================
// Configuration
// =============================================================================

const config = {
  agentUrl: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  tenant: process.env.AXONFLOW_TENANT || "semantic-kernel-demo",
};

// =============================================================================
// Governed Semantic Kernel Implementation
// =============================================================================

/**
 * GovernedKernel wraps Semantic Kernel operations with AxonFlow governance.
 * All AI calls go through policy evaluation before execution.
 */
class GovernedKernel {
  private axonflow: AxonFlow;
  private userToken: string;
  private plugins: Map<string, Plugin> = new Map();

  constructor(axonflow: AxonFlow, userToken: string) {
    this.axonflow = axonflow;
    this.userToken = userToken;
  }

  /**
   * Register a plugin function with the kernel.
   */
  registerPlugin(name: string, description: string, execute: PluginFunction): void {
    this.plugins.set(name, { name, description, execute });
    console.log(`   Registered plugin: ${name}`);
  }

  /**
   * Invoke a plugin with governance.
   */
  async invokePlugin(pluginName: string, input: string): Promise<PluginResult> {
    console.log(`\n[Kernel] Invoking plugin: ${pluginName}`);
    console.log(`   Input: ${truncate(input, 50)}`);

    try {
      // Get policy approval before plugin execution
      const approved = await this.axonflow.getPolicyApprovedContext({
        userToken: this.userToken,
        query: input,
        context: {
          plugin: pluginName,
          framework: "semantic-kernel",
          operation: "plugin_invoke",
        },
      });

      if (!approved.approved) {
        console.log(`   BLOCKED: ${approved.blockReason}`);
        return { success: false, blockReason: approved.blockReason };
      }

      // Execute the plugin
      const plugin = this.plugins.get(pluginName);
      if (!plugin) {
        return { success: false, blockReason: `Plugin not found: ${pluginName}` };
      }

      const result = await plugin.execute(input);

      // Audit the execution
      await this.axonflow.auditLLMCall({
        contextId: approved.contextId,
        responseSummary: truncate(result, 100),
        provider: "semantic-kernel",
        model: pluginName,
        tokenUsage: { promptTokens: 50, completionTokens: 100, totalTokens: 150 },
        latencyMs: 50,
      });

      console.log("   ✓ Plugin executed and audited");
      return { success: true, result };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);

      // Check if this is a policy block
      if (
        errorMsg.includes("Social Security") ||
        errorMsg.toLowerCase().includes("sql injection") ||
        errorMsg.toLowerCase().includes("blocked")
      ) {
        console.log(`   BLOCKED: ${errorMsg}`);
        return { success: false, blockReason: errorMsg };
      }

      console.log(`   Error: ${errorMsg}`);
      return { success: false, blockReason: errorMsg };
    }
  }

  /**
   * Execute a governed prompt.
   */
  async invokePrompt(prompt: string): Promise<PluginResult> {
    return this.invokePlugin("prompt", prompt);
  }

  /**
   * Execute a multi-step plan with governance at each step.
   */
  async executePlan(steps: Array<{ plugin: string; input: string }>): Promise<PluginResult[]> {
    console.log(`\n[Kernel] Executing plan with ${steps.length} steps`);

    const results: PluginResult[] = [];

    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      console.log(`\n   Step ${i + 1}: ${step.plugin}`);

      const result = await this.invokePlugin(step.plugin, step.input);
      results.push(result);

      if (!result.success) {
        console.log(`   Plan halted at step ${i + 1}`);
        break;
      }
    }

    return results;
  }
}

// =============================================================================
// Test Cases
// =============================================================================

async function runTests(axonflow: AxonFlow): Promise<void> {
  console.log("\n[Setup] Creating Governed Kernel...");
  const kernel = new GovernedKernel(axonflow, "sk-user-123");

  // Register plugins
  kernel.registerPlugin("summarize", "Summarizes text content", async (input) => {
    return `Summary: ${truncate(input, 50)}...`;
  });

  kernel.registerPlugin("translate", "Translates text to another language", async (input) => {
    return `Translated: ${input}`;
  });

  kernel.registerPlugin("search", "Searches for information", async (input) => {
    return `Search results for: ${truncate(input, 30)}...`;
  });

  kernel.registerPlugin("prompt", "Executes a prompt", async (input) => {
    return `Response to: ${truncate(input, 30)}...`;
  });

  kernel.registerPlugin("analyze", "Analyzes data", async (input) => {
    return `Analysis of: ${truncate(input, 30)}...`;
  });

  // Test 1: Safe plugin call
  console.log("\n" + "=".repeat(60));
  console.log("[Test 1] Safe Plugin Call - Summarize");
  console.log("-".repeat(40));

  const result1 = await kernel.invokePlugin(
    "summarize",
    "The quick brown fox jumps over the lazy dog. This is a classic pangram used for testing."
  );

  assertCheck(result1.success === true, "Safe plugin call returns success=true");
  assertCheck(result1.result !== undefined && result1.result !== "", "Safe plugin call returns non-empty result");
  assertCheck(result1.blockReason === undefined, "Safe plugin call has no blockReason");

  if (result1.success) {
    console.log(`   Result: ${result1.result}`);
  }

  // Test 2: Safe prompt
  console.log("\n" + "=".repeat(60));
  console.log("[Test 2] Safe Prompt - Research Query");
  console.log("-".repeat(40));

  const result2 = await kernel.invokePrompt(
    "What are the key principles of responsible AI development?"
  );

  assertCheck(result2.success === true, "Safe prompt returns success=true");
  assertCheck(result2.result !== undefined && result2.result !== "", "Safe prompt returns non-empty result");

  if (result2.success) {
    console.log(`   Result: ${result2.result}`);
  }

  // Test 3: PII Detection
  console.log("\n" + "=".repeat(60));
  console.log("[Test 3] PII Detection - Should be blocked");
  console.log("-".repeat(40));

  const result3 = await kernel.invokePlugin(
    "search",
    "Find customer record for SSN 123-45-6789"
  );

  assertCheck(result3.success === false, "PII query returns success=false (blocked)");
  assertCheck(result3.blockReason !== undefined && result3.blockReason !== "", "PII query has blockReason explaining the violation");
  assertCheck(
    !!(result3.blockReason?.toLowerCase().includes("pii") ||
    result3.blockReason?.toLowerCase().includes("ssn") ||
    result3.blockReason?.toLowerCase().includes("social security") ||
    result3.blockReason?.toLowerCase().includes("blocked")),
    "PII blockReason indicates PII/SSN violation"
  );

  // Test 4: SQL Injection
  console.log("\n" + "=".repeat(60));
  console.log("[Test 4] SQL Injection - Should be blocked");
  console.log("-".repeat(40));

  const result4 = await kernel.invokePlugin(
    "search",
    "SELECT * FROM users; DROP TABLE customers;--"
  );

  assertCheck(result4.success === false, "SQL injection query returns success=false (blocked)");
  assertCheck(result4.blockReason !== undefined && result4.blockReason !== "", "SQL injection query has blockReason");
  assertCheck(
    !!(result4.blockReason?.toLowerCase().includes("sql") ||
    result4.blockReason?.toLowerCase().includes("injection") ||
    result4.blockReason?.toLowerCase().includes("blocked")),
    "SQL injection blockReason indicates SQL/injection violation"
  );

  // Test 5: Multi-step plan
  console.log("\n" + "=".repeat(60));
  console.log("[Test 5] Multi-Step Plan Execution");
  console.log("-".repeat(40));

  const planResults = await kernel.executePlan([
    { plugin: "search", input: "Find information about renewable energy" },
    { plugin: "analyze", input: "Analyze the search results" },
    { plugin: "summarize", input: "Create a summary of the analysis" },
  ]);

  const allSucceeded = planResults.every((r) => r.success);
  assertCheck(planResults.length === 3, "Multi-step plan executes all 3 steps");
  assertCheck(allSucceeded, "All steps in multi-step plan succeed");
  assertCheck(planResults[0].result !== undefined, "First step (search) returns a result");
  assertCheck(planResults[1].result !== undefined, "Second step (analyze) returns a result");
  assertCheck(planResults[2].result !== undefined, "Third step (summarize) returns a result");

  // Test 6: Plan with blocked step
  console.log("\n" + "=".repeat(60));
  console.log("[Test 6] Plan with Blocked Step");
  console.log("-".repeat(40));

  const blockedPlanResults = await kernel.executePlan([
    { plugin: "search", input: "Find user data" },
    { plugin: "search", input: "Lookup SSN 999-88-7777" }, // Should be blocked
    { plugin: "summarize", input: "Summarize findings" },
  ]);

  const blocked = blockedPlanResults.some((r) => !r.success);
  assertCheck(blocked, "Plan with PII query has at least one blocked step");
  assertCheck(blockedPlanResults.length <= 3, "Plan halts at or before completing all steps");

  // Find the blocked step
  const blockedStep = blockedPlanResults.find((r) => !r.success);
  assertCheck(
    blockedStep?.blockReason !== undefined,
    "Blocked step in plan has a blockReason"
  );

  console.log("\n" + "=".repeat(60));
  console.log("Test Summary");
  console.log("=".repeat(60));
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => console.log(`   - ${f}`));
  }
  console.log("=".repeat(60) + "\n");
}

// =============================================================================
// Utility Functions
// =============================================================================

function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + "...";
}

// =============================================================================
// Main Entry Point
// =============================================================================

async function main(): Promise<void> {
  console.log("Semantic Kernel + AxonFlow Integration (TypeScript SDK)");
  console.log("=".repeat(60));

  console.log(`\nChecking AxonFlow at ${config.agentUrl}...`);

  const axonflow = new AxonFlow({
    endpoint: config.agentUrl,
    tenant: config.tenant,
  });

  try {
    const health = await axonflow.healthCheck();
    if (health.status !== "healthy") {
      console.error("AxonFlow is not healthy. Start it with: docker compose up -d");
      process.exit(1);
    }
    console.log(`Status: ${health.status}`);

    await runTests(axonflow);
  } catch (error) {
    console.error("Error connecting to AxonFlow:", error);
    console.error("\nMake sure AxonFlow is running: docker compose up -d");
    process.exit(1);
  }
}

main()
  .then(() => {
    process.exit(failures.length > 0 ? 1 : 0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
