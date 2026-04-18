/**
 * Execution Boundary Semantics - TypeScript (#1414)
 *
 * Demonstrates and validates idempotent retry behavior for WCP step gates:
 * 1. Default retry behavior is idempotent (same step returns cached decision)
 * 2. Explicit retry_policy="reevaluate" forces fresh policy evaluation
 * 3. Response includes cached (bool) and decision_source ("fresh"/"cached")
 * 4. Different steps are evaluated independently
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import type { StepGateRequest } from "@axonflow/sdk";

let passCount = 0;
let failCount = 0;

function assert(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
    passCount++;
  } else {
    console.log(`   FAIL: ${message}`);
    failCount++;
  }
}

const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "demo-org",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
});

async function main() {
  console.log("Execution Boundary Semantics - TypeScript (#1414)");
  console.log("=".repeat(50));
  console.log();
  console.log("This test verifies idempotent retry behavior for WCP step gates.");
  console.log();

  // Test 1: Create workflow
  console.log("Test 1: Create Workflow");
  console.log("-".repeat(30));

  const wf = await axonflow.createWorkflow({
    workflow_name: "retry-semantics-test",
    source: "external",
  });
  assert(wf.workflow_id !== "", `Workflow created: ${wf.workflow_id}`);
  console.log();

  // Test 2: First step gate (fresh)
  console.log("Test 2: First Step Gate (fresh evaluation)");
  console.log("-".repeat(30));

  const resp1 = await axonflow.stepGate(wf.workflow_id, "step-analyze", {
    step_name: "Analyze Data",
    step_type: "tool_call",
    step_input: { tool: "data_analyzer" },
  });
  assert(resp1.decision === "allow", `Decision is allow (got ${resp1.decision})`);
  assert(!resp1.cached, `First call is NOT cached (cached=${resp1.cached})`);
  assert(resp1.decision_source === "fresh", `Decision source is fresh (got ${resp1.decision_source})`);
  console.log();

  // Test 3: Same step gate (default idempotent - cached)
  console.log("Test 3: Same Step Gate Again (default idempotent)");
  console.log("-".repeat(30));

  const resp2 = await axonflow.stepGate(wf.workflow_id, "step-analyze", {
    step_name: "Analyze Data",
    step_type: "tool_call",
  });
  assert(resp2.decision === "allow", `Same decision allow (got ${resp2.decision})`);
  assert(resp2.cached, `Second call IS cached (cached=${resp2.cached})`);
  assert(resp2.decision_source === "cached", `Decision source is cached (got ${resp2.decision_source})`);
  console.log();

  // Test 4: Same step with retry_policy=reevaluate (fresh)
  console.log("Test 4: Same Step with retry_policy=reevaluate");
  console.log("-".repeat(30));

  const resp3 = await axonflow.stepGate(wf.workflow_id, "step-analyze", {
    step_name: "Analyze Data",
    step_type: "tool_call",
    retry_policy: "reevaluate",
  });
  assert(resp3.decision === "allow", `Decision is allow (got ${resp3.decision})`);
  assert(!resp3.cached, `Reevaluate is NOT cached (cached=${resp3.cached})`);
  assert(resp3.decision_source === "fresh", `Decision source is fresh (got ${resp3.decision_source})`);
  console.log();

  // Test 5: Different step (independent)
  console.log("Test 5: Different Step (independent evaluation)");
  console.log("-".repeat(30));

  const resp4 = await axonflow.stepGate(wf.workflow_id, "step-summarize", {
    step_name: "Summarize Results",
    step_type: "llm_call",
    model: "gpt-4",
    provider: "openai",
  });
  assert(!resp4.cached, `New step is NOT cached (cached=${resp4.cached})`);
  assert(resp4.decision_source === "fresh", `Decision source is fresh (got ${resp4.decision_source})`);
  console.log();

  // Test 6: Complete workflow
  console.log("Test 6: Complete Workflow");
  console.log("-".repeat(30));

  await axonflow.completeWorkflow(wf.workflow_id);
  assert(true, "Workflow completed");
  console.log();

  // Summary
  console.log("=".repeat(50));
  console.log(`Results: ${passCount} passed, ${failCount} failed`);
  if (failCount > 0) {
    console.log("FAILED");
    process.exit(1);
  }
  console.log("ALL PASSED");
}

main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
