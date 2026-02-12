/**
 * Workflow Fail - TypeScript Example
 *
 * Demonstrates and VALIDATES the FailWorkflow SDK method:
 * 1. Create a workflow and complete one step
 * 2. Call failWorkflow() with a reason
 * 3. Verify workflow status is "failed"
 * 4. Call failWorkflow() without a reason (optional)
 * 5. Verify a failed workflow cannot be resumed
 * 6. Verify getWorkflow reflects failure correctly
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import type {
  MarkStepCompletedRequest,
} from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

// Initialize AxonFlow client
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT || process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "workflow-fail-ts",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
});

async function main() {
  console.log("Workflow Fail - TypeScript (FailWorkflow Validation)");
  console.log("=".repeat(55));
  console.log();

  let workflowId = "";
  let noReasonWfId = "";

  try {
    // ========================================
    // Test 1: Create Workflow
    // ========================================
    console.log("Test 1: Create Workflow");
    console.log("   Creating 'fail-workflow-test' workflow...");

    const workflow = await axonflow.createWorkflow({
      workflow_name: "fail-workflow-test",
      source: "external",
      total_steps: 3,
      metadata: { test: "workflow-fail-ts" },
    });

    workflowId = workflow.workflow_id;
    assertCheck(!!workflow.workflow_id, "Workflow created with valid ID");
    assertCheck(workflow.workflow_id.startsWith("wf_"), "Workflow ID has 'wf_' prefix");
    console.log(`   Workflow ID: ${workflow.workflow_id}`);
    console.log();

    // ========================================
    // Test 2: Step Gate + Complete Step
    // ========================================
    console.log("Test 2: Step Gate + Complete Step");
    console.log("   Checking gate for step-1...");

    const gate = await axonflow.stepGate(workflow.workflow_id, "step-1", {
      step_name: "Data Processing",
      step_type: "llm_call",
      model: "gpt-4",
      provider: "openai",
      step_input: { prompt: "Process incoming data batch" },
    });

    assertCheck(
      gate.decision === "allow" || gate.decision === "block" || gate.decision === "require_approval",
      `Gate decision is valid (got: ${gate.decision})`
    );
    console.log(`   Decision: ${gate.decision}`);

    if (gate.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflow_id, "step-1", {
        output: { records_processed: 150 },
      } as MarkStepCompletedRequest);
      assertCheck(true, "Step 1 marked completed");
    }
    console.log();

    // ========================================
    // Test 3: FailWorkflow with Reason
    // ========================================
    console.log("Test 3: FailWorkflow with Reason");
    console.log("   Failing workflow with reason...");

    await axonflow.failWorkflow(workflow.workflow_id, "LLM provider timeout after 30s");
    assertCheck(true, "failWorkflow() with reason succeeded");
    console.log("   Reason: LLM provider timeout after 30s");
    console.log();

    // ========================================
    // Test 4: Verify Workflow Status is Failed
    // ========================================
    console.log("Test 4: Verify Workflow Status is Failed");

    const status = await axonflow.getWorkflow(workflow.workflow_id);
    assertCheck(status.workflow_name === "fail-workflow-test", "Workflow name matches");
    assertCheck(status.status === "failed", `Workflow status is 'failed' (got: ${status.status})`);
    console.log(`   Status: ${status.status}`);
    console.log(`   Workflow: ${status.workflow_name}`);
    console.log();

    // ========================================
    // Test 5: FailWorkflow without Reason
    // ========================================
    console.log("Test 5: FailWorkflow without Reason");
    console.log("   Creating second workflow...");

    const noReasonWf = await axonflow.createWorkflow({
      workflow_name: "fail-no-reason-test",
      source: "external",
      total_steps: 2,
      metadata: { test: "fail-no-reason" },
    });

    noReasonWfId = noReasonWf.workflow_id;
    console.log(`   Workflow ID: ${noReasonWf.workflow_id}`);

    await axonflow.failWorkflow(noReasonWf.workflow_id);
    assertCheck(true, "failWorkflow() without reason succeeded");

    const noReasonStatus = await axonflow.getWorkflow(noReasonWf.workflow_id);
    assertCheck(
      noReasonStatus.status === "failed",
      `Workflow status is 'failed' (got: ${noReasonStatus.status})`
    );
    console.log(`   Status: ${noReasonStatus.status}`);
    console.log();

    // ========================================
    // Test 6: Verify Failed Workflow Cannot Be Resumed
    // ========================================
    console.log("Test 6: Verify Failed Workflow Cannot Be Resumed");

    // Try step gate on failed workflow - should throw
    try {
      await axonflow.stepGate(workflow.workflow_id, "step-2", {
        step_name: "Should Not Execute",
        step_type: "tool_call",
        step_input: { tool: "noop" },
      });
      assertCheck(false, "StepGate on failed workflow should have thrown");
    } catch (resumeErr) {
      assertCheck(true, "StepGate on failed workflow throws error");
      const msg = resumeErr instanceof Error ? resumeErr.message : String(resumeErr);
      console.log(`   Expected error: ${msg}`);
    }

    // Try to complete the failed workflow - should throw
    try {
      await axonflow.completeWorkflow(workflow.workflow_id);
      assertCheck(false, "CompleteWorkflow on failed workflow should have thrown");
    } catch (completeErr) {
      assertCheck(true, "CompleteWorkflow on failed workflow throws error");
      const msg = completeErr instanceof Error ? completeErr.message : String(completeErr);
      console.log(`   Expected error: ${msg}`);
    }
    console.log();

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error("Error:", errorMessage);
    failures.push(`Unexpected error: ${errorMessage}`);
  } finally {
    // Cleanup
    console.log("Cleanup");
    console.log("-------");
    for (const wfId of [workflowId, noReasonWfId]) {
      if (wfId) {
        try {
          await axonflow.abortWorkflow(wfId, "test cleanup");
          console.log(`   Cleaned up workflow: ${wfId}`);
        } catch {
          console.log(`   Warning: Could not abort ${wfId} (may already be terminal)`);
        }
      }
    }
    console.log();
  }

  // ========================================
  // Summary
  // ========================================
  console.log("=".repeat(55));
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
    console.log();
    console.log("FailWorkflow operations validated:");
    console.log("  - createWorkflow()");
    console.log("  - stepGate() + markStepCompleted()");
    console.log("  - failWorkflow() with reason");
    console.log("  - failWorkflow() without reason");
    console.log("  - getWorkflow() verifies 'failed' status");
    console.log("  - Failed workflow cannot be resumed");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
