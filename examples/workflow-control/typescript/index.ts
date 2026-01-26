/**
 * Workflow Control Plane - TypeScript Example
 *
 * "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
 *
 * This example demonstrates how to:
 * 1. Create a workflow
 * 2. Check step gates before each step
 * 3. Mark steps as completed
 * 4. Complete the workflow
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import type {
  CreateWorkflowRequest,
  StepGateRequest,
  MarkStepCompletedRequest,
  StepGateResponse,
} from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

// Initialize AxonFlow client
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "workflow-control-ts",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
});

async function main() {
  console.log("Workflow Control Plane - TypeScript");
  console.log("=".repeat(40));
  console.log();

  try {
    // Step 1: Create a workflow
    console.log("Step 1: Create Workflow");
    console.log("   Creating 'code-review-pipeline' workflow...");

    const workflow = await axonflow.createWorkflow({
      workflow_name: "code-review-pipeline",
      source: "external",
      total_steps: 3,
      metadata: { example: "workflow-control-ts" },
    });

    assertCheck(!!workflow.workflow_id, "Workflow created with valid ID");
    assertCheck(workflow.workflow_id.length > 0, "Workflow ID is non-empty");
    console.log(`   Workflow ID: ${workflow.workflow_id}`);
    console.log();

    // Step 2: Check gate for first step (Generate Code - LLM call)
    console.log("Step 2: Check Gate - Generate Code");
    console.log("   Checking if 'generate_code' step is allowed...");

    const gate1 = await axonflow.stepGate(workflow.workflow_id, "step-1", {
      step_name: "Generate Code",
      step_type: "llm_call",
      model: "gpt-4",
      provider: "openai",
      step_input: { prompt: "Write a Python function to sort a list" },
    });

    assertCheck(
      gate1.decision === "allow" || gate1.decision === "block" || gate1.decision === "require_approval",
      "Gate decision is valid (allow/block/require_approval)"
    );
    console.log(`   Decision: ${gate1.decision}`);
    if (gate1.reason) {
      console.log(`   Reason: ${gate1.reason}`);
    }

    if (gate1.decision === "block") {
      assertCheck(!!gate1.reason, "Block decision includes reason");
      console.log("   Workflow blocked by policy. Aborting...");
      await axonflow.abortWorkflow(workflow.workflow_id, gate1.reason);
      // Workflow was blocked - this is still a valid test outcome
      console.log();
      console.log("=".repeat(40));
      console.log("Workflow blocked by policy (valid test outcome)");
      process.exit(failures.length > 0 ? 1 : 0);
    }

    if (gate1.decision === "require_approval") {
      assertCheck(!!gate1.approval_url, "Approval decision includes approval URL");
      console.log(`   Approval URL: ${gate1.approval_url}`);
      console.log(
        "   (Enterprise feature - approval workflow would be triggered)"
      );
      // In production, you would wait for approval here
    }

    // Mark step 1 completed
    if (gate1.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflow_id, "step-1", {
        output: { code: "def sort_list(items): return sorted(items)" },
      } as MarkStepCompletedRequest);
      assertCheck(true, "Step 1 marked completed");
    }
    console.log();

    // Step 3: Check gate for second step (Review Code - Tool call)
    console.log("Step 3: Check Gate - Review Code");
    console.log("   Checking if 'review_code' step is allowed...");

    const gate2 = await axonflow.stepGate(workflow.workflow_id, "step-2", {
      step_name: "Review Code",
      step_type: "tool_call",
      step_input: {
        tool: "code_reviewer",
        code: "def sort_list(items): return sorted(items)",
      },
    });

    assertCheck(
      gate2.decision === "allow" || gate2.decision === "block" || gate2.decision === "require_approval",
      "Gate 2 decision is valid"
    );
    console.log(`   Decision: ${gate2.decision}`);
    if (gate2.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflow_id, "step-2", {
        output: { review: "LGTM" },
      } as MarkStepCompletedRequest);
      assertCheck(true, "Step 2 marked completed");
    }
    console.log();

    // Step 4: Check gate for third step (Deploy - Connector call)
    console.log("Step 4: Check Gate - Deploy");
    console.log("   Checking if 'deploy' step is allowed...");

    const gate3 = await axonflow.stepGate(workflow.workflow_id, "step-3", {
      step_name: "Deploy to Production",
      step_type: "connector_call",
      step_input: { connector: "github", action: "create_pr" },
    } as StepGateRequest);

    assertCheck(
      gate3.decision === "allow" || gate3.decision === "block" || gate3.decision === "require_approval",
      "Gate 3 decision is valid"
    );
    console.log(`   Decision: ${gate3.decision}`);
    if (gate3.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflow_id, "step-3", {
        output: { pr_url: "https://github.com/example/pr/123" },
      } as MarkStepCompletedRequest);
      assertCheck(true, "Step 3 marked completed");
    }
    console.log();

    // Step 5: Complete the workflow
    console.log("Step 5: Complete Workflow");
    await axonflow.completeWorkflow(workflow.workflow_id);
    assertCheck(true, "Workflow completed successfully");
    console.log();

    // Step 6: Get final workflow status
    console.log("Step 6: Workflow Status");
    const status = await axonflow.getWorkflow(workflow.workflow_id);
    assertCheck(status.workflow_name === "code-review-pipeline", "Workflow name matches");
    assertCheck(status.status === "completed" || status.status === "in_progress", "Workflow status is valid");
    console.log(`   Workflow: ${status.workflow_name}`);
    console.log(`   Status: ${status.status}`);
    console.log(`   Steps: ${status.steps?.length || 0}`);
    console.log();

    console.log("=".repeat(40));
    if (failures.length === 0) {
      console.log("ALL TESTS PASSED");
      console.log();
      console.log("Key concepts demonstrated:");
      console.log("  1. Create workflow (register with AxonFlow)");
      console.log("  2. Check step gates (policy evaluation)");
      console.log("  3. Mark steps completed (progress tracking)");
      console.log("  4. Complete workflow (lifecycle management)");
    } else {
      console.log(`${failures.length} TEST(S) FAILED:`);
      for (const f of failures) {
        console.log(`   - ${f}`);
      }
    }
    process.exit(failures.length > 0 ? 1 : 0);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    console.error("Error:", errorMessage);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
