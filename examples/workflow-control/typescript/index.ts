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
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import type {
  CreateWorkflowRequest,
  StepGateRequest,
  MarkStepCompletedRequest,
  StepGateResponse,
} from "@axonflow/sdk";

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
      workflowName: "code-review-pipeline",
      source: "external",
      totalSteps: 3,
      metadata: { example: "workflow-control-ts" },
    } as CreateWorkflowRequest);

    console.log("   Workflow created!");
    console.log(`   Workflow ID: ${workflow.workflowId}`);
    console.log();

    // Step 2: Check gate for first step (Generate Code - LLM call)
    console.log("Step 2: Check Gate - Generate Code");
    console.log("   Checking if 'generate_code' step is allowed...");

    const gate1 = await axonflow.stepGate(workflow.workflowId, "step-1", {
      stepName: "Generate Code",
      stepType: "llm_call",
      model: "gpt-4",
      provider: "openai",
      stepInput: { prompt: "Write a Python function to sort a list" },
    } as StepGateRequest);

    console.log(`   Decision: ${gate1.decision}`);
    if (gate1.reason) {
      console.log(`   Reason: ${gate1.reason}`);
    }

    if (gate1.decision === "block") {
      console.log("   Workflow blocked by policy. Aborting...");
      await axonflow.abortWorkflow(workflow.workflowId, gate1.reason);
      return;
    }

    if (gate1.decision === "require_approval") {
      console.log(`   Approval URL: ${gate1.approvalUrl}`);
      console.log(
        "   (Enterprise feature - approval workflow would be triggered)"
      );
      // In production, you would wait for approval here
    }

    // Mark step 1 completed
    if (gate1.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflowId, "step-1", {
        output: { code: "def sort_list(items): return sorted(items)" },
      } as MarkStepCompletedRequest);
      console.log("   Step completed!");
    }
    console.log();

    // Step 3: Check gate for second step (Review Code - Tool call)
    console.log("Step 3: Check Gate - Review Code");
    console.log("   Checking if 'review_code' step is allowed...");

    const gate2 = await axonflow.stepGate(workflow.workflowId, "step-2", {
      stepName: "Review Code",
      stepType: "tool_call",
      stepInput: {
        tool: "code_reviewer",
        code: "def sort_list(items): return sorted(items)",
      },
    } as StepGateRequest);

    console.log(`   Decision: ${gate2.decision}`);
    if (gate2.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflowId, "step-2", {
        output: { review: "LGTM" },
      } as MarkStepCompletedRequest);
      console.log("   Step completed!");
    }
    console.log();

    // Step 4: Check gate for third step (Deploy - Connector call)
    console.log("Step 4: Check Gate - Deploy");
    console.log("   Checking if 'deploy' step is allowed...");

    const gate3 = await axonflow.stepGate(workflow.workflowId, "step-3", {
      stepName: "Deploy to Production",
      stepType: "connector_call",
      stepInput: { connector: "github", action: "create_pr" },
    } as StepGateRequest);

    console.log(`   Decision: ${gate3.decision}`);
    if (gate3.decision === "allow") {
      await axonflow.markStepCompleted(workflow.workflowId, "step-3", {
        output: { pr_url: "https://github.com/example/pr/123" },
      } as MarkStepCompletedRequest);
      console.log("   Step completed!");
    }
    console.log();

    // Step 5: Complete the workflow
    console.log("Step 5: Complete Workflow");
    await axonflow.completeWorkflow(workflow.workflowId);
    console.log("   Workflow completed!");
    console.log();

    // Step 6: Get final workflow status
    console.log("Step 6: Workflow Status");
    const status = await axonflow.getWorkflow(workflow.workflowId);
    console.log(`   Workflow: ${status.workflowName}`);
    console.log(`   Status: ${status.status}`);
    console.log(`   Steps: ${status.steps?.length || 0}`);
    console.log();

    console.log("=".repeat(40));
    console.log("Workflow Control Plane Example Complete!");
    console.log();
    console.log("Key concepts demonstrated:");
    console.log("  1. Create workflow (register with AxonFlow)");
    console.log("  2. Check step gates (policy evaluation)");
    console.log("  3. Mark steps completed (progress tracking)");
    console.log("  4. Complete workflow (lifecycle management)");
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    console.error("Error:", errorMessage);
    process.exit(1);
  }
}

main();
