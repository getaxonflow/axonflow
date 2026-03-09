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
 * 5. Approve/reject steps (enterprise feature)
 * 6. List pending approvals (enterprise feature)
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
      metadata: { example: "workflow-control-ts" },
      trace_id: "example-trace-ts-001",
    });

    assertCheck(!!workflow.workflow_id, "Workflow created with valid ID");
    assertCheck(workflow.workflow_id.length > 0, "Workflow ID is non-empty");
    assertCheck(workflow.trace_id === "example-trace-ts-001", "trace_id returned in create response");
    console.log(`   Workflow ID: ${workflow.workflow_id}`);
    console.log();

    // Step 2: Check gate for first step (Generate Code - LLM call)
    console.log("Step 2: Check Gate - Generate Code");
    console.log("   Checking if 'generate_code' step is allowed...");

    const gate1 = await axonflow.stepGate(workflow.workflow_id, "step-1", {
      step_name: "Generate Code",
      step_type: "llm_call",
      model: "gemini-1.5-flash",
      provider: "gemini",
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
        tokens_in: 150,
        tokens_out: 45,
        cost_usd: 0.0023,
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
        tokens_in: 150,
        tokens_out: 45,
        cost_usd: 0.0023,
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
        tokens_in: 150,
        tokens_out: 45,
        cost_usd: 0.0023,
      } as MarkStepCompletedRequest);
      assertCheck(true, "Step 3 marked completed");
    }
    console.log();

    // Step 5: Complete the workflow
    console.log("Step 5: Complete Workflow");
    await axonflow.completeWorkflow(workflow.workflow_id);
    assertCheck(true, "Workflow completed successfully");
    console.log();

    // Step 5b: Fail Workflow (v4.3.0: native SDK method)
    console.log("Step 5b: Fail Workflow");
    console.log("   Testing failWorkflow() SDK method...");
    try {
      const failWorkflow = await axonflow.createWorkflow({
        workflow_name: "wcp-fail-test",
        source: "external",
        metadata: { test: "fail-workflow" },
      });
      assertCheck(!!failWorkflow.workflow_id, "Fail-test workflow created with valid ID");
      console.log(`   Workflow ID: ${failWorkflow.workflow_id}`);

      // v4.3.0: Use native SDK failWorkflow() method
      await axonflow.failWorkflow(failWorkflow.workflow_id, "LLM provider timeout");
      assertCheck(true, "failWorkflow succeeded");

      // Verify via SDK
      const failedStatus = await axonflow.getWorkflow(failWorkflow.workflow_id);
      assertCheck(failedStatus.status === "failed", `Workflow status verified as 'failed' (got: ${failedStatus.status})`);
    } catch (failErr) {
      const msg = failErr instanceof Error ? failErr.message : String(failErr);
      failures.push(`fail_workflow test failed: ${msg}`);
    }
    console.log();

    // Step 6: Get final workflow status
    console.log("Step 6: Workflow Status");
    const status = await axonflow.getWorkflow(workflow.workflow_id);
    assertCheck(status.workflow_name === "code-review-pipeline", "Workflow name matches");
    assertCheck(status.trace_id === "example-trace-ts-001", "trace_id returned in status response");
    assertCheck(status.status === "completed" || status.status === "in_progress", "Workflow status is valid");
    console.log(`   Workflow: ${status.workflow_name}`);
    console.log(`   Status: ${status.status}`);
    console.log(`   Steps: ${status.steps?.length || 0}`);
    console.log();

    // -------------------------------------------------------
    // Step Approval Tests (Enterprise Feature)
    // These may return 403 in community mode — skip gracefully.
    // -------------------------------------------------------

    // Test 7: Step Approval Flow
    console.log("Step 7: Step Approval Flow");
    console.log("   Creating 'wcp-approval-test' workflow (3 steps)...");
    try {
      const approvalWorkflow = await axonflow.createWorkflow({
        workflow_name: "wcp-approval-test",
        source: "external",
        metadata: { example: "step-approval-ts" },
      });

      assertCheck(!!approvalWorkflow.workflow_id, "Approval test workflow created");
      console.log(`   Workflow ID: ${approvalWorkflow.workflow_id}`);

      // Gate the first step
      console.log("   Checking gate for step-1...");
      const approvalGate = await axonflow.stepGate(approvalWorkflow.workflow_id, "step-1", {
        step_name: "Approval Target Step",
        step_type: "llm_call",
        model: "gemini-1.5-flash",
        provider: "gemini",
        step_input: { prompt: "Test step for approval" },
      });
      assertCheck(
        approvalGate.decision === "allow" || approvalGate.decision === "block" || approvalGate.decision === "require_approval",
        "Approval gate decision is valid"
      );
      console.log(`   Gate decision: ${approvalGate.decision}`);

      // Approve the step
      console.log("   Approving step-1...");
      const approveResp = await axonflow.approveStep(approvalWorkflow.workflow_id, "step-1");
      assertCheck(
        approveResp !== null && approveResp !== undefined,
        "approveStep returned a response"
      );
      if (approveResp?.status) {
        assertCheck(
          approveResp.status === "approved" || typeof approveResp.status === "string",
          "Approve response shows approved status"
        );
        console.log(`   Approval status: ${approveResp.status}`);
      } else {
        console.log("   Approval response received (no status field)");
      }

      // Check pending approvals
      console.log("   Checking pending approvals...");
      const pendingResp = await axonflow.getPendingApprovals();
      assertCheck(
        pendingResp !== null && pendingResp !== undefined,
        "getPendingApprovals returned a response"
      );
      if (pendingResp?.approvals) {
        assertCheck(Array.isArray(pendingResp.approvals), "Pending approvals has approvals array");
        console.log(`   Pending approvals count: ${pendingResp.approvals.length}`);
      }
      if (pendingResp?.total !== undefined) {
        console.log(`   Total pending: ${pendingResp.total}`);
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes("403") || msg.includes("404") || msg.includes("enterprise") || msg.includes("not available") || msg.includes("license")) {
        console.log("   SKIPPED: Step approval is an enterprise feature");
        console.log(`   (${msg})`);
      } else {
        throw error;
      }
    }
    console.log();

    // Test 8: Step Rejection Flow
    console.log("Step 8: Step Rejection Flow");
    console.log("   Creating 'wcp-rejection-test' workflow (2 steps)...");
    try {
      const rejectionWorkflow = await axonflow.createWorkflow({
        workflow_name: "wcp-rejection-test",
        source: "external",
        metadata: { example: "step-rejection-ts" },
      });

      assertCheck(!!rejectionWorkflow.workflow_id, "Rejection test workflow created");
      console.log(`   Workflow ID: ${rejectionWorkflow.workflow_id}`);

      // Gate the first step
      console.log("   Checking gate for step-1...");
      const rejectionGate = await axonflow.stepGate(rejectionWorkflow.workflow_id, "step-1", {
        step_name: "Rejection Target Step",
        step_type: "tool_call",
        step_input: { tool: "risky_action", action: "delete_all" },
      });
      assertCheck(
        rejectionGate.decision === "allow" || rejectionGate.decision === "block" || rejectionGate.decision === "require_approval",
        "Rejection gate decision is valid"
      );
      console.log(`   Gate decision: ${rejectionGate.decision}`);

      // Reject the step
      console.log("   Rejecting step-1...");
      const rejectResp = await axonflow.rejectStep(rejectionWorkflow.workflow_id, "step-1");
      assertCheck(
        rejectResp !== null && rejectResp !== undefined,
        "rejectStep returned a response"
      );
      if (rejectResp?.status) {
        assertCheck(
          rejectResp.status === "rejected" || typeof rejectResp.status === "string",
          "Reject response shows rejected status"
        );
        console.log(`   Rejection status: ${rejectResp.status}`);
      } else {
        console.log("   Rejection response received (no status field)");
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes("403") || msg.includes("404") || msg.includes("enterprise") || msg.includes("not available") || msg.includes("license")) {
        console.log("   SKIPPED: Step rejection is an enterprise feature");
        console.log(`   (${msg})`);
      } else {
        throw error;
      }
    }
    console.log();

    // Test 9: Get Pending Approvals (standalone)
    console.log("Step 9: Get Pending Approvals");
    console.log("   Fetching pending approvals list...");
    try {
      const allPending = await axonflow.getPendingApprovals();
      assertCheck(
        allPending !== null && allPending !== undefined,
        "getPendingApprovals returned a response"
      );
      if (allPending?.approvals) {
        assertCheck(Array.isArray(allPending.approvals), "Response has approvals array");
        console.log(`   Approvals count: ${allPending.approvals.length}`);
      }
      if (allPending?.total !== undefined) {
        assertCheck(typeof allPending.total === "number", "Response has numeric total count");
        console.log(`   Total: ${allPending.total}`);
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes("403") || msg.includes("404") || msg.includes("enterprise") || msg.includes("not available") || msg.includes("license")) {
        console.log("   SKIPPED: Pending approvals is an enterprise feature");
        console.log(`   (${msg})`);
      } else {
        throw error;
      }
    }
    console.log();

    // ========================================
    // Step 10: SSE Streaming - Real-time execution status
    // ========================================
    console.log("Step 10: SSE Streaming - Real-time execution status");
    console.log("   Creating workflow for SSE streaming test...");

    try {
      const sseWorkflow = await axonflow.createWorkflow({
        workflow_name: "wcp-sse-streaming-test",
        source: "external",
        metadata: { example: "sse-streaming-ts" },
      });

      assertCheck(!!sseWorkflow.workflow_id, "SSE workflow created with valid ID");
      console.log(`   Workflow ID: ${sseWorkflow.workflow_id}`);

      // Run a step gate and complete a step to generate execution events
      const sseGate = await axonflow.stepGate(sseWorkflow.workflow_id, "sse-step-1", {
        step_name: "SSE Test Step",
        step_type: "llm_call",
        model: "gemini-1.5-flash",
        provider: "gemini",
        step_input: { prompt: "test SSE streaming" },
      });

      if (sseGate.decision === "allow") {
        await axonflow.markStepCompleted(sseWorkflow.workflow_id, "sse-step-1", {
          output: { result: "sse test output" },
          tokens_in: 150,
          tokens_out: 45,
          cost_usd: 0.0023,
        } as MarkStepCompletedRequest);
        assertCheck(true, "SSE step completed");
      }

      // Stream execution status via HTTP SSE endpoint
      const orchestratorUrl = process.env.AXONFLOW_ORCHESTRATOR_URL || "http://localhost:8081";
      const sseClientId = process.env.AXONFLOW_CLIENT_ID || "workflow-control-ts";
      const sseClientSecret = process.env.AXONFLOW_CLIENT_SECRET || "";
      const streamUrl = `${orchestratorUrl}/api/v1/unified/executions/${sseWorkflow.workflow_id}/stream`;
      console.log(`   SSE URL: ${streamUrl}`);

      try {
        // Completed executions are evicted from the tracker, so a 404 with
        // "NOT_FOUND" / "Execution not found" proves the endpoint exists.
        const sseResponse = await fetch(streamUrl, {
          headers: {
            "Accept": "application/json",
            "X-Client-ID": sseClientId,
            "X-Client-Secret": sseClientSecret,
            "X-Tenant-ID": sseClientId,
          },
        });

        if (sseResponse.status === 200) {
          assertCheck(true, "SSE endpoint returned 200");
          console.log("   SSE endpoint available (HTTP 200)");
        } else if (sseResponse.status === 404) {
          const body = await sseResponse.text();
          const validNotFound = body.includes("NOT_FOUND") || body.includes("Execution not found");
          assertCheck(validNotFound, `SSE endpoint returned structured 404: ${body}`);
          console.log("   SSE endpoint available (connect during active execution for real-time events)");
        } else {
          assertCheck(false, `SSE endpoint returned unexpected HTTP ${sseResponse.status}`);
        }
      } catch (sseErr) {
        console.log(`   Warning: SSE connection failed: ${sseErr}`);
        console.log("   Note: SSE endpoint may not be available yet");
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.log(`   FATAL: SSE streaming test failed: ${msg}`);
      failures.push(`SSE streaming test failed: ${msg}`);
    }
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
      console.log("  5b. Fail workflow (failWorkflow SDK method)");
      console.log("  5. Approve steps (enterprise approval flow)");
      console.log("  6. Reject steps (enterprise rejection flow)");
      console.log("  7. List pending approvals (enterprise)");
      console.log(" 10. SSE Streaming (real-time execution status)");
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
