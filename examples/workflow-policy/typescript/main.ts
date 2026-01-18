/**
 * Workflow Policy Enforcement - TypeScript Example
 *
 * Demonstrates:
 * 1. MAP policy enforcement with policyInfo in execution response
 * 2. WCP policy enforcement with policiesEvaluated/matched in step gate response
 * 3. Audit log verification to confirm operations are logged
 */

import { AxonFlow } from "@axonflow/sdk";

// Sleep helper function
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  console.log("==========================================");
  console.log("Workflow Policy Enforcement - TypeScript Example");
  console.log("==========================================");
  console.log();

  // Initialize client - use orchestrator endpoint for workflow APIs
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8081",
    clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "secret",
  });

  // Record start time for audit log query
  const startTime = new Date(Date.now() - 1000);

  // ==========================================
  // Part 1: WCP Policy Enforcement
  // ==========================================

  console.log("Part 1: WCP (Workflow Control Plane) Policy Enforcement");
  console.log("--------------------------------------------------------");
  console.log();

  // Create workflow
  console.log("1.1 Creating workflow...");
  const workflow = await client.createWorkflow({
    workflow_name: "policy-demo-typescript",
    source: "external",
    total_steps: 3,
    metadata: { example: "workflow-policy-typescript" },
  });
  console.log(`    Workflow ID: ${workflow.workflow_id}`);
  console.log();

  // Check step gate - demonstrates policiesEvaluated and policiesMatched
  console.log("1.2 Checking step gate (demonstrates policy info in response)...");
  const gate = await client.stepGate(workflow.workflow_id, "step-1", {
    step_name: "Analyze Data",
    step_type: "llm_call",
    model: "gpt-4",
    provider: "openai",
    step_input: { prompt: "Analyze customer sentiment" },
  });

  console.log(`    Decision: ${gate.decision}`);
  if (gate.reason) {
    console.log(`    Reason: ${gate.reason}`);
  }

  // Display policy evaluation details (Issue #1021)
  if (gate.policies_evaluated && gate.policies_evaluated.length > 0) {
    console.log("    Policies Evaluated:");
    for (const p of gate.policies_evaluated) {
      console.log(`      - ${p.policy_name} (${p.policy_id}): action=${p.action}`);
    }
  }
  if (gate.policies_matched && gate.policies_matched.length > 0) {
    console.log("    Policies Matched:");
    for (const p of gate.policies_matched) {
      console.log(`      - ${p.policy_name}: ${p.action} (reason: ${p.reason})`);
    }
  }
  console.log();

  // Handle decision
  if (gate.decision === "block") {
    console.log("    Step BLOCKED by policy!");
    console.log("    Aborting workflow...");
    await client.abortWorkflow(workflow.workflow_id, gate.reason);
    return;
  }

  if (gate.decision === "require_approval") {
    console.log(`    Step requires approval: ${gate.approval_url}`);
    // In production, wait for approval
  }

  // Mark step completed
  if (gate.decision === "allow") {
    await client.markStepCompleted(workflow.workflow_id, "step-1");
    console.log("    Step completed!");
  }
  console.log();

  // Test with potentially sensitive content
  console.log("1.3 Testing with database query (potential SQLi check)...");
  const gate2 = await client.stepGate(workflow.workflow_id, "step-2", {
    step_name: "Execute Query",
    step_type: "tool_call",
    step_input: { query: "SELECT name, email FROM customers LIMIT 10" },
  });

  console.log(`    Decision: ${gate2.decision}`);
  if (gate2.policies_evaluated) {
    console.log(`    Policies checked: ${gate2.policies_evaluated.length}`);
  }
  if (gate2.policies_matched && gate2.policies_matched.length > 0) {
    console.log(`    Policies matched: ${gate2.policies_matched.length}`);
    for (const p of gate2.policies_matched) {
      console.log(`      - ${p.policy_name}: ${p.reason}`);
    }
  }
  console.log();

  // Complete workflow
  console.log("1.4 Completing workflow...");
  await client.completeWorkflow(workflow.workflow_id);
  console.log("    Workflow completed!");
  console.log();

  // ==========================================
  // Part 2: Audit Log Verification
  // ==========================================

  console.log("Part 2: Audit Log Verification");
  console.log("------------------------------");
  console.log();

  // Delay to ensure audit logs are flushed (batch writer flushes every 5-10 seconds)
  console.log("    Waiting for audit log batch flush...");
  await sleep(6000);

  // Search for workflow audit logs
  console.log("2.1 Searching for workflow audit logs...");
  try {
    const auditResponse = await client.searchAuditLogs({
      startTime,
      limit: 50,
    });

    // Count workflow-related entries
    const workflowLogs = new Map<string, number>();
    for (const entry of auditResponse.entries) {
      if (entry.requestId === workflow.workflow_id) {
        const count = workflowLogs.get(entry.requestType) || 0;
        workflowLogs.set(entry.requestType, count + 1);
      }
    }

    if (workflowLogs.size > 0) {
      const totalCount = Array.from(workflowLogs.values()).reduce((a, b) => a + b, 0);
      console.log(`    ✅ Found ${totalCount} audit log entries for workflow ${workflow.workflow_id}:`);
      for (const [reqType, count] of workflowLogs) {
        console.log(`       - ${reqType}: ${count}`);
      }
    } else {
      console.log("    ⚠️  No audit logs found for this workflow");
      console.log("       (Audit logs may take a moment to flush)");
    }
    console.log();

    // Verify expected audit entries
    console.log("2.2 Verifying expected audit entries...");
    const expectedTypes = ["workflow_created", "workflow_step_gate", "workflow_completed"];
    let allFound = true;
    for (const expected of expectedTypes) {
      const found = auditResponse.entries.some(
        entry => entry.requestId === workflow.workflow_id && entry.requestType === expected
      );
      if (found) {
        console.log(`    ✅ ${expected}: FOUND`);
      } else {
        console.log(`    ❌ ${expected}: NOT FOUND`);
        allFound = false;
      }
    }
    console.log();

    if (allFound) {
      console.log("    ✅ All expected audit log entries verified!");
    } else {
      console.log("    ⚠️  Some audit log entries were not found");
    }
    console.log();
  } catch (e) {
    console.log(`    ERROR searching audit logs: ${e}`);
    console.log();
  }

  // ==========================================
  // Summary
  // ==========================================

  console.log("==========================================");
  console.log("Summary");
  console.log("==========================================");
  console.log();
  console.log("WCP Policy Enforcement (Issue #1021):");
  console.log("  - StepGateResponse.policies_evaluated: all checked policies");
  console.log("  - StepGateResponse.policies_matched: policies that triggered decision");
  console.log("  - PolicyMatch includes: policy_id, policy_name, action, reason");
  console.log();
  console.log("Audit Logging (Issue #1019):");
  console.log("  - workflow_created: logged when workflow is registered");
  console.log("  - workflow_step_gate: logged for each step gate check");
  console.log("  - workflow_completed: logged when workflow completes");
  console.log("  - workflow_aborted: logged when workflow is aborted");
  console.log();
  console.log("MAP Policy Enforcement (Issue #1020):");
  console.log("  - PlanExecutionResponse.policy_info: policy evaluation result");
  console.log("  - Includes: allowed, applied_policies, risk_score");
  console.log("  - Returns 403 Forbidden if policies block execution");
  console.log();
}

main().catch(console.error);
