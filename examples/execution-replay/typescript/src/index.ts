/**
 * AxonFlow Execution Replay API - TypeScript SDK Example
 *
 * This example demonstrates how to use the AxonFlow TypeScript SDK to:
 * 1. List all workflow executions
 * 2. Get detailed execution information
 * 3. View execution timeline
 * 4. Export execution for compliance
 *
 * The Execution Replay feature captures every step of workflow execution
 * for debugging, auditing, and compliance purposes.
 */

import { AxonFlow } from "@axonflow/sdk";

async function main(): Promise<void> {
  console.log("AxonFlow Execution Replay API - TypeScript SDK");
  console.log("========================================");
  console.log();

  // Initialize the AxonFlow client
  const agentUrl = process.env.AXONFLOW_AGENT_URL || "http://localhost:8080";
  const orchestratorUrl = process.env.AXONFLOW_ORCHESTRATOR_URL || "http://localhost:8081";

  const client = new AxonFlow({
    endpoint: agentUrl,
    orchestratorEndpoint: orchestratorUrl,
    debug: true,
  });

  try {
    // 1. List all executions
    console.log("Step 1: List Executions");
    console.log("------------------------");

    const listResult = await client.listExecutions({ limit: 10 });

    console.log(`Total executions: ${listResult.total}`);
    if (listResult.executions.length > 0) {
      console.log("Recent executions:");
      for (const exec of listResult.executions) {
        console.log(
          `  - ${exec.requestId}: ${exec.workflowName || "N/A"} ` +
            `(${exec.completedSteps}/${exec.totalSteps} steps, status=${exec.status})`
        );
      }
    } else {
      console.log("No executions found. Run a workflow to generate execution data.");
    }
    console.log();

    // 2. Get specific execution (if available)
    if (listResult.executions.length > 0) {
      const executionId = listResult.executions[0].requestId;

      console.log("Step 2: Get Execution Details");
      console.log("------------------------------");

      const execDetail = await client.getExecution(executionId);

      console.log(`Execution: ${execDetail.summary.requestId}`);
      console.log(`  Workflow: ${execDetail.summary.workflowName || "N/A"}`);
      console.log(`  Status: ${execDetail.summary.status}`);
      console.log(
        `  Steps: ${execDetail.summary.completedSteps}/${execDetail.summary.totalSteps} completed`
      );
      console.log(`  Total Tokens: ${execDetail.summary.totalTokens}`);
      console.log(`  Total Cost: $${execDetail.summary.totalCostUsd.toFixed(6)}`);
      console.log("  Steps:");
      for (const step of execDetail.steps) {
        const duration = step.durationMs ? `${step.durationMs}ms` : "in progress";
        console.log(`    [${step.stepIndex}] ${step.stepName}: ${step.status} (${duration})`);
      }
      console.log();

      // 3. Get execution timeline
      console.log("Step 3: Get Execution Timeline");
      console.log("-------------------------------");

      const timeline = await client.getExecutionTimeline(executionId);

      console.log("Timeline:");
      for (const entry of timeline) {
        const errorFlag = entry.hasError ? " [ERROR]" : "";
        const approvalFlag = entry.hasApproval ? " [APPROVAL]" : "";
        console.log(
          `  [${entry.stepIndex}] ${entry.stepName}: ${entry.status}${errorFlag}${approvalFlag}`
        );
      }
      console.log();

      // 4. Export execution
      console.log("Step 4: Export Execution");
      console.log("-------------------------");

      const exportData = await client.exportExecution(executionId, {
        includeInput: true,
        includeOutput: true,
      });

      // Pretty print the export (truncated)
      let prettyExport = JSON.stringify(exportData, null, 2);
      if (prettyExport.length > 500) {
        prettyExport = prettyExport.substring(0, 500) + "\n  ... (truncated)";
      }
      console.log(`Export (truncated):\n${prettyExport}`);
      console.log();
    }
  } finally {
    // Client cleanup (if needed in future versions)
  }

  console.log("========================================");
  console.log("Execution Replay Demo Complete!");
  console.log();
  console.log("SDK Methods Used:");
  console.log("  client.listExecutions()          - List executions");
  console.log("  client.getExecution(id)          - Get execution details");
  console.log("  client.getExecutionSteps(id)     - Get execution steps");
  console.log("  client.getExecutionTimeline(id)  - Get execution timeline");
  console.log("  client.exportExecution(id)       - Export execution");
  console.log("  client.deleteExecution(id)       - Delete execution");
}

main().catch(console.error);
