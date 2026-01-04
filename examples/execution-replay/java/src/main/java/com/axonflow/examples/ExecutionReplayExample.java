package com.axonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.executionreplay.ExecutionReplayTypes.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;
import java.util.Map;

/**
 * AxonFlow Execution Replay API - Java SDK Example
 *
 * This example demonstrates how to use the AxonFlow Java SDK to:
 * 1. List all workflow executions
 * 2. Get detailed execution information
 * 3. View execution timeline
 * 4. Export execution for compliance
 *
 * The Execution Replay feature captures every step of workflow execution
 * for debugging, auditing, and compliance purposes.
 */
public class ExecutionReplayExample {

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        System.out.println("AxonFlow Execution Replay API - Java SDK");
        System.out.println("========================================");
        System.out.println();

        // Initialize the AxonFlow client
        String agentUrl = System.getenv().getOrDefault("AXONFLOW_AGENT_URL", "http://localhost:8080");
        String orchestratorUrl = System.getenv().getOrDefault("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081");

        AxonFlowConfig config = AxonFlowConfig.builder()
                .agentUrl(agentUrl)
                .orchestratorUrl(orchestratorUrl)
                .debug(true)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            // 1. List all executions
            System.out.println("Step 1: List Executions");
            System.out.println("------------------------");

            ListExecutionsResponse listResult = client.listExecutions(
                    ListExecutionsOptions.builder().setLimit(10)
            );

            System.out.println("Total executions: " + listResult.getTotal());
            List<ExecutionSummary> executions = listResult.getExecutions();

            if (executions != null && !executions.isEmpty()) {
                System.out.println("Recent executions:");
                for (ExecutionSummary exec : executions) {
                    System.out.printf("  - %s: %s (%d/%d steps, status=%s)%n",
                            exec.getRequestId(),
                            exec.getWorkflowName() != null ? exec.getWorkflowName() : "N/A",
                            exec.getCompletedSteps(),
                            exec.getTotalSteps(),
                            exec.getStatus());
                }
            } else {
                System.out.println("No executions found. Run a workflow to generate execution data.");
            }
            System.out.println();

            // 2. Get specific execution (if available)
            if (executions != null && !executions.isEmpty()) {
                String executionId = executions.get(0).getRequestId();

                System.out.println("Step 2: Get Execution Details");
                System.out.println("------------------------------");

                try {
                    ExecutionDetail execDetail = client.getExecution(executionId);
                    ExecutionSummary summary = execDetail.getSummary();

                    System.out.println("Execution: " + summary.getRequestId());
                    System.out.println("  Workflow: " + (summary.getWorkflowName() != null ? summary.getWorkflowName() : "N/A"));
                    System.out.println("  Status: " + summary.getStatus());
                    System.out.printf("  Steps: %d/%d completed%n",
                            summary.getCompletedSteps(),
                            summary.getTotalSteps());
                    System.out.println("  Total Tokens: " + summary.getTotalTokens());
                    System.out.printf("  Total Cost: $%.6f%n", summary.getTotalCostUsd());
                    System.out.println("  Steps:");

                    for (ExecutionSnapshot step : execDetail.getSteps()) {
                        String duration = step.getDurationMs() != null
                                ? step.getDurationMs() + "ms"
                                : "in progress";
                        System.out.printf("    [%d] %s: %s (%s)%n",
                                step.getStepIndex(),
                                step.getStepName(),
                                step.getStatus(),
                                duration);
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
                System.out.println();

                // 3. Get execution timeline
                System.out.println("Step 3: Get Execution Timeline");
                System.out.println("-------------------------------");

                try {
                    List<TimelineEntry> timeline = client.getExecutionTimeline(executionId);

                    System.out.println("Timeline:");
                    for (TimelineEntry entry : timeline) {
                        String errorFlag = entry.hasError() ? " [ERROR]" : "";
                        String approvalFlag = entry.hasApproval() ? " [APPROVAL]" : "";
                        System.out.printf("  [%d] %s: %s%s%s%n",
                                entry.getStepIndex(),
                                entry.getStepName(),
                                entry.getStatus(),
                                errorFlag,
                                approvalFlag);
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
                System.out.println();

                // 4. Export execution
                System.out.println("Step 4: Export Execution");
                System.out.println("-------------------------");

                try {
                    Map<String, Object> exportData = client.exportExecution(executionId,
                            ExecutionExportOptions.builder()
                                    .setIncludeInput(true)
                                    .setIncludeOutput(true));

                    // Pretty print the export (truncated)
                    String prettyExport = gson.toJson(exportData);
                    if (prettyExport.length() > 500) {
                        prettyExport = prettyExport.substring(0, 500) + "\n  ... (truncated)";
                    }
                    System.out.println("Export (truncated):\n" + prettyExport);
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
                System.out.println();
            }

            System.out.println("========================================");
            System.out.println("Execution Replay Demo Complete!");
            System.out.println();
            System.out.println("SDK Methods Used:");
            System.out.println("  client.listExecutions()         - List executions");
            System.out.println("  client.getExecution(id)         - Get execution details");
            System.out.println("  client.getExecutionSteps(id)    - Get execution steps");
            System.out.println("  client.getExecutionTimeline(id) - Get execution timeline");
            System.out.println("  client.exportExecution(id)      - Export execution");
            System.out.println("  client.deleteExecution(id)      - Delete execution");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
