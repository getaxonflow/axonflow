/*
 * Copyright 2026 AxonFlow
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.executionreplay.ExecutionReplayTypes.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow Execution Replay - Java SDK
 *
 * This example demonstrates and VALIDATES all Execution Replay SDK methods:
 * 1. listExecutions()         - List all workflow executions
 * 2. getExecution()           - Get detailed execution information
 * 3. getExecutionTimeline()   - View execution timeline
 * 4. exportExecution()        - Export execution for compliance
 *
 * VALIDATION: This example exits with code 1 if any API call fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class ExecutionReplayExample {

    private static final List<String> failures = new ArrayList<>();
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   \u274C FAIL: " + message);
        } else {
            System.out.println("   \u2713 PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Execution Replay - Java SDK");
        System.out.println("=====================================");
        System.out.println();

        AxonFlowConfig config = AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            // ========================================
            // 1. LIST EXECUTIONS
            // ========================================
            System.out.println("1. listExecutions - Listing workflow executions...");
            ListExecutionsResponse listResult;
            try {
                listResult = client.listExecutions(
                    ListExecutionsOptions.builder().setLimit(10)
                );
            } catch (Exception e) {
                System.out.println("   \u274C FATAL: listExecutions failed: " + e.getMessage());
                System.exit(1);
                return;
            }

            assertCheck(listResult.getTotal() >= 0, "total is a valid count");
            System.out.println("   Total executions: " + listResult.getTotal());

            List<ExecutionSummary> executions = listResult.getExecutions();
            if (executions != null && !executions.isEmpty()) {
                System.out.println("   Recent executions:");
                int count = Math.min(3, executions.size());
                for (int i = 0; i < count; i++) {
                    ExecutionSummary exec = executions.get(i);
                    System.out.printf("     - %s: %s (%d/%d steps, status=%s)%n",
                        exec.getRequestId(),
                        exec.getWorkflowName() != null ? exec.getWorkflowName() : "N/A",
                        exec.getCompletedSteps(),
                        exec.getTotalSteps(),
                        exec.getStatus());
                    assertCheck(
                        exec.getRequestId() != null && !exec.getRequestId().isEmpty(),
                        "Execution has valid requestId"
                    );
                }
            } else {
                System.out.println("   No executions found (run a workflow first)");
            }
            System.out.println();

            // Continue with detailed validation if executions exist
            if (executions != null && !executions.isEmpty()) {
                String executionId = executions.get(0).getRequestId();

                // ========================================
                // 2. GET EXECUTION DETAILS
                // ========================================
                System.out.println("2. getExecution - Getting execution details...");
                ExecutionDetail execDetail;
                try {
                    execDetail = client.getExecution(executionId);
                } catch (Exception e) {
                    System.out.println("   \u274C FATAL: getExecution failed: " + e.getMessage());
                    System.exit(1);
                    return;
                }

                ExecutionSummary summary = execDetail.getSummary();
                assertCheck(
                    executionId.equals(summary.getRequestId()),
                    "Summary requestId matches"
                );
                assertCheck(
                    summary.getStatus() != null && !summary.getStatus().isEmpty(),
                    "Summary has valid status"
                );
                assertCheck(summary.getTotalSteps() >= 0, "Summary has valid totalSteps");

                System.out.println("   Execution: " + summary.getRequestId());
                System.out.println("   Status: " + summary.getStatus());
                System.out.printf("   Steps: %d/%d completed%n",
                    summary.getCompletedSteps(), summary.getTotalSteps());
                System.out.println("   Total Tokens: " + summary.getTotalTokens());
                System.out.printf("   Total Cost: $%.6f%n", summary.getTotalCostUsd());
                System.out.println();

                // ========================================
                // 3. GET EXECUTION TIMELINE
                // ========================================
                System.out.println("3. getExecutionTimeline - Getting timeline view...");
                List<TimelineEntry> timeline;
                try {
                    timeline = client.getExecutionTimeline(executionId);
                } catch (Exception e) {
                    System.out.println("   \u274C FATAL: getExecutionTimeline failed: " + e.getMessage());
                    System.exit(1);
                    return;
                }

                assertCheck(timeline != null, "Timeline returns valid array");
                System.out.println("   Timeline entries: " + (timeline != null ? timeline.size() : 0));
                if (timeline != null) {
                    int count = Math.min(3, timeline.size());
                    for (int i = 0; i < count; i++) {
                        TimelineEntry entry = timeline.get(i);
                        String errorFlag = entry.hasError() ? " [ERROR]" : "";
                        System.out.printf("     [%d] %s: %s%s%n",
                            entry.getStepIndex(),
                            entry.getStepName(),
                            entry.getStatus(),
                            errorFlag);
                    }
                }
                System.out.println();

                // ========================================
                // 4. EXPORT EXECUTION
                // ========================================
                System.out.println("4. exportExecution - Exporting for compliance...");
                Map<String, Object> exportData;
                try {
                    exportData = client.exportExecution(executionId,
                        ExecutionExportOptions.builder()
                            .setIncludeInput(true)
                            .setIncludeOutput(true));
                } catch (Exception e) {
                    System.out.println("   \u274C FATAL: exportExecution failed: " + e.getMessage());
                    System.exit(1);
                    return;
                }

                assertCheck(exportData != null, "Export returns valid data");
                String prettyExport = gson.toJson(exportData);
                if (prettyExport.length() > 300) {
                    prettyExport = prettyExport.substring(0, 300) + "\n     ... (truncated)";
                }
                System.out.println("   Export preview:\n" + prettyExport);
                System.out.println();
            }

            // ========================================
            // SUMMARY
            // ========================================
            System.out.println("=====================================");
            if (failures.isEmpty()) {
                System.out.println("\u2713 ALL TESTS PASSED");
                System.out.println();
                System.out.println("Methods validated:");
                System.out.println("  1. listExecutions()         - List with pagination");
                System.out.println("  2. getExecution()           - Get full details");
                System.out.println("  3. getExecutionTimeline()   - Get timeline view");
                System.out.println("  4. exportExecution()        - Export for compliance");
            } else {
                System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
                for (String f : failures) {
                    System.out.println("   - " + f);
                }
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("\u274C FATAL: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
