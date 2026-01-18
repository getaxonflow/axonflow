package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.AuditLogEntry;
import com.getaxonflow.sdk.types.AuditSearchRequest;
import com.getaxonflow.sdk.types.AuditSearchResponse;
import com.getaxonflow.sdk.types.workflow.PolicyMatch;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Workflow Policy Enforcement - Java Example
 *
 * Demonstrates:
 * 1. MAP policy enforcement with policyInfo in execution response
 * 2. WCP policy enforcement with policiesEvaluated/matched in step gate response
 * 3. Audit log verification to confirm operations are logged
 */
public class WorkflowPolicyExample {

    public static void main(String[] args) {
        System.out.println("==========================================");
        System.out.println("Workflow Policy Enforcement - Java Example");
        System.out.println("==========================================");
        System.out.println();

        // Initialize client - use orchestrator endpoint for workflow APIs
        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8081"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "secret"))
                .build();

        AxonFlow client = AxonFlow.create(config);

        // Record start time for audit log query
        Instant startTime = Instant.now().minusSeconds(1);

        try {
            // ==========================================
            // Part 1: WCP Policy Enforcement
            // ==========================================

            System.out.println("Part 1: WCP (Workflow Control Plane) Policy Enforcement");
            System.out.println("--------------------------------------------------------");
            System.out.println();

            // Create workflow
            System.out.println("1.1 Creating workflow...");
            CreateWorkflowRequest createReq = CreateWorkflowRequest.builder()
                    .workflowName("policy-demo-java")
                    .source(WorkflowSource.EXTERNAL)
                    .totalSteps(3)
                    .metadata(Map.of("example", "workflow-policy-java"))
                    .build();

            CreateWorkflowResponse workflow = client.createWorkflow(createReq);
            System.out.println("    Workflow ID: " + workflow.getWorkflowId());
            System.out.println();

            // Check step gate - demonstrates policiesEvaluated and policiesMatched
            System.out.println("1.2 Checking step gate (demonstrates policy info in response)...");
            StepGateRequest gateReq = StepGateRequest.builder()
                    .stepName("Analyze Data")
                    .stepType(StepType.LLM_CALL)
                    .model("gpt-4")
                    .provider("openai")
                    .stepInput(Map.of("prompt", "Analyze customer sentiment"))
                    .build();

            StepGateResponse gate = client.stepGate(workflow.getWorkflowId(), "step-1", gateReq);

            System.out.println("    Decision: " + gate.getDecision());
            if (gate.getReason() != null) {
                System.out.println("    Reason: " + gate.getReason());
            }

            // Display policy evaluation details (Issue #1021)
            if (gate.getPoliciesEvaluated() != null && !gate.getPoliciesEvaluated().isEmpty()) {
                System.out.println("    Policies Evaluated:");
                for (PolicyMatch p : gate.getPoliciesEvaluated()) {
                    System.out.printf("      - %s (%s): action=%s%n",
                            p.getPolicyName(), p.getPolicyId(), p.getAction());
                }
            }
            if (gate.getPoliciesMatched() != null && !gate.getPoliciesMatched().isEmpty()) {
                System.out.println("    Policies Matched:");
                for (PolicyMatch p : gate.getPoliciesMatched()) {
                    System.out.printf("      - %s: %s (reason: %s)%n",
                            p.getPolicyName(), p.getAction(), p.getReason());
                }
            }
            System.out.println();

            // Handle decision
            if (gate.getDecision() == GateDecision.BLOCK) {
                System.out.println("    Step BLOCKED by policy!");
                System.out.println("    Aborting workflow...");
                client.abortWorkflow(workflow.getWorkflowId(), gate.getReason());
                return;
            }

            if (gate.getDecision() == GateDecision.REQUIRE_APPROVAL) {
                System.out.println("    Step requires approval: " + gate.getApprovalUrl());
                // In production, wait for approval
            }

            // Mark step completed
            if (gate.getDecision() == GateDecision.ALLOW) {
                client.markStepCompleted(workflow.getWorkflowId(), "step-1", null);
                System.out.println("    Step completed!");
            }
            System.out.println();

            // Test with potentially sensitive content
            System.out.println("1.3 Testing with database query (potential SQLi check)...");
            StepGateRequest gateReq2 = StepGateRequest.builder()
                    .stepName("Execute Query")
                    .stepType(StepType.TOOL_CALL)
                    .stepInput(Map.of("query", "SELECT name, email FROM customers LIMIT 10"))
                    .build();

            StepGateResponse gate2 = client.stepGate(workflow.getWorkflowId(), "step-2", gateReq2);

            System.out.println("    Decision: " + gate2.getDecision());
            if (gate2.getPoliciesEvaluated() != null) {
                System.out.println("    Policies checked: " + gate2.getPoliciesEvaluated().size());
            }
            if (gate2.getPoliciesMatched() != null && !gate2.getPoliciesMatched().isEmpty()) {
                System.out.println("    Policies matched: " + gate2.getPoliciesMatched().size());
                for (PolicyMatch p : gate2.getPoliciesMatched()) {
                    System.out.printf("      - %s: %s%n", p.getPolicyName(), p.getReason());
                }
            }
            System.out.println();

            // Complete workflow
            System.out.println("1.4 Completing workflow...");
            client.completeWorkflow(workflow.getWorkflowId());
            System.out.println("    Workflow completed!");
            System.out.println();

            // ==========================================
            // Part 2: Audit Log Verification
            // ==========================================

            System.out.println("Part 2: Audit Log Verification");
            System.out.println("------------------------------");
            System.out.println();

            // Delay to ensure audit logs are flushed (batch writer flushes every 5-10 seconds)
            System.out.println("    Waiting for audit log batch flush...");
            Thread.sleep(6000);

            // Search for workflow audit logs
            System.out.println("2.1 Searching for workflow audit logs...");
            try {
                AuditSearchRequest searchRequest = AuditSearchRequest.builder()
                        .startTime(startTime)
                        .limit(50)
                        .build();

                AuditSearchResponse auditResponse = client.searchAuditLogs(searchRequest);

                // Count workflow-related entries
                Map<String, Integer> workflowLogs = new HashMap<>();
                for (AuditLogEntry entry : auditResponse.getEntries()) {
                    if (entry.getRequestId().equals(workflow.getWorkflowId())) {
                        workflowLogs.merge(entry.getRequestType(), 1, Integer::sum);
                    }
                }

                if (!workflowLogs.isEmpty()) {
                    int totalCount = workflowLogs.values().stream().mapToInt(Integer::intValue).sum();
                    System.out.println("    ✅ Found " + totalCount + " audit log entries for workflow " + workflow.getWorkflowId() + ":");
                    for (Map.Entry<String, Integer> e : workflowLogs.entrySet()) {
                        System.out.println("       - " + e.getKey() + ": " + e.getValue());
                    }
                } else {
                    System.out.println("    ⚠️  No audit logs found for this workflow");
                    System.out.println("       (Audit logs may take a moment to flush)");
                }
                System.out.println();

                // Verify expected audit entries
                System.out.println("2.2 Verifying expected audit entries...");
                List<String> expectedTypes = Arrays.asList("workflow_created", "workflow_step_gate", "workflow_completed");
                boolean allFound = true;
                for (String expected : expectedTypes) {
                    boolean found = auditResponse.getEntries().stream()
                            .anyMatch(e -> e.getRequestId().equals(workflow.getWorkflowId())
                                    && e.getRequestType().equals(expected));
                    if (found) {
                        System.out.println("    ✅ " + expected + ": FOUND");
                    } else {
                        System.out.println("    ❌ " + expected + ": NOT FOUND");
                        allFound = false;
                    }
                }
                System.out.println();

                if (allFound) {
                    System.out.println("    ✅ All expected audit log entries verified!");
                } else {
                    System.out.println("    ⚠️  Some audit log entries were not found");
                }
                System.out.println();

            } catch (Exception auditEx) {
                System.out.println("    ERROR searching audit logs: " + auditEx.getMessage());
                System.out.println();
            }

            // ==========================================
            // Summary
            // ==========================================

            System.out.println("==========================================");
            System.out.println("Summary");
            System.out.println("==========================================");
            System.out.println();
            System.out.println("WCP Policy Enforcement (Issue #1021):");
            System.out.println("  - StepGateResponse.policiesEvaluated: all checked policies");
            System.out.println("  - StepGateResponse.policiesMatched: policies that triggered decision");
            System.out.println("  - PolicyMatch includes: policyId, policyName, action, reason");
            System.out.println();
            System.out.println("Audit Logging (Issue #1019):");
            System.out.println("  - workflow_created: logged when workflow is registered");
            System.out.println("  - workflow_step_gate: logged for each step gate check");
            System.out.println("  - workflow_completed: logged when workflow completes");
            System.out.println("  - workflow_aborted: logged when workflow is aborted");
            System.out.println();
            System.out.println("MAP Policy Enforcement (Issue #1020):");
            System.out.println("  - PlanExecutionResponse.policyInfo: policy evaluation result");
            System.out.println("  - Includes: allowed, appliedPolicies, riskScore");
            System.out.println("  - Returns 403 Forbidden if policies block execution");
            System.out.println();

        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }
}
