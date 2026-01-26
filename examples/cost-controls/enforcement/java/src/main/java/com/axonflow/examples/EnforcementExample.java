package com.axonflow.examples;

import com.axonflow.sdk.AxonFlowClient;
import com.axonflow.sdk.AxonFlowConfig;
import com.axonflow.sdk.BudgetInfo;
import com.axonflow.sdk.BudgetStatus;
import com.axonflow.sdk.CreateBudgetRequest;
import com.axonflow.sdk.LLMResponse;
import com.axonflow.sdk.ProxyLLMCallRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow Budget Enforcement Test - Java (Issue #1082)
 *
 * This example tests that budget limits are ACTUALLY enforced, not just tracked:
 * 1. Create a budget with a low limit ($0.01) and on_exceed=block
 * 2. Make LLM requests until the budget is exceeded
 * 3. Verify that subsequent requests are blocked with HTTP 402
 * 4. Verify that BudgetInfo is included in the response
 *
 * This addresses Issue #1082 - testing actual functionality, not just API availability.
 *
 * Prerequisites:
 * - AxonFlow Agent running on localhost:8080
 * - OpenAI or Anthropic API key configured in AxonFlow
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   mvn compile exec:java
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class EnforcementExample {
    private static final List<String> failures = new ArrayList<>();
    private final String budgetId;
    private final AxonFlowClient client;
    private final String userToken;

    public EnforcementExample() {
        this.budgetId = "enforcement-test-" + System.currentTimeMillis();
        this.client = new AxonFlowClient(AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo-client"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"))
                .build());
        this.userToken = getEnv("AXONFLOW_USER_TOKEN", "");
    }

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   ✓ PASS: " + message);
        } else {
            System.out.println("   ❌ FAIL: " + message);
            failures.add(message);
        }
    }

    public static void main(String[] args) {
        EnforcementExample example = new EnforcementExample();
        example.run();
    }

    public void run() {
        System.out.println("AxonFlow Budget Enforcement Test - Java (Issue #1082)");
        System.out.println("=".repeat(56));
        System.out.println();
        System.out.println("This test verifies that budget limits BLOCK requests, not just track them.");
        System.out.println();

        try {
            createBudget();
            LLMResponse blockedResponse = makeRequestsUntilBlocked();
            verifyEnforcement(blockedResponse);
        } finally {
            cleanup();
        }

        printSummary();
    }

    private void createBudget() {
        System.out.println("Step 1: Create a budget with on_exceed=block");
        System.out.println("-".repeat(44));

        try {
            client.createBudget(CreateBudgetRequest.builder()
                    .id(budgetId)
                    .name("Enforcement Test Budget")
                    .scope("organization")
                    .scopeId("demo-org")
                    .limitUsd(0.01) // $0.01 - will be exceeded by first request
                    .period("daily")
                    .onExceed("block") // Key: requests should be BLOCKED when exceeded
                    .alertThresholds(List.of(50, 80, 100))
                    .build());
            System.out.println("   Created budget: " + budgetId + " (limit: $0.01, action: block)");
            System.out.println();
        } catch (Exception e) {
            System.out.println("ERROR: Failed to create budget: " + e.getMessage());
            System.out.println();
            System.out.println("This test requires the cost controls API to be available.");
            System.out.println("Skipping enforcement test.");
            System.exit(0);
        }
    }

    private LLMResponse makeRequestsUntilBlocked() {
        System.out.println("Step 2: Make LLM requests until blocked");
        System.out.println("-".repeat(40));

        LLMResponse blockedResponse = null;
        int maxRequests = 10; // Safety limit

        for (int i = 1; i <= maxRequests; i++) {
            System.out.print("   Request " + i + ": ");

            try {
                // Use ProxyLLMCall (not deprecated executeQuery)
                LLMResponse response = client.proxyLLMCall(ProxyLLMCallRequest.builder()
                        .userToken(userToken)
                        .query("Say hello in one word")
                        .requestType("chat")
                        .options(Map.of("provider", "openai"))
                        .build());

                if (response.isBlocked() && response.getBlockReason() != null) {
                    System.out.println("BLOCKED - " + response.getBlockReason() + " ✓");
                    blockedResponse = response;
                    break;
                }

                System.out.println("OK (tokens used)");
            } catch (Exception e) {
                String errorStr = e.getMessage().toLowerCase();
                // Check if this is a budget block error (HTTP 402)
                if (errorStr.contains("402") || errorStr.contains("payment required") ||
                    errorStr.contains("budget") || errorStr.contains("exceeded")) {
                    System.out.println("BLOCKED (budget exceeded) ✓");
                    blockedResponse = LLMResponse.builder().blocked(true).build();
                    break;
                }
                System.out.println("ERROR: " + e.getMessage());
                failCount++;
            }
        }

        System.out.println();
        return blockedResponse;
    }

    private void verifyEnforcement(LLMResponse blockedResponse) {
        System.out.println("Step 3: Verify enforcement");
        System.out.println("-".repeat(27));

        // Test 1: Request was blocked
        assertCheck(blockedResponse != null, "Request was blocked when budget exceeded");
        if (blockedResponse == null) {
            return;
        }

        // Test 2: BudgetInfo is present in response
        BudgetInfo budgetInfo = blockedResponse.getBudgetInfo();
        assertCheck(budgetInfo != null, "BudgetInfo is included in blocked response");
        if (budgetInfo != null) {
            // Test 3: BudgetInfo shows exceeded status
            assertCheck(budgetInfo.isExceeded(), "BudgetInfo.exceeded is true");

            // Test 4: Percentage >= 100
            double percentage = budgetInfo.getPercentage();
            assertCheck(percentage >= 100, String.format("BudgetInfo.percentage is %.1f%% (>= 100%%)", percentage));

            // Test 5: Action is "block"
            String action = budgetInfo.getAction();
            assertCheck("block".equals(action), "BudgetInfo.action is 'block' (got: " + action + ")");
        }

        // Test 6: Verify budget status via API
        try {
            BudgetStatus status = client.getBudgetStatus(budgetId);
            boolean statusConfirmed = status.isBlocked() || status.isExceeded();
            assertCheck(statusConfirmed, "GetBudgetStatus confirms is_blocked or is_exceeded");
        } catch (Exception e) {
            assertCheck(false, "Could not get budget status: " + e.getMessage());
        }
    }

    private void cleanup() {
        System.out.println();
        System.out.println("Step 4: Cleanup");
        System.out.println("-".repeat(15));
        try {
            client.deleteBudget(budgetId);
            System.out.println("   Deleted budget: " + budgetId);
        } catch (Exception e) {
            System.out.println("   Warning: Failed to delete budget: " + e.getMessage());
        }
    }

    private void printSummary() {
        System.out.println();
        System.out.println("=".repeat(56));
        System.out.println("Assertion Summary");
        System.out.println("=".repeat(56));

        if (failures.isEmpty()) {
            System.out.println("All assertions passed! Budget enforcement is working correctly!");
        } else {
            System.out.println("Failures (" + failures.size() + "):");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.out.println("Budget enforcement has issues - check the failures above.");
            System.exit(1);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
