package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.RequestType;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.BudgetOnExceed;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.BudgetPeriod;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.BudgetScope;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.BudgetStatus;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.CreateBudgetRequest;

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
 * 4. Verify that the budget's own status reports exceeded/blocked
 *
 * The Go and Python siblings additionally assert on the BudgetInfo carried in the blocked
 * response. That is not portable to Java SDK 9.0.0 — see makeRequestsUntilBlocked below.
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
    private static final String CLIENT_ID = "cost-controls-enforcement-example";
    private static final List<String> failures = new ArrayList<>();

    private final String budgetId;
    private final AxonFlow client;
    private final String userToken;

    public EnforcementExample() {
        this.budgetId = "enforcement-test-" + System.currentTimeMillis();
        this.client = AxonFlow.create(AxonFlowConfig.builder()
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
            BlockOutcome outcome = makeRequestsUntilBlocked();
            verifyEnforcement(outcome);
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
                    .scope(BudgetScope.ORGANIZATION)
                    .scopeId("demo-org")
                    .limitUsd(0.01) // $0.01 - will be exceeded by first request
                    .period(BudgetPeriod.DAILY)
                    .onExceed(BudgetOnExceed.BLOCK) // Key: requests should be BLOCKED when exceeded
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

    /**
     * Whether the request loop terminated in a budget block.
     *
     * <p>There is deliberately no {@code ClientResponse} carried alongside. The platform DOES send a
     * populated {@code budget_info} on the 402 (agent {@code run.go}, budget-block branch), and
     * the Go sibling of this example asserts on it — but the Java SDK 9.0.0 raises every 402 as
     * a {@link com.getaxonflow.sdk.exceptions.PolicyViolationException} from
     * {@code handleErrorResponse} before the body is deserialised, and it throws on
     * {@code blocked=true} before returning a {@code ClientResponse} too. So no path through
     * this SDK version can hand the example a {@code BudgetInfo}, and the four assertions the
     * Go and Python siblings make on it are not portable here. Tracked in #3192 — do not
     * "restore" them against a fabricated response object, which is what the pre-9.0.0 version
     * of this file did.
     */
    private enum BlockOutcome {
        BLOCKED,
        NOT_BLOCKED
    }

    private BlockOutcome makeRequestsUntilBlocked() {
        System.out.println("Step 2: Make LLM requests until blocked");
        System.out.println("-".repeat(40));

        int maxRequests = 10; // Safety limit

        for (int i = 1; i <= maxRequests; i++) {
            System.out.print("   Request " + i + ": ");

            try {
                client.proxyLLMCall(ClientRequest.builder()
                        .userToken(userToken)
                        .clientId(CLIENT_ID)
                        .query("Say hello in one word")
                        .requestType(RequestType.CHAT)
                        // Provider goes in the CONTEXT: the builder's llmProvider() field
                        // serialises as llm_provider, which the agent's request struct does
                        // not carry and nothing reads. See #3192.
                        .context(Map.of("provider", "openai"))
                        .build());

                System.out.println("OK (tokens used)");
            } catch (Exception e) {
                String errorStr = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
                // A budget block arrives as an exception, not as a returned response:
                // proxyLLMCall throws PolicyViolationException on both blocked=true and
                // HTTP 402.
                if (errorStr.contains("402") || errorStr.contains("payment required")
                        || errorStr.contains("budget") || errorStr.contains("exceeded")) {
                    System.out.println("BLOCKED (budget exceeded) ✓");
                    return BlockOutcome.BLOCKED;
                }
                System.out.println("ERROR: " + e.getMessage());
                assertCheck(false, "Request " + i + " failed for a non-budget reason: " + e.getMessage());
            }
        }

        System.out.println();
        return BlockOutcome.NOT_BLOCKED;
    }

    private void verifyEnforcement(BlockOutcome outcome) {
        System.out.println("Step 3: Verify enforcement");
        System.out.println("-".repeat(27));

        // Test 1: Request was blocked
        assertCheck(outcome == BlockOutcome.BLOCKED, "Request was blocked when budget exceeded");

        // Test 2: the budget's own status confirms it, which is the assertion that
        // survives the SDK's discarding of the 402 body (see makeRequestsUntilBlocked).
        try {
            BudgetStatus status = client.getBudgetStatus(budgetId);
            boolean statusConfirmed = Boolean.TRUE.equals(status.isBlocked())
                    || Boolean.TRUE.equals(status.isExceeded());
            assertCheck(statusConfirmed, "GetBudgetStatus confirms is_blocked or is_exceeded");

            Double percentage = status.getPercentage();
            assertCheck(percentage != null && percentage >= 100,
                    String.format("BudgetStatus.percentage is %s (>= 100)", percentage));

            assertCheck(status.getBudget() != null && "block".equals(status.getBudget().getOnExceed()),
                    "Budget on_exceed is 'block'");
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
