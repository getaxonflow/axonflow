package com.example;

import java.time.Instant;
import java.util.Arrays;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.costcontrols.CostControlTypes.*;

/**
 * AxonFlow Cost Controls Example - Java SDK (Comprehensive)
 *
 * This example covers ALL cost control SDK methods:
 * - Budget: Create, Get, List, Update, Delete
 * - Budget Status and Alerts
 * - Budget Check (pre-flight)
 * - Usage: Summary, Breakdown, Records
 * - Pricing
 */
public class CostControlsExample {

    public static void main(String[] args) {
        System.out.println("AxonFlow Cost Controls - Java SDK (Comprehensive)");
        System.out.println("=".repeat(52));
        System.out.println();

        // Create AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .orchestratorUrl(getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"))
            .build());

        String budgetId = "demo-budget-java-" + Instant.now().getEpochSecond();
        Budget createdBudget = null;

        try {
            // ========================================
            // BUDGET MANAGEMENT
            // ========================================

            // 1. createBudget
            System.out.println("1. createBudget - Creating a monthly budget...");
            try {
                CreateBudgetRequest request = CreateBudgetRequest.builder()
                    .id(budgetId)
                    .name("Demo Budget (Java SDK)")
                    .scope(BudgetScope.ORGANIZATION)
                    .limitUsd(100.0)
                    .period(BudgetPeriod.MONTHLY)
                    .onExceed(BudgetOnExceed.WARN)
                    .alertThresholds(Arrays.asList(50, 80, 100))
                    .build();

                createdBudget = client.createBudget(request);
                System.out.printf("   Created: %s (limit: $%.2f/month)%n", createdBudget.getId(), createdBudget.getLimitUsd());
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
                return;
            }
            System.out.println();

            // 2. getBudget
            System.out.println("2. getBudget - Retrieving budget by ID...");
            try {
                Budget retrievedBudget = client.getBudget(budgetId);
                System.out.printf("   Retrieved: %s (scope: %s, period: %s)%n",
                    retrievedBudget.getId(), retrievedBudget.getScope(), retrievedBudget.getPeriod());
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 3. listBudgets
            System.out.println("3. listBudgets - Listing all budgets...");
            try {
                BudgetsResponse budgetList = client.listBudgets(ListBudgetsOptions.builder().limit(10).build());
                System.out.printf("   Found %d budgets (total: %d)%n", budgetList.getBudgets().size(), budgetList.getTotal());
                int count = 0;
                for (Budget b : budgetList.getBudgets()) {
                    if (count++ >= 3) {
                        System.out.printf("   ... and %d more%n", budgetList.getBudgets().size() - 3);
                        break;
                    }
                    System.out.printf("   - %s: $%.2f/%s%n", b.getId(), b.getLimitUsd(), b.getPeriod());
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 4. updateBudget
            System.out.println("4. updateBudget - Updating budget limit...");
            try {
                UpdateBudgetRequest updateRequest = UpdateBudgetRequest.builder()
                    .name("Demo Budget (Java SDK) - Updated")
                    .limitUsd(150.0)
                    .build();
                Budget updatedBudget = client.updateBudget(budgetId, updateRequest);
                System.out.printf("   Updated: %s (new limit: $%.2f)%n", updatedBudget.getId(), updatedBudget.getLimitUsd());
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // ========================================
            // BUDGET STATUS & ALERTS
            // ========================================

            // 5. getBudgetStatus
            System.out.println("5. getBudgetStatus - Checking current budget status...");
            try {
                BudgetStatus status = client.getBudgetStatus(budgetId);
                System.out.printf("   Used: $%.2f / $%.2f (%.1f%%)%n",
                    status.getUsedUsd(), status.getBudget().getLimitUsd(), status.getPercentage());
                System.out.printf("   Remaining: $%.2f%n", status.getRemainingUsd());
                System.out.printf("   Exceeded: %s, Blocked: %s%n", status.isExceeded(), status.isBlocked());
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 6. getBudgetAlerts
            System.out.println("6. getBudgetAlerts - Getting alerts for budget...");
            try {
                BudgetAlertsResponse alertsResponse = client.getBudgetAlerts(budgetId);
                System.out.printf("   Found %d alerts%n", alertsResponse.getCount());
                if (alertsResponse.getAlerts() != null) {
                    for (BudgetAlert a : alertsResponse.getAlerts()) {
                        System.out.printf("   - [%s] %s (%.1f%% at $%.2f)%n",
                            a.getAlertType(), a.getMessage(), a.getPercentageReached(), a.getAmountUsd());
                    }
                }
                if (alertsResponse.getCount() == 0) {
                    System.out.println("   (no alerts yet)");
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 7. checkBudget
            System.out.println("7. checkBudget - Pre-flight budget check...");
            try {
                BudgetCheckRequest checkRequest = BudgetCheckRequest.builder()
                    .orgId("demo-org")
                    .build();
                BudgetDecision decision = client.checkBudget(checkRequest);
                System.out.printf("   Allowed: %s%n", decision.isAllowed());
                if (decision.getAction() != null) {
                    System.out.printf("   Action: %s%n", decision.getAction());
                }
                if (decision.getMessage() != null) {
                    System.out.printf("   Message: %s%n", decision.getMessage());
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // ========================================
            // USAGE TRACKING
            // ========================================

            // 8. getUsageSummary
            System.out.println("8. getUsageSummary - Getting usage summary...");
            try {
                UsageSummary summary = client.getUsageSummary("monthly");
                System.out.printf("   Total Cost: $%.6f%n", summary.getTotalCostUsd());
                System.out.printf("   Total Requests: %d%n", summary.getTotalRequests());
                System.out.printf("   Tokens: %d in, %d out%n", summary.getTotalTokensIn(), summary.getTotalTokensOut());
                System.out.printf("   Avg Cost/Request: $%.6f%n", summary.getAverageCostPerRequest());
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 9. getUsageBreakdown
            System.out.println("9. getUsageBreakdown - Getting usage breakdown by provider...");
            try {
                UsageBreakdown breakdown = client.getUsageBreakdown("provider", "monthly");
                System.out.printf("   Breakdown by: %s (total: $%.6f)%n", breakdown.getGroupBy(), breakdown.getTotalCostUsd());
                if (breakdown.getItems() != null) {
                    for (UsageBreakdownItem item : breakdown.getItems()) {
                        System.out.printf("   - %s: $%.6f (%.1f%%, %d requests)%n",
                            item.getGroupValue(), item.getCostUsd(), item.getPercentage(), item.getRequestCount());
                    }
                }
                if (breakdown.getItems() == null || breakdown.getItems().isEmpty()) {
                    System.out.println("   (no usage data yet)");
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // 10. listUsageRecords
            System.out.println("10. listUsageRecords - Listing recent usage records...");
            try {
                UsageRecordsResponse recordsResponse = client.listUsageRecords(
                    ListUsageRecordsOptions.builder().limit(5).build());
                System.out.printf("   Found %d records (showing up to 5)%n", recordsResponse.getTotal());
                if (recordsResponse.getRecords() != null) {
                    for (UsageRecord r : recordsResponse.getRecords()) {
                        System.out.printf("   - %s/%s: %d tokens, $%.6f%n",
                            r.getProvider(), r.getModel(), r.getTokensIn() + r.getTokensOut(), r.getCostUsd());
                    }
                }
                if (recordsResponse.getRecords() == null || recordsResponse.getRecords().isEmpty()) {
                    System.out.println("   (no usage records yet)");
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // ========================================
            // PRICING
            // ========================================

            // 11. getPricing
            System.out.println("11. getPricing - Getting model pricing...");
            try {
                PricingListResponse pricingResp = client.getPricing("anthropic", "claude-sonnet-4");
                if (pricingResp.getPricing() != null && !pricingResp.getPricing().isEmpty()) {
                    PricingInfo pricing = pricingResp.getPricing().get(0);
                    System.out.printf("   Provider: %s%n", pricing.getProvider());
                    System.out.printf("   Model: %s%n", pricing.getModel());
                    System.out.printf("   Input: $%.4f/1K tokens%n", pricing.getPricing().getInputPer1k());
                    System.out.printf("   Output: $%.4f/1K tokens%n", pricing.getPricing().getOutputPer1k());
                }
            } catch (Exception e) {
                System.out.printf("   ERROR: %s%n", e.getMessage());
            }
            System.out.println();

            // ========================================
            // CLEANUP
            // ========================================

            // 12. deleteBudget
            System.out.println("12. deleteBudget - Cleaning up...");
            try {
                client.deleteBudget(budgetId);
                System.out.printf("   Deleted budget: %s%n", budgetId);
            } catch (Exception e) {
                System.out.printf("   WARNING: Failed to delete budget: %s%n", e.getMessage());
            }
            System.out.println();

            System.out.println("=".repeat(52));
            System.out.println("All 12 Cost Control methods tested!");

        } finally {
            client.close();
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null && !value.isEmpty() ? value : defaultValue;
    }
}
