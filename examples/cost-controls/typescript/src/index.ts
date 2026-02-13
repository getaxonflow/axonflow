/**
 * AxonFlow Cost Controls Example - TypeScript SDK (Comprehensive)
 *
 * This example covers ALL cost control SDK methods:
 * - Budget: Create, Get, List, Update, Delete
 * - Budget Status and Alerts
 * - Budget Check (pre-flight)
 * - Usage: Summary, Breakdown, Records
 * - Pricing
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";
import type {
  Budget,
  CreateBudgetRequest,
  UpdateBudgetRequest,
  BudgetCheckRequest,
  ListBudgetsOptions,
  ListUsageRecordsOptions,
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

function getEnv(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

async function main() {
  console.log("AxonFlow Cost Controls - TypeScript SDK (Comprehensive)");
  console.log("=".repeat(56));
  console.log();

  // Create AxonFlow client
  // Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
  // The Agent proxies orchestrator routes internally.
  const client = new AxonFlow({
    endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
  });

  const budgetId = `demo-budget-ts-${Date.now()}`;

  // ========================================
  // BUDGET MANAGEMENT
  // ========================================

  // 1. createBudget
  console.log("1. createBudget - Creating a monthly budget...");
  let createdBudget: Budget | null = null;
  let budgetsAvailable = true;
  try {
    const request: CreateBudgetRequest = {
      id: budgetId,
      name: "Demo Budget (TypeScript SDK)",
      scope: "organization",
      limitUsd: 100.0,
      period: "monthly",
      onExceed: "warn",
      alertThresholds: [50, 80, 100],
    };
    createdBudget = await client.createBudget(request);
    console.log(`   Created: ${createdBudget.id} (limit: $${createdBudget.limitUsd.toFixed(2)}/month)`);
    assertCheck(createdBudget.id === budgetId, `Budget ID matches (expected: ${budgetId})`);
    assertCheck(createdBudget.limitUsd === 100.0, `Budget limit is $100.00 (got: ${createdBudget.limitUsd})`);
    assertCheck(createdBudget.period === "monthly", `Budget period is monthly (got: ${createdBudget.period})`);
    assertCheck(createdBudget.scope === "organization", `Budget scope is organization (got: ${createdBudget.scope})`);
  } catch (error) {
    const errStr = String(error);
    if (errStr.includes("404") || errStr.toLowerCase().includes("not found")) {
      console.log("   Budget management requires Enterprise license (endpoint returned 404)");
      budgetsAvailable = false;
    } else {
      console.log(`   ERROR: ${error}`);
      failures.push("createBudget failed");
      return;
    }
  }
  console.log();

  if (budgetsAvailable) {
    // 2. getBudget
    console.log("2. getBudget - Retrieving budget by ID...");
    try {
      const retrievedBudget = await client.getBudget(budgetId);
      console.log(`   Retrieved: ${retrievedBudget.id} (scope: ${retrievedBudget.scope}, period: ${retrievedBudget.period})`);
      assertCheck(retrievedBudget.id === budgetId, `Retrieved budget ID matches (expected: ${budgetId})`);
      assertCheck(retrievedBudget.name === "Demo Budget (TypeScript SDK)", "Retrieved budget name matches");
    } catch (error) {
      console.log(`   ERROR: ${error}`);
      failures.push("getBudget failed");
    }
    console.log();

    // 3. listBudgets
    console.log("3. listBudgets - Listing all budgets...");
    try {
      const options: ListBudgetsOptions = { limit: 10 };
      const budgetList = await client.listBudgets(options);
      console.log(`   Found ${budgetList.budgets.length} budgets (total: ${budgetList.total})`);
      budgetList.budgets.slice(0, 3).forEach((b) => {
        console.log(`   - ${b.id}: $${b.limitUsd.toFixed(2)}/${b.period}`);
      });
      if (budgetList.budgets.length > 3) {
        console.log(`   ... and ${budgetList.budgets.length - 3} more`);
      }
      assertCheck(Array.isArray(budgetList.budgets), "Budgets response is an array");
      assertCheck(budgetList.budgets.length >= 1, `At least 1 budget exists (got ${budgetList.budgets.length})`);
      const ourBudget = budgetList.budgets.find((b) => b.id === budgetId);
      assertCheck(ourBudget !== undefined, `Created budget ${budgetId} is in the list`);
    } catch (error) {
      console.log(`   ERROR: ${error}`);
      failures.push("listBudgets failed");
    }
    console.log();

    // 4. updateBudget
    console.log("4. updateBudget - Updating budget limit...");
    try {
      const updateRequest: UpdateBudgetRequest = {
        name: "Demo Budget (TypeScript SDK) - Updated",
        limitUsd: 150.0,
      };
      const updatedBudget = await client.updateBudget(budgetId, updateRequest);
      console.log(`   Updated: ${updatedBudget.id} (new limit: $${updatedBudget.limitUsd.toFixed(2)})`);
      assertCheck(updatedBudget.limitUsd === 150.0, `Updated limit is $150.00 (got: ${updatedBudget.limitUsd})`);
      assertCheck(updatedBudget.name === "Demo Budget (TypeScript SDK) - Updated", "Updated name matches");
    } catch (error) {
      console.log(`   ERROR: ${error}`);
      failures.push("updateBudget failed");
    }
    console.log();

    // ========================================
    // BUDGET STATUS & ALERTS
    // ========================================

    // 5. getBudgetStatus
    console.log("5. getBudgetStatus - Checking current budget status...");
    try {
      const status = await client.getBudgetStatus(budgetId);
      console.log(`   Used: $${status.usedUsd.toFixed(2)} / $${status.budget.limitUsd.toFixed(2)} (${status.percentage.toFixed(1)}%)`);
      console.log(`   Remaining: $${status.remainingUsd.toFixed(2)}`);
      console.log(`   Exceeded: ${status.isExceeded}, Blocked: ${status.isBlocked}`);
      assertCheck(status.budget !== undefined, "Budget status contains budget object");
      assertCheck(status.budget.limitUsd === 150.0, `Budget limit is $150.00 (got: ${status.budget.limitUsd})`);
      assertCheck(typeof status.usedUsd === "number", "usedUsd is a number");
      assertCheck(typeof status.percentage === "number", "percentage is a number");
      assertCheck(status.remainingUsd >= 0, `remainingUsd is non-negative (got: ${status.remainingUsd})`);
    } catch (error) {
      console.log(`   ERROR: ${error}`);
      failures.push("getBudgetStatus failed");
    }
    console.log();

    // 6. getBudgetAlerts
    console.log("6. getBudgetAlerts - Getting alerts for budget...");
    try {
      const alertsResponse = await client.getBudgetAlerts(budgetId);
      console.log(`   Found ${alertsResponse.count} alerts`);
      alertsResponse.alerts.forEach((a) => {
        console.log(`   - [${a.alertType}] ${a.message} (${a.percentageReached.toFixed(1)}% at $${a.amountUsd.toFixed(2)})`);
      });
      if (alertsResponse.count === 0) {
        console.log("   (no alerts yet)");
      }
    } catch (error) {
      console.log(`   ERROR: ${error}`);
    }
    console.log();

    // 7. checkBudget
    console.log("7. checkBudget - Pre-flight budget check...");
    try {
      const checkRequest: BudgetCheckRequest = { orgId: "demo-org" };
      const decision = await client.checkBudget(checkRequest);
      console.log(`   Allowed: ${decision.allowed}`);
      if (decision.action) {
        console.log(`   Action: ${decision.action}`);
      }
      if (decision.message) {
        console.log(`   Message: ${decision.message}`);
      }
      assertCheck(typeof decision.allowed === "boolean", "checkBudget returns allowed boolean");
    } catch (error) {
      console.log(`   ERROR: ${error}`);
      failures.push("checkBudget failed");
    }
    console.log();
  } else {
    console.log("2-7. Skipping budget operations (requires Enterprise license)");
    console.log();
  }

  // ========================================
  // USAGE TRACKING
  // ========================================

  // 8. getUsageSummary
  console.log("8. getUsageSummary - Getting usage summary...");
  try {
    const summary = await client.getUsageSummary("monthly");
    console.log(`   Total Cost: $${summary.totalCostUsd.toFixed(6)}`);
    console.log(`   Total Requests: ${summary.totalRequests}`);
    console.log(`   Tokens: ${summary.totalTokensIn} in, ${summary.totalTokensOut} out`);
    console.log(`   Avg Cost/Request: $${summary.averageCostPerRequest.toFixed(6)}`);
    assertCheck(typeof summary.totalCostUsd === "number", "totalCostUsd is a number");
    assertCheck(typeof summary.totalRequests === "number", "totalRequests is a number");
    assertCheck(summary.totalCostUsd >= 0, `totalCostUsd is non-negative (got: ${summary.totalCostUsd})`);
    assertCheck(summary.totalRequests >= 0, `totalRequests is non-negative (got: ${summary.totalRequests})`);
  } catch (error) {
    console.log(`   ERROR: ${error}`);
    failures.push("getUsageSummary failed");
  }
  console.log();

  // 9. getUsageBreakdown
  console.log("9. getUsageBreakdown - Getting usage breakdown by provider...");
  try {
    const breakdown = await client.getUsageBreakdown("provider", "monthly");
    console.log(`   Breakdown by: ${breakdown.groupBy} (total: $${breakdown.totalCostUsd.toFixed(6)})`);
    breakdown.items.forEach((item) => {
      console.log(`   - ${item.groupValue}: $${item.costUsd.toFixed(6)} (${item.percentage.toFixed(1)}%, ${item.requestCount} requests)`);
    });
    if (breakdown.items.length === 0) {
      console.log("   (no usage data yet)");
    }
    assertCheck(breakdown.groupBy === "provider", `Breakdown groupBy is provider (got: ${breakdown.groupBy})`);
    assertCheck(Array.isArray(breakdown.items), "Breakdown items is an array");
    assertCheck(typeof breakdown.totalCostUsd === "number", "totalCostUsd is a number");
  } catch (error) {
    const errMsg = String(error);
    if (errMsg.includes("404") || errMsg.toLowerCase().includes("not found")) {
      console.log("   Usage breakdown requires Enterprise license (endpoint returned 404)");
    } else {
      console.log(`   ERROR: ${error}`);
      failures.push("getUsageBreakdown failed");
    }
  }
  console.log();

  // 10. listUsageRecords
  console.log("10. listUsageRecords - Listing recent usage records...");
  try {
    const options: ListUsageRecordsOptions = { limit: 5 };
    const recordsResponse = await client.listUsageRecords(options);
    console.log(`   Found ${recordsResponse.total} records (showing up to 5)`);
    recordsResponse.records.forEach((r) => {
      console.log(`   - ${r.provider}/${r.model}: ${r.tokensIn + r.tokensOut} tokens, $${r.costUsd.toFixed(6)}`);
    });
    if (recordsResponse.records.length === 0) {
      console.log("   (no usage records yet)");
    }
    assertCheck(Array.isArray(recordsResponse.records), "Records response is an array");
    assertCheck(typeof recordsResponse.total === "number", "Total is a number");
  } catch (error) {
    const errMsg = String(error);
    if (errMsg.includes("404") || errMsg.toLowerCase().includes("not found")) {
      console.log("   Usage records requires Enterprise license (endpoint returned 404)");
    } else {
      console.log(`   ERROR: ${error}`);
      failures.push("listUsageRecords failed");
    }
  }
  console.log();

  // ========================================
  // PRICING
  // ========================================

  // 11. getPricing
  console.log("11. getPricing - Getting model pricing...");
  try {
    const pricingResp = await client.getPricing("anthropic", "claude-sonnet-4");
    if (pricingResp.pricing.length > 0) {
      const pricing = pricingResp.pricing[0];
      console.log(`   Provider: ${pricing.provider}`);
      console.log(`   Model: ${pricing.model}`);
      console.log(`   Input: $${pricing.pricing.inputPer1k.toFixed(4)}/1K tokens`);
      console.log(`   Output: $${pricing.pricing.outputPer1k.toFixed(4)}/1K tokens`);
    }
  } catch (error) {
    console.log(`   ERROR: ${error}`);
  }
  console.log();

  // ========================================
  // CLEANUP
  // ========================================

  // 12. deleteBudget
  console.log("12. deleteBudget - Cleaning up...");
  if (budgetsAvailable) {
    try {
      await client.deleteBudget(budgetId);
      console.log(`   Deleted budget: ${budgetId}`);
      // Verify deletion
      try {
        await client.getBudget(budgetId);
        failures.push("deleteBudget: Budget still exists after deletion");
      } catch {
        assertCheck(true, "Budget successfully deleted (not found on lookup)");
      }
    } catch (error) {
      console.log(`   WARNING: Failed to delete budget: ${error}`);
      failures.push("deleteBudget failed");
    }
  } else {
    console.log("   Skipped (budget was not created)");
  }
  console.log();

  console.log("=".repeat(56));
  console.log("All 12 Cost Control methods tested!");
  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  } else {
    console.log("All assertions passed!");
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
