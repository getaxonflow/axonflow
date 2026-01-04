/**
 * AxonFlow Cost Controls Example - TypeScript SDK (Comprehensive)
 *
 * This example covers ALL cost control SDK methods:
 * - Budget: Create, Get, List, Update, Delete
 * - Budget Status and Alerts
 * - Budget Check (pre-flight)
 * - Usage: Summary, Breakdown, Records
 * - Pricing
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

function getEnv(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

async function main() {
  console.log("AxonFlow Cost Controls - TypeScript SDK (Comprehensive)");
  console.log("=".repeat(56));
  console.log();

  // Create AxonFlow client
  const client = new AxonFlow({
    endpoint: getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
    orchestratorEndpoint: getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
  });

  const budgetId = `demo-budget-ts-${Date.now()}`;

  // ========================================
  // BUDGET MANAGEMENT
  // ========================================

  // 1. createBudget
  console.log("1. createBudget - Creating a monthly budget...");
  let createdBudget: Budget | null = null;
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
    return;
  }
  console.log();

  // 2. getBudget
  console.log("2. getBudget - Retrieving budget by ID...");
  try {
    const retrievedBudget = await client.getBudget(budgetId);
    console.log(`   Retrieved: ${retrievedBudget.id} (scope: ${retrievedBudget.scope}, period: ${retrievedBudget.period})`);
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
  }
  console.log();

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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  } catch (error) {
    console.log(`   ERROR: ${error}`);
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
  try {
    await client.deleteBudget(budgetId);
    console.log(`   Deleted budget: ${budgetId}`);
  } catch (error) {
    console.log(`   WARNING: Failed to delete budget: ${error}`);
  }
  console.log();

  console.log("=".repeat(56));
  console.log("All 12 Cost Control methods tested!");
}

main().catch(console.error);
