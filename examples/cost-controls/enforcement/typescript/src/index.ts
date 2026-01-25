/**
 * AxonFlow Budget Enforcement Test - TypeScript (Issue #1082)
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
 *   npm install
 *   npm start
 */

import { AxonFlow } from '@axonflow/sdk';
import type { ExecuteQueryResponse, BudgetStatus } from '@axonflow/sdk';

// Extend SDK types for budget info access
interface BudgetInfoFromResponse {
  budgetId?: string;
  budgetName?: string;
  usedUsd: number;
  limitUsd: number;
  percentage: number;
  exceeded: boolean;
  action?: string;
}

class EnforcementTest {
  private passCount = 0;
  private failCount = 0;
  private budgetId: string;
  private client: AxonFlow;
  private userToken: string;

  constructor() {
    this.budgetId = `enforcement-test-${Date.now()}`;
    // Disable caching for budget enforcement testing
    // Otherwise cached responses bypass budget checks
    this.client = new AxonFlow({
      endpoint: process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080',
      clientId: process.env.AXONFLOW_CLIENT_ID || 'demo-client',
      clientSecret: process.env.AXONFLOW_CLIENT_SECRET || 'demo-secret',
      cache: { enabled: false, ttl: 1 },
    });
    this.userToken = process.env.AXONFLOW_USER_TOKEN || '';
  }

  async run(): Promise<void> {
    console.log('AxonFlow Budget Enforcement Test - TypeScript (Issue #1082)');
    console.log('='.repeat(60));
    console.log();
    console.log('This test verifies that budget limits BLOCK requests, not just track them.');
    console.log();

    try {
      await this.createBudget();
      const blockedResponse = await this.makeRequestsUntilBlocked();
      await this.verifyEnforcement(blockedResponse);
    } finally {
      await this.cleanup();
    }

    this.printSummary();
  }

  private async createBudget(): Promise<void> {
    console.log('Step 1: Create a budget with on_exceed=block');
    console.log('-'.repeat(44));

    try {
      await this.client.createBudget({
        id: this.budgetId,
        name: 'Enforcement Test Budget',
        scope: 'organization',
        scopeId: 'demo-org',
        limitUsd: 0.01, // $0.01 - will be exceeded by first request
        period: 'daily',
        onExceed: 'block', // Key: requests should be BLOCKED when exceeded
        alertThresholds: [50, 80, 100],
      });
      console.log(`   Created budget: ${this.budgetId} (limit: $0.01, action: block)`);
      console.log();
    } catch (e) {
      console.log(`ERROR: Failed to create budget: ${e}`);
      console.log();
      console.log('This test requires the cost controls API to be available.');
      console.log('Skipping enforcement test.');
      process.exit(0);
    }
  }

  private async makeRequestsUntilBlocked(): Promise<ExecuteQueryResponse | null> {
    console.log('Step 2: Make LLM requests until blocked');
    console.log('-'.repeat(40));

    let blockedResponse: ExecuteQueryResponse | null = null;
    const maxRequests = 10; // Safety limit

    for (let i = 1; i <= maxRequests; i++) {
      process.stdout.write(`   Request ${i}: `);

      try {
        // Use proxyLLMCall (not deprecated executeQuery)
        const response = await this.client.proxyLLMCall({
          userToken: this.userToken,
          query: 'Say hello in one word',
          requestType: 'chat',
          context: { provider: 'openai' },
        });

        // Debug: print budget info if present
        if (response.budgetInfo) {
          console.log(`Budget: ${JSON.stringify(response.budgetInfo)}`);
        }

        if (response.blocked && response.blockReason) {
          console.log(`BLOCKED - ${response.blockReason} ✓`);
          blockedResponse = response;
          break;
        }

        if (response.blocked) {
          console.log(`BLOCKED (no reason) - budget_info: ${JSON.stringify(response.budgetInfo)} ✓`);
          blockedResponse = response;
          break;
        }

        console.log(`OK (blocked=${response.blocked}, success=${response.success})`);
      } catch (e: unknown) {
        const errorStr = String(e).toLowerCase();
        // Check if this is a budget block error (HTTP 402)
        if (['402', 'payment required', 'budget', 'exceeded'].some(s => errorStr.includes(s))) {
          console.log('BLOCKED (budget exceeded) ✓');
          // Create a response-like object from the error
          blockedResponse = {
            blocked: true,
            success: false,
            metadata: {},
            budgetInfo: (e as { budgetInfo?: BudgetInfoFromResponse }).budgetInfo,
          } as unknown as ExecuteQueryResponse;
          break;
        }
        console.log(`ERROR: ${e}`);
        this.failCount++;
      }
    }

    console.log();
    return blockedResponse;
  }

  private async verifyEnforcement(blockedResponse: ExecuteQueryResponse | null): Promise<void> {
    console.log('Step 3: Verify enforcement');
    console.log('-'.repeat(27));

    // Test 1: Request was blocked
    if (blockedResponse !== null) {
      console.log('   [PASS] Request was blocked when budget exceeded');
      this.passCount++;
    } else {
      console.log('   [FAIL] Request was NOT blocked - budget enforcement not working!');
      this.failCount++;
      return;
    }

    // Test 2: BudgetInfo is present in response
    const budgetInfo = blockedResponse.budgetInfo as BudgetInfoFromResponse | undefined;
    if (budgetInfo) {
      console.log('   [PASS] BudgetInfo is included in blocked response');
      this.passCount++;

      // Test 3: BudgetInfo shows exceeded status
      if (budgetInfo.exceeded) {
        console.log('   [PASS] BudgetInfo.exceeded is true');
        this.passCount++;
      } else {
        console.log('   [FAIL] BudgetInfo.exceeded should be true');
        this.failCount++;
      }

      // Test 4: Percentage >= 100
      const percentage = budgetInfo.percentage || 0;
      if (percentage >= 100) {
        console.log(`   [PASS] BudgetInfo.percentage is ${percentage.toFixed(1)}% (>= 100%)`);
        this.passCount++;
      } else {
        console.log(`   [FAIL] BudgetInfo.percentage is ${percentage.toFixed(1)}% (expected >= 100%)`);
        this.failCount++;
      }

      // Test 5: Action is "block"
      const action = budgetInfo.action || '';
      if (action === 'block') {
        console.log("   [PASS] BudgetInfo.action is 'block'");
        this.passCount++;
      } else {
        console.log(`   [FAIL] BudgetInfo.action is '${action}' (expected 'block')`);
        this.failCount++;
      }
    } else {
      console.log('   [FAIL] BudgetInfo is missing from blocked response');
      this.failCount++;
    }

    // Test 6: Verify budget status via API
    try {
      const status = await this.client.getBudgetStatus(this.budgetId);
      if (status.isBlocked) {
        console.log('   [PASS] GetBudgetStatus confirms isBlocked=true');
        this.passCount++;
      } else if (status.isExceeded) {
        console.log('   [PASS] GetBudgetStatus confirms isExceeded=true');
        this.passCount++;
      } else {
        console.log('   [FAIL] GetBudgetStatus shows budget is not exceeded');
        this.failCount++;
      }
    } catch (e) {
      console.log(`   [FAIL] Could not get budget status: ${e}`);
      this.failCount++;
    }
  }

  private async cleanup(): Promise<void> {
    console.log();
    console.log('Step 4: Cleanup');
    console.log('-'.repeat(15));
    try {
      await this.client.deleteBudget(this.budgetId);
      console.log(`   Deleted budget: ${this.budgetId}`);
    } catch (e) {
      console.log(`   Warning: Failed to delete budget: ${e}`);
    }
  }

  private printSummary(): void {
    console.log();
    console.log('='.repeat(60));
    console.log(`Results: ${this.passCount} PASS, ${this.failCount} FAIL`);

    if (this.failCount === 0) {
      console.log('Budget enforcement is working correctly!');
    } else {
      console.log('Budget enforcement has issues - check the failures above.');
      process.exit(1);
    }
  }
}

// Run the test
const test = new EnforcementTest();
test.run().catch((e) => {
  console.error('Unexpected error:', e);
  process.exit(1);
});
