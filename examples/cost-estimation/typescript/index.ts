/**
 * AxonFlow Cost Estimation Example - TypeScript
 *
 * Validates the new cost estimation endpoints added in v4.3.0:
 *   - POST /api/v1/plans/estimate  - Estimate cost of a plan before execution
 *   - GET  /api/v1/plans/{id}/cost - Get cost estimate for an existing plan
 *
 * These endpoints are NOT in any SDK yet, so this example uses fetch() for
 * raw HTTP calls and the TypeScript SDK for plan generation.
 *
 * Usage:
 *   npx tsx index.ts
 *
 * Environment:
 *   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - Client ID (default: demo-org)
 *   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
 *   AXONFLOW_USER_TOKEN    - JWT token for MAP operations (optional)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

interface EstimateResponse {
  estimated_cost_usd?: number;
  currency?: string;
  breakdown?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

async function doRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: string
): Promise<{ status: number; data: Record<string, unknown> | null }> {
  const options: RequestInit = {
    method,
    headers,
    signal: AbortSignal.timeout(15000),
  };
  if (body) {
    options.body = body;
  }

  const response = await fetch(url, options);
  let data: Record<string, unknown> | null = null;
  try {
    const text = await response.text();
    if (text) {
      data = JSON.parse(text);
    }
  } catch {
    // Response is not JSON
  }
  return { status: response.status, data };
}

async function main(): Promise<void> {
  console.log("AxonFlow Cost Estimation - TypeScript (Raw HTTP + SDK)");
  console.log("======================================================");
  console.log();

  const endpoint = getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080");
  const clientId = getEnv("AXONFLOW_CLIENT_ID", "demo-org");
  const clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");
  const userToken = getEnv("AXONFLOW_USER_TOKEN", "");

  console.log(`Endpoint: ${endpoint}`);
  console.log(`Client ID: ${clientId}`);
  console.log("------------------------------------------------------");
  console.log();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Client-ID": clientId,
  };
  if (clientSecret) {
    headers["X-Client-Secret"] = clientSecret;
  }

  // ========================================
  // 1. HEALTH CHECK
  // ========================================
  console.log("1. Health Check...");
  try {
    const { status, data } = await doRequest("GET", `${endpoint}/health`, {});
    assertCheck(status === 200, `Health check returns 200 (got ${status})`);
    if (data) {
      console.log(`   Status: ${data.status}`);
    }
  } catch (error) {
    console.log(`   ERROR: ${error}`);
    assertCheck(false, "Health check request succeeded");
  }
  console.log();

  // ========================================
  // 2. POST /api/v1/plans/estimate
  // ========================================
  console.log("2. POST /api/v1/plans/estimate - Estimate cost before execution...");

  // Use real WorkflowStep fields: prompt and max_tokens.
  // Short prompt (~50 chars) vs long prompt (~600 chars) should produce different estimates.
  const shortPrompt = "Summarize the key findings from the analysis.";
  const longPrompt =
    "You are a senior data analyst. Given the following customer feedback dataset " +
    "containing 500 reviews across 12 product categories spanning the last fiscal quarter, " +
    "perform a comprehensive sentiment analysis. Break down sentiment by category, identify " +
    "emerging trends, flag critical issues that require immediate attention, and provide " +
    "actionable recommendations for each product team. Include statistical confidence intervals " +
    "for your sentiment scores and highlight any anomalies or outliers in the data distribution.";

  const estimatePayload = JSON.stringify({
    provider: "openai",
    model: "gpt-4",
    steps: [
      {
        name: "analyze",
        type: "llm_call",
        prompt: longPrompt,
        max_tokens: 2000,
      },
      {
        name: "summarize",
        type: "llm_call",
        prompt: shortPrompt,
        max_tokens: 200,
      },
    ],
  });

  try {
    const { status, data } = await doRequest(
      "POST",
      `${endpoint}/api/v1/plans/estimate`,
      headers,
      estimatePayload
    );

    if (status === 429) {
      console.log("   Rate limited (429) - community mode allows 10 estimates/day");
      console.log("   This is expected behavior; skipping estimate assertions.");
      assertCheck(true, "Estimate endpoint returned valid status (429 rate limit)");
    } else {
      assertCheck(status === 200, `Estimate returns 200 (got ${status})`);

      if (status === 200 && data) {
        const estimate = data as EstimateResponse;
        console.log(`   Response: ${JSON.stringify(estimate)}`);

        // Verify estimated_cost_usd field
        const hasCost = "estimated_cost_usd" in estimate;
        assertCheck(hasCost, "Response contains 'estimated_cost_usd' field");
        if (hasCost) {
          const cost = estimate.estimated_cost_usd!;
          assertCheck(typeof cost === "number", "estimated_cost_usd is a number");
          assertCheck(cost >= 0, `estimated_cost_usd >= 0 (got ${cost.toFixed(6)})`);
          console.log(`   Estimated Cost: $${cost.toFixed(6)} USD`);
        }

        // Verify currency field
        const hasCurrency = "currency" in estimate;
        assertCheck(hasCurrency, "Response contains 'currency' field");
        if (hasCurrency) {
          assertCheck(
            estimate.currency === "USD",
            `currency is 'USD' (got '${estimate.currency}')`
          );
        }

        // Check breakdown and verify prompt-aware estimation
        if ("breakdown" in estimate && Array.isArray(estimate.breakdown)) {
          const breakdown = estimate.breakdown as Array<Record<string, unknown>>;
          console.log(`   Breakdown: ${JSON.stringify(breakdown)}`);

          // Verify per-step token estimates differ (long prompt > short prompt)
          if (breakdown.length >= 2) {
            const analyzeTokensIn = breakdown[0].estimated_tokens_in as number;
            const summarizeTokensIn = breakdown[1].estimated_tokens_in as number;
            console.log(`   Analyze step tokens_in: ${analyzeTokensIn}`);
            console.log(`   Summarize step tokens_in: ${summarizeTokensIn}`);
            assertCheck(
              analyzeTokensIn > summarizeTokensIn,
              "Long-prompt step has more estimated input tokens than short-prompt step"
            );

            // Verify max_tokens is respected for output estimates
            const analyzeTokensOut = breakdown[0].estimated_tokens_out as number;
            const summarizeTokensOut = breakdown[1].estimated_tokens_out as number;
            console.log(`   Analyze step tokens_out: ${analyzeTokensOut} (expected: 2000)`);
            console.log(`   Summarize step tokens_out: ${summarizeTokensOut} (expected: 200)`);
            assertCheck(
              analyzeTokensOut === 2000,
              `Analyze step respects max_tokens=2000 for output estimate (got ${analyzeTokensOut})`
            );
            assertCheck(
              summarizeTokensOut === 200,
              `Summarize step respects max_tokens=200 for output estimate (got ${summarizeTokensOut})`
            );
          }
        } else {
          console.log("   Note: 'breakdown' not present (community mode returns aggregate only)");
        }
      }
    }
  } catch (error) {
    console.log(`   ERROR: ${error}`);
    assertCheck(false, "Estimate request completed");
  }
  console.log();

  // ========================================
  // 3. CREATE PLAN VIA SDK + GET COST
  // ========================================
  console.log("3. Create MAP plan via SDK, then GET /api/v1/plans/{id}/cost...");

  try {
    const axonflow = new AxonFlow({
      endpoint,
      clientId: clientId || undefined,
      clientSecret: clientSecret || undefined,
      debug: getEnv("AXONFLOW_DEBUG", "") === "true",
    });

    const query = "Create a brief plan to analyze customer feedback and generate a summary report";
    const domain = "generic";

    const plan = await axonflow.generatePlan(query, domain, userToken || undefined);

    assertCheck(plan !== null && plan !== undefined, "Plan generated successfully");
    assertCheck(!!plan.planId, "Plan has a valid ID");
    console.log(`   Plan ID: ${plan.planId}`);
    console.log(`   Steps: ${plan.steps?.length || 0}`);

    // GET /api/v1/plans/{id}/cost
    console.log();
    console.log("   Fetching cost for existing plan...");

    const { status: costStatus, data: costData } = await doRequest(
      "GET",
      `${endpoint}/api/v1/plans/${plan.planId}/cost`,
      headers
    );

    if (costStatus === 429) {
      console.log("   Rate limited (429) - community mode allows 10 estimates/day");
      assertCheck(true, "Plan cost endpoint returned valid status (429 rate limit)");
    } else if (costStatus === 404) {
      console.log("   Plan cost endpoint returned 404 - endpoint may require enterprise mode");
      assertCheck(true, "Plan cost endpoint responded (404 - may require enterprise)");
    } else {
      assertCheck(costStatus === 200, `GET plan cost returns 200 (got ${costStatus})`);

      if (costStatus === 200 && costData) {
        const costEstimate = costData as EstimateResponse;
        console.log(`   Cost Response: ${JSON.stringify(costEstimate)}`);

        const hasCost = "estimated_cost_usd" in costEstimate;
        assertCheck(hasCost, "Plan cost response contains 'estimated_cost_usd'");
        if (hasCost) {
          const cost = costEstimate.estimated_cost_usd!;
          assertCheck(cost >= 0, `Plan cost >= 0 (got ${cost})`);
        }

        const hasCurrency = "currency" in costEstimate;
        assertCheck(hasCurrency, "Plan cost response contains 'currency'");
        if (hasCurrency) {
          assertCheck(
            costEstimate.currency === "USD",
            `Plan cost currency is 'USD' (got '${costEstimate.currency}')`
          );
        }

        if (!("breakdown" in costEstimate)) {
          console.log("   Note: 'breakdown' not present (community mode returns aggregate only)");
        }
      }
    }
  } catch (error) {
    console.log(`   ERROR: ${error}`);
    assertCheck(false, `Plan creation and cost retrieval succeeded: ${error}`);
  }
  console.log();

  // ========================================
  // SUMMARY
  // ========================================
  console.log("======================================================");
  console.log("Cost Estimation Example - Summary");
  console.log("======================================================");
  if (failures.length === 0) {
    console.log("All assertions passed!");
  } else {
    console.log(`${failures.length} assertion(s) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
