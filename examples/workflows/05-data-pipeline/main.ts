/**
 * Example 5: Data Pipeline Workflow - TypeScript
 *
 * Demonstrates a 5-stage data pipeline: Extract → Clean → Enrich → Aggregate → Report
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId,
    clientSecret,
  });

  console.log('Connected to AxonFlow');
  console.log('Starting 5-stage data pipeline for customer analytics...\n');

  const startTime = Date.now();
  const stageResults: { stage: string; success: boolean; hasData: boolean }[] = [];

  try {
    // Stage 1: Extract
    console.log('Stage 1/5: Extracting customer transaction data...');
    const extractResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: 'Extract customer purchase data from the last 30 days. Include customer ID, purchase amount, product categories, and timestamps. Simulate 500 customer transactions.',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    stageResults.push({
      stage: 'Extract',
      success: !extractResp.blocked,
      hasData: extractResp.data !== null && extractResp.data !== undefined,
    });
    console.log('Stage 1 complete: Data extracted\n');

    // Stage 2: Transform (Clean & Normalize)
    console.log('Stage 2/5: Cleaning and normalizing data...');
    const cleanResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: `From the extracted data above, perform the following transformations:
1. Remove duplicate transactions
2. Standardize date formats to ISO 8601
3. Normalize product category names
4. Validate all amounts are positive numbers
5. Flag any anomalies (unusually high amounts)`,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    stageResults.push({
      stage: 'Clean',
      success: !cleanResp.blocked,
      hasData: cleanResp.data !== null && cleanResp.data !== undefined,
    });
    console.log('Stage 2 complete: Data cleaned and normalized\n');

    // Stage 3: Enrich
    console.log('Stage 3/5: Enriching with customer segments and lifetime value...');
    const enrichResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: `Based on the cleaned transaction data:
1. Calculate customer lifetime value (CLV)
2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)
3. Identify top-spending product categories per segment
4. Calculate average order value per segment`,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    stageResults.push({
      stage: 'Enrich',
      success: !enrichResp.blocked,
      hasData: enrichResp.data !== null && enrichResp.data !== undefined,
    });
    console.log('Stage 3 complete: Data enriched with segments and metrics\n');

    // Stage 4: Aggregate
    console.log('Stage 4/5: Aggregating insights and trends...');
    const aggregateResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: `Generate aggregated insights:
1. Total revenue by customer segment
2. Growth trends (week-over-week)
3. Top 5 products by revenue
4. Customer churn risk indicators
5. Recommended actions for each segment`,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    stageResults.push({
      stage: 'Aggregate',
      success: !aggregateResp.blocked,
      hasData: aggregateResp.data !== null && aggregateResp.data !== undefined,
    });
    console.log('Stage 4 complete: Insights aggregated\n');

    // Stage 5: Report
    console.log('Stage 5/5: Generating executive summary report...');
    const reportResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: `Create an executive summary report with:
1. Key metrics (total revenue, customer count, avg order value)
2. Segment analysis
3. Top actionable recommendations
4. Risk alerts (if any)
Format as a concise business report.`,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    stageResults.push({
      stage: 'Report',
      success: !reportResp.blocked,
      hasData: reportResp.data !== null && reportResp.data !== undefined,
    });

    const duration = (Date.now() - startTime) / 1000;

    console.log('\nCUSTOMER ANALYTICS REPORT');
    console.log('='.repeat(60));
    console.log(reportResp.data);
    console.log('='.repeat(60));
    console.log();
    console.log(`Pipeline completed in ${duration.toFixed(1)} seconds`);

    // Assertions for all stages
    console.log('\n--- Pipeline Stage Assertions ---');
    assertCheck(stageResults.length === 5, `All 5 stages executed (got ${stageResults.length})`);

    for (const result of stageResults) {
      assertCheck(result.success, `Stage "${result.stage}" completed without blocking`);
      assertCheck(result.hasData, `Stage "${result.stage}" returned data`);
    }

    // Validate final report content
    console.log('\n--- Report Content Assertions ---');
    const reportText = JSON.stringify(reportResp.data).toLowerCase();
    assertCheck(
      reportText.includes('revenue') || reportText.includes('sales') || reportText.includes('total'),
      'Report contains revenue/sales metrics'
    );
    assertCheck(
      reportText.includes('customer') || reportText.includes('segment'),
      'Report contains customer/segment analysis'
    );
    assertCheck(
      reportText.includes('recommend') || reportText.includes('action') || reportText.includes('insight'),
      'Report contains recommendations or insights'
    );

    // Validate pipeline performance
    console.log('\n--- Performance Assertions ---');
    assertCheck(duration < 300, `Pipeline completed within 5 minutes (${duration.toFixed(1)}s)`);
    assertCheck(
      reportResp.requestId !== undefined && reportResp.requestId !== '',
      'Final response has request ID for tracing'
    );

    console.log('\nAll 5 stages executed successfully');
    console.log('Data pipeline: Extract -> Clean -> Enrich -> Aggregate -> Report');
  } catch (error) {
    console.error(`Pipeline failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
