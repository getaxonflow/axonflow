/**
 * Example 5: Data Pipeline Workflow - TypeScript
 *
 * Demonstrates a 5-stage data pipeline: Extract → Clean → Enrich → Aggregate → Report
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY;

  if (!licenseKey) {
    console.error('❌ AXONFLOW_LICENSE_KEY must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    licenseKey: licenseKey,
  });

  console.log('✅ Connected to AxonFlow');
  console.log('🔄 Starting 5-stage data pipeline for customer analytics...\n');

  const startTime = Date.now();

  try {
    // Stage 1: Extract
    console.log('📥 Stage 1/5: Extracting customer transaction data...');
    await client.executeQuery({
      userToken: 'user-123',
      query: 'Extract customer purchase data from the last 30 days. Include customer ID, purchase amount, product categories, and timestamps. Simulate 500 customer transactions.',
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    console.log('✅ Stage 1 complete: Data extracted\n');

    // Stage 2: Transform (Clean & Normalize)
    console.log('🧹 Stage 2/5: Cleaning and normalizing data...');
    await client.executeQuery({
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
    console.log('✅ Stage 2 complete: Data cleaned and normalized\n');

    // Stage 3: Enrich
    console.log('💎 Stage 3/5: Enriching with customer segments and lifetime value...');
    await client.executeQuery({
      userToken: 'user-123',
      query: `Based on the cleaned transaction data:
1. Calculate customer lifetime value (CLV)
2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)
3. Identify top-spending product categories per segment
4. Calculate average order value per segment`,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });
    console.log('✅ Stage 3 complete: Data enriched with segments and metrics\n');

    // Stage 4: Aggregate
    console.log('📊 Stage 4/5: Aggregating insights and trends...');
    await client.executeQuery({
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
    console.log('✅ Stage 4 complete: Insights aggregated\n');

    // Stage 5: Report
    console.log('📈 Stage 5/5: Generating executive summary report...');
    const reportResp = await client.executeQuery({
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

    const duration = (Date.now() - startTime) / 1000;

    console.log('\n📊 CUSTOMER ANALYTICS REPORT');
    console.log('='.repeat(60));
    console.log(reportResp.data);
    console.log('='.repeat(60));
    console.log();
    console.log(`⏱️  Pipeline completed in ${duration.toFixed(1)} seconds`);
    console.log('✅ All 5 stages executed successfully');
    console.log('💡 Data pipeline: Extract → Clean → Enrich → Aggregate → Report');
  } catch (error) {
    console.error(`❌ Pipeline failed: ${error}`);
    process.exit(1);
  }
}

main();
