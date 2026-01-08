/**
 * Example 6: Multi-Step Approval Workflow - TypeScript
 *
 * Demonstrates a multi-level approval chain: Manager → Director → Finance
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const agentUrl = process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set');
    process.exit(1);
  }

  const client = new AxonFlow({
    endpoint: agentUrl,
    clientId,
    clientSecret,
  });

  console.log('✅ Connected to AxonFlow');
  console.log('🔐 Starting multi-step approval workflow for capital expenditure...\n');

  // Purchase request details
  const amount = 15000.0;
  const item = '10 Dell PowerEdge R750 servers for production deployment';

  try {
    // Step 1: Manager Approval
    console.log(`📤 Step 1: Requesting Manager approval for $${amount.toFixed(2)} purchase...`);
    const managerQuery = `As a manager, would you approve a purchase request for $${amount.toFixed(2)} to buy: ${item}? Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.`;

    const managerResp = await client.executeQuery({
      userToken: 'user-123',
      query: managerQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    console.log('📥 Manager Response:', managerResp.data);

    const managerResult = JSON.stringify(managerResp.data);
    if (!managerResult.includes('APPROVED')) {
      console.log('❌ Purchase rejected at manager level');
      console.log('Workflow terminated');
      return;
    }

    console.log('✅ Manager approval granted\n');

    // Step 2: Director Approval (for amounts > $10K)
    if (amount > 10000) {
      console.log('📤 Step 2: Escalating to Director for amounts > $10,000...');
      const directorQuery = `As a Director, review this approved purchase: $${amount.toFixed(2)} for ${item}. Manager approved with reasoning: '${managerResp.data}'. Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.`;

      const directorResp = await client.executeQuery({
        userToken: 'user-123',
        query: directorQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      console.log('📥 Director Response:', directorResp.data);

      const directorResult = JSON.stringify(directorResp.data);
      if (!directorResult.includes('APPROVED')) {
        console.log('❌ Purchase rejected at director level');
        console.log('Workflow terminated');
        return;
      }

      console.log('✅ Director approval granted\n');
    } else {
      console.log('ℹ️  Step 2: Director approval skipped (amount < $10,000)\n');
    }

    // Step 3: Finance Approval (for amounts > $5K)
    if (amount > 5000) {
      console.log('📤 Step 3: Final Finance team compliance check...');
      const financeQuery = `As Finance team, perform final compliance check on approved purchase: $${amount.toFixed(2)} for ${item}. Verify budget availability and compliance with procurement policies. Respond with APPROVED or REJECTED and reasoning.`;

      const financeResp = await client.executeQuery({
        userToken: 'user-123',
        query: financeQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      console.log('📥 Finance Response:', financeResp.data);

      const financeResult = JSON.stringify(financeResp.data);
      if (!financeResult.includes('APPROVED')) {
        console.log('❌ Purchase rejected at finance level');
        console.log('Workflow terminated');
        return;
      }

      console.log('✅ Finance approval granted\n');
    }

    // All approvals obtained
    console.log('='.repeat(60));
    console.log('🎉 Purchase Request FULLY APPROVED');
    console.log('='.repeat(60));
    console.log(`Amount: $${amount.toFixed(2)}`);
    console.log(`Item: ${item}`);
    console.log('Approvals: Manager ✅ Director ✅ Finance ✅\n');
    console.log('✅ Workflow completed - Purchase can proceed');
    console.log('💡 Multi-step approval: Manager → Director → Finance');
  } catch (error) {
    console.error(`❌ Approval workflow failed: ${error}`);
    process.exit(1);
  }
}

main();
