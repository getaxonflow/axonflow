/**
 * Example 6: Multi-Step Approval Workflow - TypeScript
 *
 * Demonstrates a multi-level approval chain: Manager -> Director -> Finance
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
  console.log('Starting multi-step approval workflow for capital expenditure...\n');

  // Purchase request details
  const amount = 15000.0;
  const item = '10 Dell PowerEdge R750 servers for production deployment';

  // Track approval chain
  const approvalChain: { level: string; approved: boolean; hasReasoning: boolean }[] = [];
  let workflowTerminated = false;
  let terminationLevel = '';

  try {
    // Step 1: Manager Approval
    console.log(`Step 1: Requesting Manager approval for $${amount.toFixed(2)} purchase...`);
    const managerQuery = `As a manager, would you approve a purchase request for $${amount.toFixed(2)} to buy: ${item}? Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.`;

    const managerResp = await client.proxyLLMCall({
      userToken: 'user-123',
      query: managerQuery,
      requestType: 'chat',
      context: { model: 'gpt-4' },
    });

    console.log('Manager Response:', managerResp.data);

    // Assertions for manager response
    console.log('\n--- Manager Approval Assertions ---');
    assertCheck(managerResp !== null && managerResp !== undefined, 'Manager response exists');
    assertCheck(!managerResp.blocked, 'Manager request is not blocked');
    assertCheck(
      managerResp.data !== null && managerResp.data !== undefined,
      'Manager response has data'
    );

    const managerResult = JSON.stringify(managerResp.data);
    const managerApproved = managerResult.includes('APPROVED');
    const managerHasReasoning =
      managerResult.length > 20 &&
      (managerResult.toLowerCase().includes('reason') ||
        managerResult.toLowerCase().includes('because') ||
        managerResult.toLowerCase().includes('budget') ||
        managerResult.toLowerCase().includes('server'));

    approvalChain.push({
      level: 'Manager',
      approved: managerApproved,
      hasReasoning: managerHasReasoning,
    });

    assertCheck(
      managerResult.includes('APPROVED') || managerResult.includes('REJECTED'),
      'Manager response contains APPROVED or REJECTED decision'
    );
    assertCheck(managerHasReasoning, 'Manager response includes reasoning');

    if (!managerApproved) {
      workflowTerminated = true;
      terminationLevel = 'Manager';
      console.log('Purchase rejected at manager level');
      console.log('Workflow terminated');
    } else {
      console.log('Manager approval granted\n');

      // Step 2: Director Approval (for amounts > $10K)
      if (amount > 10000) {
        console.log('Step 2: Escalating to Director for amounts > $10,000...');
        const directorQuery = `As a Director, review this approved purchase: $${amount.toFixed(2)} for ${item}. Manager approved with reasoning: '${managerResp.data}'. Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.`;

        const directorResp = await client.proxyLLMCall({
          userToken: 'user-123',
          query: directorQuery,
          requestType: 'chat',
          context: { model: 'gpt-4' },
        });

        console.log('Director Response:', directorResp.data);

        // Assertions for director response
        console.log('\n--- Director Approval Assertions ---');
        assertCheck(directorResp !== null && directorResp !== undefined, 'Director response exists');
        assertCheck(!directorResp.blocked, 'Director request is not blocked');
        assertCheck(
          directorResp.data !== null && directorResp.data !== undefined,
          'Director response has data'
        );

        const directorResult = JSON.stringify(directorResp.data);
        const directorApproved = directorResult.includes('APPROVED');
        const directorHasReasoning =
          directorResult.length > 20 &&
          (directorResult.toLowerCase().includes('roi') ||
            directorResult.toLowerCase().includes('strategic') ||
            directorResult.toLowerCase().includes('reason') ||
            directorResult.toLowerCase().includes('approve'));

        approvalChain.push({
          level: 'Director',
          approved: directorApproved,
          hasReasoning: directorHasReasoning,
        });

        assertCheck(
          directorResult.includes('APPROVED') || directorResult.includes('REJECTED'),
          'Director response contains APPROVED or REJECTED decision'
        );
        assertCheck(directorHasReasoning, 'Director response includes reasoning');

        if (!directorApproved) {
          workflowTerminated = true;
          terminationLevel = 'Director';
          console.log('Purchase rejected at director level');
          console.log('Workflow terminated');
        } else {
          console.log('Director approval granted\n');
        }
      } else {
        console.log('Step 2: Director approval skipped (amount < $10,000)\n');
      }
    }

    // Step 3: Finance Approval (for amounts > $5K, only if not already terminated)
    if (!workflowTerminated && amount > 5000) {
      console.log('Step 3: Final Finance team compliance check...');
      const financeQuery = `As Finance team, perform final compliance check on approved purchase: $${amount.toFixed(2)} for ${item}. Verify budget availability and compliance with procurement policies. Respond with APPROVED or REJECTED and reasoning.`;

      const financeResp = await client.proxyLLMCall({
        userToken: 'user-123',
        query: financeQuery,
        requestType: 'chat',
        context: { model: 'gpt-4' },
      });

      console.log('Finance Response:', financeResp.data);

      // Assertions for finance response
      console.log('\n--- Finance Approval Assertions ---');
      assertCheck(financeResp !== null && financeResp !== undefined, 'Finance response exists');
      assertCheck(!financeResp.blocked, 'Finance request is not blocked');
      assertCheck(
        financeResp.data !== null && financeResp.data !== undefined,
        'Finance response has data'
      );

      const financeResult = JSON.stringify(financeResp.data);
      const financeApproved = financeResult.includes('APPROVED');
      const financeHasReasoning =
        financeResult.length > 20 &&
        (financeResult.toLowerCase().includes('budget') ||
          financeResult.toLowerCase().includes('compliance') ||
          financeResult.toLowerCase().includes('policy') ||
          financeResult.toLowerCase().includes('approve'));

      approvalChain.push({
        level: 'Finance',
        approved: financeApproved,
        hasReasoning: financeHasReasoning,
      });

      assertCheck(
        financeResult.includes('APPROVED') || financeResult.includes('REJECTED'),
        'Finance response contains APPROVED or REJECTED decision'
      );
      assertCheck(financeHasReasoning, 'Finance response includes reasoning');

      if (!financeApproved) {
        workflowTerminated = true;
        terminationLevel = 'Finance';
        console.log('Purchase rejected at finance level');
        console.log('Workflow terminated');
      } else {
        console.log('Finance approval granted\n');
      }
    }

    // Final workflow assertions
    console.log('\n--- Workflow Assertions ---');
    assertCheck(
      approvalChain.length >= 1,
      `At least one approval level executed (got ${approvalChain.length})`
    );

    if (!workflowTerminated) {
      // All approvals obtained
      console.log('='.repeat(60));
      console.log('Purchase Request FULLY APPROVED');
      console.log('='.repeat(60));
      console.log(`Amount: $${amount.toFixed(2)}`);
      console.log(`Item: ${item}`);

      const approvalSummary = approvalChain.map((a) => `${a.level} ${a.approved ? 'OK' : 'X'}`).join(' ');
      console.log(`Approvals: ${approvalSummary}\n`);

      // Validate full approval chain for $15K purchase
      assertCheck(
        approvalChain.length === 3,
        `All 3 approval levels executed for $15K purchase (got ${approvalChain.length})`
      );
      assertCheck(
        approvalChain.every((a) => a.approved),
        'All approval levels granted approval'
      );
      assertCheck(
        approvalChain.every((a) => a.hasReasoning),
        'All approval levels provided reasoning'
      );

      console.log('Workflow completed - Purchase can proceed');
    } else {
      // Workflow was terminated early
      assertCheck(terminationLevel !== '', `Workflow terminated at ${terminationLevel} level`);
      console.log(`\nWorkflow terminated at ${terminationLevel} level`);
    }

    console.log('Multi-step approval: Manager -> Director -> Finance');
  } catch (error) {
    console.error(`Approval workflow failed: ${error}`);
    process.exit(1);
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
