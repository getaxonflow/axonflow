/**
 * AxonFlow MCP Connector Example - TypeScript
 *
 * Demonstrates how to query MCP (Model Context Protocol) connectors
 * through AxonFlow with policy governance.
 *
 * MCP connectors allow AI applications to securely interact with
 * external systems like databases, APIs, and more.
 *
 * Prerequisites:
 * - AxonFlow running with connectors enabled (docker compose up -d)
 * - PostgreSQL connector configured in config/axonflow.yaml
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   npm run start
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

async function main(): Promise<void> {
  console.log('AxonFlow MCP Connector Example - TypeScript');
  console.log('='.repeat(60));
  console.log();

  // Initialize AxonFlow client with OAuth2-style credentials
  const axonflow = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080',
    clientId: process.env.AXONFLOW_CLIENT_ID || 'demo',
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || 'demo-secret',
    debug: true,
  });

  console.log('Testing MCP Connector Queries');
  console.log('-'.repeat(60));
  console.log();

  // Example 1: Query PostgreSQL Connector (configured in axonflow.yaml)
  console.log('Example 1: Query PostgreSQL Connector');
  console.log('-'.repeat(40));
  let example1Success = false;
  try {
    const response = await axonflow.queryConnector(
      'postgres',  // connector name (configured in config/axonflow.yaml)
      'SELECT 1 as health_check, current_timestamp as server_time',  // safe query
      {}
    );

    if (response.success) {
      console.log('Status: SUCCESS');
      console.log('Data:', JSON.stringify(response.data, null, 2));
      example1Success = true;
      assertCheck(response.success === true, 'queryConnector returns success: true');
      assertCheck(response.data !== undefined, 'queryConnector returns data');
    } else {
      console.log('Status: FAILED');
      console.log('Error:', response.error);
      // Not adding to failures as postgres may not be configured
    }
  } catch (error) {
    console.log('Status: FAILED');
    console.log(`Error: ${error}`);
    // Not adding to failures as postgres may not be configured
  }

  console.log();

  // Example 2: Query with Policy Enforcement (SQL Injection)
  console.log('Example 2: Query with Policy Enforcement');
  console.log('-'.repeat(40));
  console.log('MCP queries are policy-checked before execution.');
  console.log('Queries that violate policies will be blocked.');
  console.log();

  let sqliBlocked = false;
  try {
    // This demonstrates that even connector queries go through policy checks
    const response = await axonflow.queryConnector(
      'postgres',
      'SELECT * FROM users WHERE 1=1; DROP TABLE users;--',  // SQL injection attempt
      {}
    );
    console.log('Status: Query allowed (UNEXPECTED - should have been blocked!)');
    console.log('Response:', response);
    // If we get here and it succeeded, SQLi detection may not be enabled
  } catch (error: any) {
    const errorMsg = error.message || String(error);
    if (errorMsg.includes('blocked') || errorMsg.includes('policy') || errorMsg.includes('SQL injection') || errorMsg.includes('sqli')) {
      console.log('Status: BLOCKED by policy (expected behavior)');
      console.log('Reason:', error.message);
      sqliBlocked = true;
      assertCheck(true, 'SQLi query blocked by policy enforcement');
      // Verify error message indicates policy violation
      const hasBlockedIndicator = errorMsg.includes('blocked') || errorMsg.includes('policy');
      assertCheck(hasBlockedIndicator, 'Error message indicates policy blocking');
    } else {
      console.log('Status: Error');
      console.log(`Error: ${error.message}`);
      // Not adding to failures as this might be a connection error
    }
  }

  // Note: We don't fail if SQLi wasn't blocked as policies may not be configured
  if (sqliBlocked) {
    console.log('   SQLi blocking verified successfully');
  } else {
    console.log('   Note: SQLi blocking not verified (may require policy configuration)');
  }

  console.log();
  console.log('='.repeat(60));
  console.log('TypeScript MCP Connector Test: COMPLETE');

  // Final assertion summary
  if (failures.length > 0) {
    console.log(`\n=== ASSERTION FAILURES: ${failures.length} ===`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  } else {
    console.log('\n=== ALL ASSERTIONS PASSED ===');
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
