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
 * - AxonFlow running with connectors enabled (docker-compose up -d)
 * - PostgreSQL connector configured in config/axonflow.yaml
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   npm run start
 */

import { AxonFlow } from '@axonflow/sdk';

async function main(): Promise<void> {
  console.log('AxonFlow MCP Connector Example - TypeScript');
  console.log('='.repeat(60));
  console.log();

  // Initialize AxonFlow client
  const axonflow = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || 'http://localhost:8080',
    licenseKey: process.env.AXONFLOW_LICENSE_KEY || '',
    tenant: process.env.AXONFLOW_TENANT || 'demo',
    debug: true,
  });

  console.log('Testing MCP Connector Queries');
  console.log('-'.repeat(60));
  console.log();

  // Example 1: Query PostgreSQL Connector (configured in axonflow.yaml)
  console.log('Example 1: Query PostgreSQL Connector');
  console.log('-'.repeat(40));
  try {
    const response = await axonflow.queryConnector(
      'postgres',  // connector name (configured in config/axonflow.yaml)
      'SELECT 1 as health_check, current_timestamp as server_time',  // safe query
      {}
    );

    if (response.success) {
      console.log('Status: SUCCESS');
      console.log('Data:', JSON.stringify(response.data, null, 2));
    } else {
      console.log('Status: FAILED');
      console.log('Error:', response.error);
    }
  } catch (error) {
    console.log('Status: FAILED');
    console.log(`Error: ${error}`);
  }

  console.log();

  // Example 2: Query with Policy Enforcement (SQL Injection)
  console.log('Example 2: Query with Policy Enforcement');
  console.log('-'.repeat(40));
  console.log('MCP queries are policy-checked before execution.');
  console.log('Queries that violate policies will be blocked.');
  console.log();

  try {
    // This demonstrates that even connector queries go through policy checks
    const response = await axonflow.queryConnector(
      'postgres',
      'SELECT * FROM users WHERE 1=1; DROP TABLE users;--',  // SQL injection attempt
      {}
    );
    console.log('Status: Query allowed (UNEXPECTED - should have been blocked!)');
    console.log('Response:', response);
  } catch (error: any) {
    if (error.message?.includes('blocked') || error.message?.includes('policy') || error.message?.includes('SQL injection')) {
      console.log('Status: BLOCKED by policy (expected behavior)');
      console.log('Reason:', error.message);
    } else {
      console.log('Status: Error');
      console.log(`Error: ${error.message}`);
    }
  }

  console.log();
  console.log('='.repeat(60));
  console.log('TypeScript MCP Connector Test: COMPLETE');
}

main().catch(console.error);
