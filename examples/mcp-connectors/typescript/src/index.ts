/**
 * AxonFlow MCP Connector Example - TypeScript
 *
 * Demonstrates how to query MCP (Model Context Protocol) connectors
 * through AxonFlow with policy governance.
 *
 * MCP connectors allow AI applications to securely interact with
 * external systems like GitHub, Salesforce, Jira, and more.
 *
 * Prerequisites:
 * - AxonFlow running with connectors enabled
 * - Connector installed and configured (e.g., GitHub connector)
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

  // Example 1: List GitHub Issues (requires GitHub connector)
  console.log('Example 1: Query GitHub Connector');
  console.log('-'.repeat(40));
  try {
    const response = await axonflow.queryConnector(
      'github',  // connector name
      'list open issues in the main repository',  // natural language query
      {
        repo: 'getaxonflow/axonflow',
        state: 'open',
        limit: 5,
      }
    );

    if (response.success) {
      console.log('Status: SUCCESS');
      console.log('Data:', JSON.stringify(response.data, null, 2).substring(0, 500));
    } else {
      console.log('Status: FAILED');
      console.log('Error:', response.error);
    }
  } catch (error) {
    // Connector not installed - expected for demo
    console.log('Status: Connector not available (expected if not installed)');
    console.log(`Error: ${error}`);
  }

  console.log();

  // Example 2: Search with Policy Check
  console.log('Example 2: Query with Policy Enforcement');
  console.log('-'.repeat(40));
  console.log('MCP queries are policy-checked before execution.');
  console.log('Queries that violate policies will be blocked.');

  try {
    // This demonstrates that even connector queries go through policy checks
    const response = await axonflow.queryConnector(
      'database',  // Example connector
      'SELECT * FROM users WHERE 1=1; DROP TABLE users;--',  // SQL injection attempt
      {}
    );
    console.log('Status: Query allowed');
    console.log('Response:', response);
  } catch (error: any) {
    if (error.message?.includes('blocked') || error.message?.includes('policy')) {
      console.log('Status: BLOCKED by policy (expected behavior)');
      console.log('Reason:', error.message);
    } else {
      console.log('Status: Connector not available');
      console.log(`Error: ${error.message}`);
    }
  }

  console.log();
  console.log('='.repeat(60));
  console.log('TypeScript MCP Connector Test: COMPLETE');
}

main().catch(console.error);
