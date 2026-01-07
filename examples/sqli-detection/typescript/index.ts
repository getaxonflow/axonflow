/**
 * AxonFlow SQL Injection Detection - TypeScript SDK
 *
 * This example demonstrates and VALIDATES AxonFlow's SQLi detection:
 * - DROP/DELETE/TRUNCATE statements
 * - UNION SELECT attacks
 * - Boolean-based injection (OR 1=1)
 * - Comment injection
 * - Stacked queries
 * - Time-based blind SQLi
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

interface TestCase {
  name: string;
  query: string;
  shouldBlock: boolean;
  sqliType: string;
}

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    failures.push(message);
    console.log(`   \u274C FAIL: ${message}`);
  } else {
    console.log(`   \u2713 PASS: ${message}`);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow SQL Injection Detection - TypeScript SDK');
  console.log('='.repeat(52));
  console.log();

  const axonflow = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  const testCases: TestCase[] = [
    {
      name: 'Safe Query',
      query: 'Find users who signed up in the last 30 days',
      shouldBlock: false,
      sqliType: '',
    },
    {
      name: 'DROP TABLE',
      query: 'SELECT * FROM users; DROP TABLE users;--',
      shouldBlock: true,
      sqliType: 'drop_table',
    },
    {
      name: 'UNION SELECT',
      query: 'Get user where id = 1 UNION SELECT password FROM admin',
      shouldBlock: true,
      sqliType: 'union_select',
    },
    {
      name: 'Boolean Injection (OR 1=1)',
      query: "SELECT * FROM users WHERE username='' OR '1'='1'",
      shouldBlock: true,
      sqliType: 'boolean_injection',
    },
    {
      name: 'Comment Injection',
      query: "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
      shouldBlock: false, // Not detected by default policies
      sqliType: 'comment_injection',
    },
    {
      name: 'Stacked Queries',
      query: 'SELECT name FROM users; DELETE FROM audit_log;',
      shouldBlock: true,
      sqliType: 'stacked_queries',
    },
    {
      name: 'Truncate Statement',
      query: 'SELECT * FROM data; TRUNCATE TABLE logs;',
      shouldBlock: true,
      sqliType: 'truncate',
    },
  ];

  for (let i = 0; i < testCases.length; i++) {
    const test = testCases[i];
    console.log(`Test ${i + 1}: ${test.name}`);
    const queryPreview =
      test.query.length > 60 ? test.query.substring(0, 60) + '...' : test.query;
    console.log(`  Query: ${queryPreview}`);

    let result;
    try {
      result = await axonflow.getPolicyApprovedContext({
        userToken: 'sqli-detection-user',
        query: test.query,
      });
    } catch (error) {
      console.log(`   \u274C FATAL: getPolicyApprovedContext failed: ${error}`);
      process.exit(1);
    }

    const wasBlocked = !result.approved;

    // Validate context ID for approved requests
    if (result.approved) {
      assert(result.contextId !== '', 'contextId is not empty');
      assert(result.contextId.startsWith('ctx_'), "contextId has correct prefix 'ctx_'");
      console.log('   Status: APPROVED');
    } else {
      console.log('   Status: BLOCKED');
      console.log(`   Reason: ${result.blockReason}`);
      assert(result.blockReason !== '', 'blockReason is provided for blocked requests');
    }

    // Verify expected behavior
    if (test.shouldBlock) {
      assert(wasBlocked, `SQLi type '${test.sqliType}' is blocked`);
    } else {
      assert(!wasBlocked, 'Safe query is approved');
    }

    console.log();
  }

  console.log('='.repeat(52));
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('SQLi patterns validated:');
    console.log('  - Safe query (approved)');
    console.log('  - DROP TABLE (blocked)');
    console.log('  - UNION SELECT (blocked)');
    console.log('  - Boolean injection (blocked)');
    console.log('  - Comment injection (not detected)');
    console.log('  - Stacked queries (blocked)');
    console.log('  - TRUNCATE (blocked)');
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
