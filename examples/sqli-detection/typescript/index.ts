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
 * Expected outcome (v11): the stored policy action decides. Every shipped
 * sys_sqli_* policy stores action "warn", so a detected SQLi pattern is APPROVED
 * and the matched sys_sqli_* policy id is returned in `policies` - the detection
 * signal. It is not blocked. To block SQL injection, record an organization
 * override of category "sqli" with action "block"
 * (PUT /api/v1/detection-posture/sqli on the customer portal API, Enterprise) or
 * change the policy's action. This example validates the shipped actions with no
 * override recorded; against an org with sqli=block it fails loudly.
 * The SQLI_ACTION environment variable no longer sets an action.
 *
 * Run with: npx ts-node index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

interface TestCase {
  name: string;
  query: string;
  expectDetected: boolean;
  sqliType: string;
}

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function sqliPolicies(policies: string[] | undefined): string[] {
  return (policies ?? []).filter((p) => p.startsWith('sys_sqli_'));
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
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
      expectDetected: false,
      sqliType: '',
    },
    {
      name: 'DROP TABLE',
      query: 'SELECT * FROM users; DROP TABLE users;--',
      expectDetected: true,
      sqliType: 'drop_table',
    },
    {
      name: 'UNION SELECT',
      query: 'Get user where id = 1 UNION SELECT password FROM admin',
      expectDetected: true,
      sqliType: 'union_select',
    },
    {
      name: 'Boolean Injection (OR 1=1)',
      query: "SELECT * FROM users WHERE username='' OR '1'='1'",
      expectDetected: true,
      sqliType: 'boolean_injection',
    },
    {
      name: 'Comment Injection',
      query: "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
      expectDetected: false, // Not detected by default policies
      sqliType: 'comment_injection',
    },
    {
      name: 'Stacked Queries',
      query: 'SELECT name FROM users; DELETE FROM audit_log;',
      expectDetected: true,
      sqliType: 'stacked_queries',
    },
    {
      name: 'Truncate Statement',
      query: 'SELECT * FROM data; TRUNCATE TABLE logs;',
      expectDetected: true,
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
        userToken: getEnv('AXONFLOW_USER_TOKEN', 'sqli-detection-user'),
        query: test.query,
      });
    } catch (error) {
      console.log(`   \u274C FATAL: getPolicyApprovedContext failed: ${error}`);
      process.exit(1);
    }

    const detected = sqliPolicies(result.policies);

    // Validate context ID for approved requests (UUID format)
    if (result.approved) {
      assertCheck(result.contextId !== '', 'contextId is not empty');
      if (detected.length > 0) {
        console.log(`   Status: APPROVED - SQLi WARNED (${detected.join(', ')})`);
      } else {
        console.log('   Status: APPROVED');
      }
    } else {
      console.log('   Status: BLOCKED');
      console.log(`   Reason: ${result.blockReason}`);
      console.log(
        '   (the shipped sys_sqli_* action is warn; a block means an org sqli=block override or an edited policy action)'
      );
    }

    // Verify expected behavior: the stored "warn" action approves the request
    if (test.expectDetected) {
      assertCheck(result.approved, `SQLi type '${test.sqliType}' is approved with a warning (stored action: warn)`);
      assertCheck(detected.length > 0, `SQLi type '${test.sqliType}' is detected (sys_sqli_* policy matched)`);
    } else if (test.sqliType === '') {
      assertCheck(result.approved, 'Safe query is approved');
      assertCheck(detected.length === 0, 'Safe query matches no sys_sqli_* policy');
    } else {
      assertCheck(result.approved, `SQLi type '${test.sqliType}' is approved`);
    }

    console.log();
  }

  console.log('='.repeat(52));
  if (failures.length === 0) {
    console.log('\u2713 ALL TESTS PASSED');
    console.log();
    console.log('SQLi patterns validated:');
    console.log('  - Safe query (approved)');
    console.log('  - DROP TABLE (detected, warned)');
    console.log('  - UNION SELECT (detected, warned)');
    console.log('  - Boolean injection (detected, warned)');
    console.log('  - Comment injection (not detected)');
    console.log('  - Stacked queries (detected, warned)');
    console.log('  - TRUNCATE (detected, warned)');
    console.log();
    console.log('SQL injection warns by default. To block it, record an org override');
    console.log('sqli=block or change the policy action.');
  } else {
    console.log(`\u274C ${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => {
      console.log(`   - ${f}`);
    });
    process.exit(1);
  }
}

main();
