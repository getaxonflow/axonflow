/**
 * AxonFlow Policy Management - Test Pattern
 *
 * This example demonstrates how to test regex patterns
 * before creating policies. This helps ensure your patterns
 * work correctly and catch the right inputs.
 */

import { AxonFlow } from '@axonflow/sdk';

async function main() {
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
  });

  console.log('AxonFlow Policy Management - Pattern Testing');
  console.log('='.repeat(60));

  try {
    // 1. Test a credit card pattern
    console.log('\n1. Testing credit card pattern...');

    const ccPattern = '\\b(?:\\d{4}[- ]?){3}\\d{4}\\b';
    const ccTestInputs = [
      '4111-1111-1111-1111',      // Valid Visa format with dashes
      '4111111111111111',          // Valid Visa format no dashes
      '4111 1111 1111 1111',       // Valid with spaces
      'not-a-card',                // Invalid
      '411111111111111',           // Too short (15 digits)
      '41111111111111111',         // Too long (17 digits)
      'My card is 5500-0000-0000-0004',  // Embedded in text
    ];

    const ccResult = await client.testPattern(ccPattern, ccTestInputs);

    console.log(`   Pattern: ${ccPattern}`);
    console.log(`   Valid regex: ${ccResult.valid}`);
    console.log('\n   Results:');

    ccResult.matches.forEach((match) => {
      const icon = match.matched ? '\u2713 MATCH' : '\u2717 no match';
      console.log(`   ${icon}  "${match.input}"`);
    });

    // 2. Test a US SSN pattern
    console.log('\n2. Testing US SSN pattern...');

    const ssnPattern = '\\b\\d{3}-\\d{2}-\\d{4}\\b';
    const ssnTestInputs = [
      '123-45-6789',               // Valid SSN format
      '000-00-0000',               // Valid format (but invalid SSN)
      'SSN: 987-65-4321',          // Embedded in text
      '123456789',                 // No dashes
      '12-345-6789',               // Wrong grouping
    ];

    const ssnResult = await client.testPattern(ssnPattern, ssnTestInputs);

    console.log(`   Pattern: ${ssnPattern}`);
    console.log('\n   Results:');

    ssnResult.matches.forEach((match) => {
      const icon = match.matched ? '\u2713 MATCH' : '\u2717 no match';
      console.log(`   ${icon}  "${match.input}"`);
    });

    // 3. Test an email pattern
    console.log('\n3. Testing email pattern...');

    const emailPattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}';
    const emailTestInputs = [
      'user@example.com',
      'first.last@company.org',
      'test+filter@gmail.com',
      'invalid-email',
      '@missing-local.com',
      'no-domain@',
    ];

    const emailResult = await client.testPattern(emailPattern, emailTestInputs);

    console.log(`   Pattern: ${emailPattern}`);
    console.log('\n   Results:');

    emailResult.matches.forEach((match) => {
      const icon = match.matched ? '\u2713 MATCH' : '\u2717 no match';
      console.log(`   ${icon}  "${match.input}"`);
    });

    // 4. Test SQL injection pattern
    console.log('\n4. Testing SQL injection pattern...');

    const sqliPattern = '(?i)\\b(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|drop\\s+table)\\b';
    const sqliTestInputs = [
      'SELECT * FROM users',
      'UNION SELECT password FROM admin',
      'DROP TABLE customers',
      'Normal user query',
      'My name is Robert',
      'INSERT INTO logs VALUES',
    ];

    const sqliResult = await client.testPattern(sqliPattern, sqliTestInputs);

    console.log(`   Pattern: ${sqliPattern.slice(0, 50)}...`);
    console.log('\n   Results:');

    sqliResult.matches.forEach((match) => {
      const icon = match.matched ? '\u2713 BLOCKED' : '\u2717 allowed';
      console.log(`   ${icon}  "${match.input}"`);
    });

    // 5. Test an invalid pattern
    console.log('\n5. Testing invalid pattern (error handling)...');

    try {
      const invalidPattern = '([unclosed';
      const invalidResult = await client.testPattern(invalidPattern, ['test']);

      if (!invalidResult.valid) {
        console.log(`   Pattern: ${invalidPattern}`);
        console.log(`   Valid: false`);
        console.log(`   Error: ${invalidResult.error}`);
      }
    } catch (e) {
      console.log('   Server rejected invalid pattern (expected)');
    }

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('Pattern Testing Summary');
    console.log('='.repeat(60));
    console.log(`
Best Practices:
  1. Always test patterns before creating policies
  2. Include edge cases in your test inputs
  3. Test with real-world examples from your domain
  4. Consider case sensitivity (use (?i) for case-insensitive)
  5. Use word boundaries (\\b) to avoid partial matches
`);

  } catch (error) {
    if (error instanceof Error) {
      console.error('\nError:', error.message);
    }
    process.exit(1);
  }
}

main();
