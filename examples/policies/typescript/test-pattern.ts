/**
 * AxonFlow Policy Management - Test Pattern
 *
 * This example demonstrates how to test regex patterns
 * before creating policies. This helps ensure your patterns
 * work correctly and catch the right inputs.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

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

    assertCheck(ccResult.valid === true, 'Credit card pattern is valid regex');
    assertCheck(ccResult.matches.length === 7, 'All 7 credit card test inputs were evaluated');
    // Valid formats should match
    assertCheck(ccResult.matches[0].matched === true, '4111-1111-1111-1111 (dashes) matches');
    assertCheck(ccResult.matches[1].matched === true, '4111111111111111 (no dashes) matches');
    assertCheck(ccResult.matches[2].matched === true, '4111 1111 1111 1111 (spaces) matches');
    // Invalid formats should not match
    assertCheck(ccResult.matches[3].matched === false, 'not-a-card does not match');
    assertCheck(ccResult.matches[4].matched === false, '15-digit number does not match');
    assertCheck(ccResult.matches[5].matched === false, '17-digit number does not match');
    // Embedded card should match
    assertCheck(ccResult.matches[6].matched === true, 'Embedded card in text matches');

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

    assertCheck(ssnResult.valid === true, 'SSN pattern is valid regex');
    assertCheck(ssnResult.matches.length === 5, 'All 5 SSN test inputs were evaluated');
    assertCheck(ssnResult.matches[0].matched === true, '123-45-6789 matches SSN pattern');
    assertCheck(ssnResult.matches[1].matched === true, '000-00-0000 matches SSN format');
    assertCheck(ssnResult.matches[2].matched === true, 'Embedded SSN in text matches');
    assertCheck(ssnResult.matches[3].matched === false, 'No-dashes SSN does not match');
    assertCheck(ssnResult.matches[4].matched === false, 'Wrong grouping does not match');

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

    assertCheck(emailResult.valid === true, 'Email pattern is valid regex');
    assertCheck(emailResult.matches.length === 6, 'All 6 email test inputs were evaluated');
    assertCheck(emailResult.matches[0].matched === true, 'user@example.com matches');
    assertCheck(emailResult.matches[1].matched === true, 'first.last@company.org matches');
    assertCheck(emailResult.matches[2].matched === true, 'test+filter@gmail.com matches');
    assertCheck(emailResult.matches[3].matched === false, 'invalid-email does not match');
    assertCheck(emailResult.matches[4].matched === false, '@missing-local.com does not match');
    assertCheck(emailResult.matches[5].matched === false, 'no-domain@ does not match');

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

    assertCheck(sqliResult.valid === true, 'SQL injection pattern is valid regex');
    assertCheck(sqliResult.matches.length === 6, 'All 6 SQLi test inputs were evaluated');
    // SQL injection patterns should be detected
    assertCheck(sqliResult.matches[0].matched === true, 'SELECT * FROM detected as SQLi');
    assertCheck(sqliResult.matches[1].matched === true, 'UNION SELECT detected as SQLi');
    assertCheck(sqliResult.matches[2].matched === true, 'DROP TABLE detected as SQLi');
    // Normal inputs should not be blocked
    assertCheck(sqliResult.matches[3].matched === false, 'Normal query is allowed');
    assertCheck(sqliResult.matches[4].matched === false, 'Regular name is allowed');
    assertCheck(sqliResult.matches[5].matched === true, 'INSERT INTO detected as SQLi');

    // 5. Test an invalid pattern
    console.log('\n5. Testing invalid pattern (error handling)...');

    let invalidHandledCorrectly = false;
    try {
      const invalidPattern = '([unclosed';
      const invalidResult = await client.testPattern(invalidPattern, ['test']);

      if (!invalidResult.valid) {
        console.log(`   Pattern: ${invalidPattern}`);
        console.log(`   Valid: false`);
        console.log(`   Error: ${invalidResult.error}`);
        invalidHandledCorrectly = true;
        assertCheck(invalidResult.valid === false, 'Invalid pattern returns valid=false');
        assertCheck(typeof invalidResult.error === 'string', 'Invalid pattern returns error message');
      }
    } catch (e) {
      console.log('   Server rejected invalid pattern (expected)');
      invalidHandledCorrectly = true;
    }
    assertCheck(invalidHandledCorrectly, 'Invalid regex pattern is properly handled');

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
    failures.push(`Unexpected error: ${error instanceof Error ? error.message : error}`);
  }

  // Final assertion summary
  console.log('='.repeat(60));
  console.log('Assertion Summary');
  console.log('='.repeat(60));
  if (failures.length === 0) {
    console.log('All assertions passed!');
  } else {
    console.log(`${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
