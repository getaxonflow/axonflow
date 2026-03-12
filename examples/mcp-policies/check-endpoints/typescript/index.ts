/**
 * MCP Policy Check Endpoints Example - TypeScript SDK
 *
 * Demonstrates standalone policy-check endpoints:
 * 1. check-input: Validate MCP requests against policies without executing
 * 2. check-output: Validate MCP response data against policies
 *
 * Run with: npx tsx index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';

const failures: string[] = [];

function assert(condition: boolean, message: string): void {
    if (!condition) {
        failures.push(message);
        console.log(`   FAIL: ${message}`);
    } else {
        console.log(`   PASS: ${message}`);
    }
}

async function main(): Promise<void> {
    console.log('MCP Policy Check Endpoints - TypeScript SDK');
    console.log('='.repeat(50));
    console.log();

    const client = new AxonFlow({
        endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
        clientId: process.env.AXONFLOW_CLIENT_ID || 'demo',
        clientSecret: process.env.AXONFLOW_CLIENT_SECRET || '',
        debug: process.env.AXONFLOW_DEBUG === 'true',
    });

    // ---------------------------------------------------------------
    // CHECK-INPUT TESTS
    // ---------------------------------------------------------------

    // Test 1: Clean SQL query passes
    console.log('Test 1: Check-Input — Clean SQL Query');
    console.log('--------------------------------------');
    let inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'SELECT name, department FROM employees WHERE id = 42',
        operation: 'query',
    });
    assert(inputResp.allowed === true, 'allowed = true');
    assert(inputResp.policies_evaluated > 0, `policies_evaluated = ${inputResp.policies_evaluated}`);
    console.log();

    // Test 2: SQL injection blocked
    console.log('Test 2: Check-Input — SQL Injection Blocked');
    console.log('--------------------------------------------');
    inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'SELECT * FROM users UNION SELECT username, password FROM admin_users--',
    });
    assert(inputResp.allowed === false, 'allowed = false');
    assert(!!inputResp.block_reason, `block_reason: ${inputResp.block_reason}`);
    console.log();

    // Test 3: Dangerous query blocked
    console.log('Test 3: Check-Input — Dangerous Query (DROP TABLE)');
    console.log('---------------------------------------------------');
    inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'SELECT * FROM users; DROP TABLE users--',
    });
    assert(inputResp.allowed === false, 'allowed = false');
    console.log();

    // ---------------------------------------------------------------
    // CHECK-INPUT: PARAMETER SCANNING (Issue #1287)
    // ---------------------------------------------------------------

    // Test 4: Clean parameterized query passes
    console.log('Test 4: Check-Input — Clean Parameterized Query');
    console.log('------------------------------------------------');
    inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'SELECT * FROM users WHERE id = $1',
        operation: 'query',
        parameters: { '1': 'usr-42' },
    });
    assert(inputResp.allowed === true, 'allowed = true');
    console.log();

    // Test 5: SQLi hidden in parameters — blocked
    console.log('Test 5: Check-Input — SQLi in Parameters');
    console.log('-----------------------------------------');
    inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'SELECT * FROM users WHERE id = $1',
        operation: 'query',
        parameters: { '1': '1 OR 1=1; DROP TABLE users--' },
    });
    assert(inputResp.allowed === false, 'allowed = false (SQLi detected in parameters)');
    assert(!!inputResp.block_reason, `block_reason: ${inputResp.block_reason}`);
    console.log();

    // Test 6: PII hidden in parameters — detected
    console.log('Test 6: Check-Input — PII in Parameters (SSN)');
    console.log('----------------------------------------------');
    inputResp = await client.mcpCheckInput({
        connectorType: 'postgres',
        statement: 'INSERT INTO contacts VALUES ($1, $2)',
        operation: 'execute',
        parameters: { '1': 'Alice', '2': '123-45-6789' },
    });
    // PII detection uses redact action (not block), so allowed=true but policies match
    console.log(`   allowed=${inputResp.allowed}, policies_evaluated=${inputResp.policies_evaluated}`);
    assert(inputResp.policies_evaluated > 0, 'PII policies evaluated for parameters');
    console.log();

    // ---------------------------------------------------------------
    // CHECK-OUTPUT TESTS
    // ---------------------------------------------------------------

    // Test 7: Clean response data passes
    console.log('Test 7: Check-Output — Clean Response Data');
    console.log('-------------------------------------------');
    let outputResp = await client.mcpCheckOutput({
        connectorType: 'postgres',
        responseData: [
            { id: 1, name: 'Alice Johnson', department: 'Engineering' },
            { id: 2, name: 'Bob Smith', department: 'Marketing' },
        ],
        rowCount: 2,
    });
    assert(outputResp.allowed === true, 'allowed = true');
    assert(outputResp.policies_evaluated > 0, `policies_evaluated = ${outputResp.policies_evaluated}`);
    console.log();

    // Test 8: PII in response — redacted
    console.log('Test 8: Check-Output — PII Redaction (SSN)');
    console.log('-------------------------------------------');
    outputResp = await client.mcpCheckOutput({
        connectorType: 'postgres',
        responseData: [
            { id: 1, name: 'Alice', ssn: '123-45-6789' },
            { id: 2, name: 'Bob', ssn: '987-65-4321' },
        ],
        rowCount: 2,
    });
    assert(outputResp.allowed === true, 'allowed = true (redacted, not blocked)');
    if (outputResp.redacted_data) {
        const redacted = JSON.stringify(outputResp.redacted_data);
        assert(!redacted.includes('123-45-6789'), 'SSN was redacted from response');
    }
    console.log();

    // Test 9: Execute-style response
    console.log('Test 9: Check-Output — Execute Response (Message)');
    console.log('--------------------------------------------------');
    outputResp = await client.mcpCheckOutput({
        connectorType: 'postgres',
        message: '3 rows updated',
        metadata: { query: "UPDATE users SET status = 'active' WHERE region = 'us'" },
    });
    assert(outputResp.allowed === true, 'allowed = true');
    console.log();

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    console.log('='.repeat(50));
    if (failures.length > 0) {
        console.log(`FAILED: ${failures.length} assertion(s) failed:`);
        for (const f of failures) {
            console.log(`  - ${f}`);
        }
        process.exit(1);
    }
    console.log('ALL TESTS PASSED');
}

main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
