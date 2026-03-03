/**
 * Version Discovery Example - TypeScript SDK
 *
 * Demonstrates SDK-platform version discovery:
 * 1. healthCheck() returns platform version and capabilities
 * 2. AxonFlow.hasCapability() checks for specific platform features
 * 3. SDK version mismatch warnings
 *
 * Run with: npx tsx index.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow, VERSION } from '@axonflow/sdk';

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
    console.log('Version Discovery — TypeScript SDK');
    console.log('==================================');
    console.log();

    const client = new AxonFlow({
        endpoint: process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080',
        clientId: process.env.AXONFLOW_CLIENT_ID || 'demo',
        clientSecret: process.env.AXONFLOW_CLIENT_SECRET || '',
        debug: process.env.AXONFLOW_DEBUG === 'true',
    });

    // ---------------------------------------------------------------
    // Test 1: healthCheck returns version and capabilities
    // ---------------------------------------------------------------
    console.log('Test 1: healthCheck — Version and Capabilities');
    console.log('-----------------------------------------------');

    const health = await client.healthCheck();

    console.log(`   Platform version: ${health.version}`);
    console.log(`   Status: ${health.status}`);
    console.log(`   Capabilities: ${health.capabilities?.length ?? 0}`);

    assert(health.version !== undefined && health.version !== '', 'version is non-empty');
    assert(health.status === 'healthy' || health.status === 'starting', 'status is healthy or starting');
    assert(health.capabilities !== undefined && health.capabilities.length > 0, 'capabilities list is non-empty');
    assert(health.sdkCompatibility !== undefined, 'sdkCompatibility is present');

    if (health.sdkCompatibility) {
        console.log(`   Min SDK: ${health.sdkCompatibility.minSdkVersion}`);
        console.log(`   Recommended SDK: ${health.sdkCompatibility.recommendedSdkVersion}`);
        assert(health.sdkCompatibility.minSdkVersion !== '', 'minSdkVersion is non-empty');
        assert(health.sdkCompatibility.recommendedSdkVersion !== '', 'recommendedSdkVersion is non-empty');
    }
    console.log();

    // ---------------------------------------------------------------
    // Test 2: hasCapability
    // ---------------------------------------------------------------
    console.log('Test 2: hasCapability');
    console.log('---------------------');

    assert(AxonFlow.hasCapability(health, 'health_check'), "hasCapability('health_check') = true");
    assert(AxonFlow.hasCapability(health, 'version_discovery'), "hasCapability('version_discovery') = true");
    assert(!AxonFlow.hasCapability(health, 'nonexistent_feature'), "hasCapability('nonexistent_feature') = false");
    console.log();

    // ---------------------------------------------------------------
    // Test 3: List all capabilities
    // ---------------------------------------------------------------
    console.log('Test 3: All Capabilities');
    console.log('------------------------');
    if (health.capabilities) {
        for (const cap of health.capabilities) {
            console.log(`   - ${cap.name} (since ${cap.since}): ${cap.description}`);
        }
    }
    console.log();

    // ---------------------------------------------------------------
    // Test 4: SDK version info
    // ---------------------------------------------------------------
    console.log('Test 4: SDK Version');
    console.log('-------------------');
    console.log(`   SDK version: ${VERSION}`);
    assert(VERSION !== '', 'SDK version is non-empty');
    console.log();

    // ---------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------
    console.log('==================================');
    if (failures.length > 0) {
        console.log(`FAILED: ${failures.length} failures`);
        for (const f of failures) {
            console.log(`  - ${f}`);
        }
        process.exit(1);
    }
    console.log('ALL PASSED');
}

main().catch((err) => {
    console.error('Fatal error:', err);
    process.exit(1);
});
