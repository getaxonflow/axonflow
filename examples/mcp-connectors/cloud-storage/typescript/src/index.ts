/**
 * Cloud Storage Connector Example - TypeScript SDK
 *
 * Tests S3 cloud storage connector operations via the AxonFlow TypeScript SDK.
 * Uses MinIO as S3-compatible backend (started by docker compose).
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Usage:
 *   docker compose up -d
 *   cd examples/mcp-connectors/cloud-storage/typescript
 *   npm install
 *   npx ts-node src/index.ts
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

/** Convert ConnectorResponse.data (any) to an array of row objects. */
function dataToRows(data: any): Record<string, any>[] {
  if (!Array.isArray(data)) return [];
  return data.filter((r: any) => typeof r === 'object' && r !== null);
}

async function main(): Promise<void> {
  const endpoint = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID || 'test-client';
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || 'test-secret';

  const client = new AxonFlow({ endpoint, clientId, clientSecret });

  const testKey = `test-object-${Date.now()}.txt`;
  const testContent = `Hello from AxonFlow TypeScript SDK cloud storage example - ${new Date().toISOString()}`;
  const bucket = 'axonflow-test-bucket';

  console.log('==============================================');
  console.log('Cloud Storage Connector - TypeScript SDK Example');
  console.log('==============================================');
  console.log(`Endpoint: ${endpoint}`);
  console.log(`Test key: ${testKey}`);
  console.log();

  // Test 1: Verify S3 connector is registered
  console.log('Test 1: Verify S3 connector is registered...');
  console.log('----------------------------------------------');

  try {
    const connectors = await client.listConnectors();
    const types = connectors.map((c: any) => c.type);
    assertCheck(types.includes('s3'), 'S3 connector is registered');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'List connectors succeeded');
  }
  console.log();

  // Test 2: Put object
  console.log('Test 2: Put object to S3 (MinIO)...');
  console.log('----------------------------------------------');

  try {
    const putResp = await client.mcpExecute({
      connector: 's3',
      action: 'put_object',
      params: { bucket, key: testKey, content: testContent, content_type: 'text/plain' },
    });
    assertCheck(putResp.success, 'Put object succeeded');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'Put object succeeded');
  }
  console.log();

  // Test 3: Get object and verify content
  console.log('Test 3: Get object and verify content...');
  console.log('----------------------------------------------');

  try {
    const getResp = await client.mcpQuery({
      connector: 's3',
      statement: 'get_object',
      options: { bucket, key: testKey },
    });
    const rows = dataToRows(getResp.data);
    assertCheck(rows.length > 0, 'Get object returned data');

    if (rows.length > 0) {
      const content = rows[0].content || '';
      assertCheck(content.includes('Hello from AxonFlow TypeScript SDK'), 'Content matches uploaded data');
    }
    assertCheck(getResp.policy_info != null, 'Policy info present in response');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'Get object returned data');
  }
  console.log();

  // Test 4: List objects and verify key
  console.log('Test 4: List objects and verify key exists...');
  console.log('----------------------------------------------');

  try {
    const listResp = await client.mcpQuery({
      connector: 's3',
      statement: 'list_objects',
      options: { bucket, prefix: 'test-object-' },
    });
    const rows = dataToRows(listResp.data);
    assertCheck(rows.length > 0, 'List objects returned results');

    const keys = rows.map((r: any) => r.key || '');
    assertCheck(keys.includes(testKey), 'Uploaded key found in listing');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'List objects returned results');
  }
  console.log();

  // Test 5: Head object metadata
  console.log('Test 5: Head object metadata...');
  console.log('----------------------------------------------');

  try {
    const headResp = await client.mcpQuery({
      connector: 's3',
      statement: 'head_object',
      options: { bucket, key: testKey },
    });
    const rows = dataToRows(headResp.data);
    assertCheck(rows.length > 0, 'Head object returned metadata');

    if (rows.length > 0) {
      assertCheck((rows[0].content_type || '').includes('text/plain'), 'Content-Type is text/plain');
      const size = rows[0].content_length || rows[0].size || 0;
      assertCheck(Number(size) > 0, 'Object has non-zero size');
    }
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'Head object returned metadata');
  }
  console.log();

  // Test 6: Delete object
  console.log('Test 6: Delete object...');
  console.log('----------------------------------------------');

  try {
    const delResp = await client.mcpExecute({
      connector: 's3',
      action: 'delete_object',
      params: { bucket, key: testKey },
    });
    assertCheck(delResp.success, 'Delete object succeeded');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'Delete object succeeded');
  }
  console.log();

  // Test 7: Verify deletion
  console.log('Test 7: Verify object was deleted...');
  console.log('----------------------------------------------');

  try {
    const verifyResp = await client.mcpQuery({
      connector: 's3',
      statement: 'list_objects',
      options: { bucket, prefix: testKey },
    });
    const rows = dataToRows(verifyResp.data);
    const keys = rows.map((r: any) => r.key || '');
    assertCheck(!keys.includes(testKey), 'Deleted object no longer in listing');
  } catch (e: any) {
    console.log(`  Error: ${e.message}`);
    assertCheck(false, 'Deleted object no longer in listing');
  }
  console.log();

  // Results
  console.log('==============================================');
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} assertions failed`);
    failures.forEach(f => console.log(`  - ${f}`));
    process.exit(1);
  }

  console.log('ALL ASSERTIONS PASSED - Cloud storage connector tests verified!');
  console.log('==============================================');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
