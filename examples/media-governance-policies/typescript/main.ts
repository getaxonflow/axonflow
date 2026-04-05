/**
 * AxonFlow Media Governance Policies - TypeScript SDK
 *
 * Demonstrates and VALIDATES media governance POLICY management capabilities:
 *   - Listing system media policies (seeded by platform migrations)
 *   - Creating and deleting custom media policies via orchestrator API
 *   - Policy toggle lifecycle (enable/disable)
 *   - Media governance config and status endpoints
 *   - Per-tenant media governance disable/enable (Enterprise only)
 *   - Verifying non-media requests are unaffected by media policies
 *
 * All requests go through the agent entry point (AXONFLOW_ENDPOINT, default :8080).
 * The agent proxies policy CRUD, media governance config, and proxyLLMCall requests.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: npx ts-node main.ts
 * Prerequisites: docker compose up -d
 */

import { AxonFlow } from '@axonflow/sdk';
import type { MediaContent } from '@axonflow/sdk';

// Minimal valid 1x1 white pixel JPEG encoded as base64.
const TEST_IMAGE_BASE64 =
  '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof' +
  'Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh' +
  'MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR' +
  'CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAA' +
  'AAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQAC' +
  'EQMRAD8AbwA//9k=';

const failures: string[] = [];

function getEnv(key: string, defaultVal: string): string {
  return process.env[key] || defaultVal;
}

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<void> {
  console.log('AxonFlow Media Governance Policies - TypeScript SDK');
  console.log('='.repeat(52));
  console.log();

  // Single client: all requests go through the agent entry point
  const client = new AxonFlow({
    endpoint: getEnv('AXONFLOW_ENDPOINT', 'http://localhost:8080'),
    clientId: getEnv('AXONFLOW_CLIENT_ID', 'demo'),
    clientSecret: getEnv('AXONFLOW_CLIENT_SECRET', 'demo'),
    debug: getEnv('AXONFLOW_DEBUG', '') === 'true',
  });

  const userToken = 'media-policy-user';

  // ========================================
  // Test 1: Verify system media policies exist
  // ========================================
  console.log('Test 1: Verify system media policies exist');
  console.log('  Listing dynamic policies with type=media');
  console.log();

  let systemPolicies: any;
  try {
    systemPolicies = await client.listDynamicPolicies({
      type: 'media',
      limit: 100,
    });
  } catch (error) {
    console.log(`   FAIL: listDynamicPolicies failed: ${error}`);
    failures.push('listDynamicPolicies call failed');
    console.log();
    // Continue with remaining tests
    systemPolicies = [];
  }

  const policies = systemPolicies || [];
  const sysMediaPolicies = policies.filter(
    (p: any) => p.id && p.id.startsWith('sys_media_')
  );

  assertCheck(
    sysMediaPolicies.length >= 5,
    `At least 5 system media policies found (got ${sysMediaPolicies.length})`
  );

  // Verify expected categories
  const mediaSafetyCount = sysMediaPolicies.filter(
    (p: any) => p.category === 'media-safety'
  ).length;
  assertCheck(
    mediaSafetyCount >= 2,
    `media-safety category has >= 2 policies (got ${mediaSafetyCount})`
  );

  const mediaBiometricCount = sysMediaPolicies.filter(
    (p: any) => p.category === 'media-biometric'
  ).length;
  assertCheck(
    mediaBiometricCount >= 1,
    `media-biometric category has >= 1 policy (got ${mediaBiometricCount})`
  );

  const mediaPiiCount = sysMediaPolicies.filter(
    (p: any) => p.category === 'media-pii'
  ).length;
  assertCheck(
    mediaPiiCount >= 1,
    `media-pii category has >= 1 policy (got ${mediaPiiCount})`
  );

  const mediaDocumentCount = sysMediaPolicies.filter(
    (p: any) => p.category === 'media-document'
  ).length;
  assertCheck(
    mediaDocumentCount >= 1,
    `media-document category has >= 1 policy (got ${mediaDocumentCount})`
  );

  // Print discovered policies
  console.log();
  console.log('  System media policies:');
  for (const p of sysMediaPolicies) {
    console.log(`    - ${p.id}: ${p.name} [${p.category}]`);
  }
  console.log();

  // ========================================
  // Test 2: System NSFW policy evaluation -- clean image passes
  // ========================================
  console.log('Test 2: System NSFW policy evaluation -- clean image passes');
  console.log('  Sending 1x1 white JPEG via proxyLLMCall');
  console.log();

  let resp2: any;
  try {
    resp2 = await client.proxyLLMCall({
      userToken,
      query: 'Describe this image',
      requestType: 'chat',
      media: [
        {
          source: 'base64',
          mimeType: 'image/jpeg',
          base64Data: TEST_IMAGE_BASE64,
        } as MediaContent,
      ],
    });
  } catch (error) {
    console.log(`   FAIL: proxyLLMCall failed: ${error}`);
    failures.push('Test 2: proxyLLMCall failed');
    resp2 = null;
  }

  if (resp2) {
    assertCheck(resp2.success === true, 'Response is successful');
    assertCheck(
      resp2.blocked !== true,
      `Clean image is NOT blocked (blocked=${resp2.blocked || false})`
    );

    if (resp2.mediaAnalysis) {
      console.log('   PASS: media_analysis present (pipeline active)');
      if (resp2.mediaAnalysis.results && resp2.mediaAnalysis.results.length > 0) {
        const result = resp2.mediaAnalysis.results[0];
        console.log(`   NSFW score: ${result.nsfwScore}`);
        console.log(`   Content safe: ${result.contentSafe}`);
      }
    } else {
      console.log(
        '   WARNING: media_analysis absent -- media governance pipeline not active (requires platform v4.4.0+ with analyzers)'
      );
    }
  }
  console.log();

  // ========================================
  // Test 3: Custom media policy -- create and verify
  // ========================================
  console.log('Test 3: Custom media policy -- create and verify');
  console.log();

  // 3a. Create a custom media policy: block if has_faces == true
  console.log('  3a. Creating custom media policy: block if media.has_faces == true');
  let createdPolicyId: string | null = null;

  try {
    const createResp = await client.createDynamicPolicy({
      name: 'test-face-block-ts-example',
      description: 'Blocks images containing faces (TypeScript example test policy)',
      type: 'media',
      category: 'media-safety',
      conditions: [
        {
          field: 'media.has_faces',
          operator: 'equals',
          value: true,
        },
      ],
      actions: [
        {
          type: 'block',
          config: {
            message: 'Media blocked: faces detected in image',
          },
        },
      ],
      priority: 100,
      enabled: true,
    });

    createdPolicyId = createResp?.id || null;
    assertCheck(
      createdPolicyId !== null && createdPolicyId !== '',
      `Policy created with ID: ${createdPolicyId || '<none>'}`
    );
  } catch (error) {
    console.log(`   FAIL: createDynamicPolicy failed: ${error}`);
    failures.push('Test 3: createDynamicPolicy failed');
  }

  // 3b. Verify it appears in the list
  console.log();
  console.log('  3b. Verifying policy appears in list');

  if (createdPolicyId) {
    try {
      const listResp = await client.listDynamicPolicies({
        type: 'media',
        limit: 100,
      });

      const foundInList = (listResp || []).some(
        (p: any) => p.id === createdPolicyId
      );
      assertCheck(foundInList, 'Created policy found in list');
    } catch (error) {
      console.log(`   FAIL: listDynamicPolicies failed: ${error}`);
      failures.push('Test 3b: listDynamicPolicies failed');
    }
  } else {
    console.log('   SKIP: No policy ID to verify');
  }

  // 3c. Send a 1x1 image request -- should NOT be blocked (no faces in a 1px image)
  console.log();
  console.log('  3c. Sending 1x1 image request (no faces expected)');

  try {
    const processResp = await client.proxyLLMCall({
      userToken,
      query: 'Describe this image',
      requestType: 'chat',
      media: [
        {
          source: 'base64',
          mimeType: 'image/jpeg',
          base64Data: TEST_IMAGE_BASE64,
        } as MediaContent,
      ],
    });

    assertCheck(processResp.success === true, '1x1 image request succeeded');
    assertCheck(
      processResp.blocked !== true,
      '1x1 image NOT blocked by face policy (no faces in 1px image)'
    );
  } catch (error) {
    console.log(`   FAIL: proxyLLMCall failed: ${error}`);
    failures.push('Test 3c: proxyLLMCall failed');
  }

  // 3d. Cleanup -- delete the custom policy
  console.log();
  console.log('  3d. Cleaning up: deleting custom policy');

  if (createdPolicyId) {
    try {
      await client.deleteDynamicPolicy(createdPolicyId);
      assertCheck(true, 'Policy deleted successfully');
    } catch (error) {
      console.log(`   FAIL: deleteDynamicPolicy failed: ${error}`);
      failures.push('Test 3d: deleteDynamicPolicy failed');
    }
  } else {
    console.log('   SKIP: No policy to delete');
  }
  console.log();

  // ========================================
  // Test 4: Media governance config -- read status
  // ========================================
  console.log('Test 4: Media governance config -- read status');
  console.log();

  let statusResp: any = null;
  let perTenantControl = false;

  // 4a. getMediaGovernanceStatus
  console.log('  4a. getMediaGovernanceStatus()');

  try {
    statusResp = await client.getMediaGovernanceStatus();

    assertCheck(
      statusResp.available !== undefined,
      `Response contains 'available' field (available=${statusResp.available})`
    );

    const tier = statusResp.tier || '';
    assertCheck(
      tier !== '',
      `Tier is non-empty (tier=${tier})`
    );

    perTenantControl = statusResp.per_tenant_control === true;
    console.log(
      `   Tier: ${tier} | Available: ${statusResp.available} | Per-tenant control: ${perTenantControl}`
    );
  } catch (error) {
    console.log(`   FAIL: getMediaGovernanceStatus failed: ${error}`);
    failures.push('Test 4a: getMediaGovernanceStatus failed');
  }

  // 4b. getMediaGovernanceConfig
  console.log();
  console.log('  4b. getMediaGovernanceConfig()');

  try {
    const configResp = await client.getMediaGovernanceConfig();

    assertCheck(
      configResp.tenant_id !== undefined,
      `Response contains 'tenant_id' field (tenant_id=${configResp.tenant_id})`
    );

    console.log(
      `   Tenant: ${configResp.tenant_id} | Enabled: ${configResp.enabled}`
    );
  } catch (error) {
    console.log(`   FAIL: getMediaGovernanceConfig failed: ${error}`);
    failures.push('Test 4b: getMediaGovernanceConfig failed');
  }
  console.log();

  // ========================================
  // Test 5: Policy toggle lifecycle
  // ========================================
  console.log('Test 5: Policy toggle lifecycle (create -> disable -> re-enable -> delete)');
  console.log();

  // 5a. Create a media policy
  console.log('  5a. Creating media policy: media.nsfw_score > 0.5 -> block');
  let togglePolicyId: string | null = null;

  try {
    const toggleCreateResp = await client.createDynamicPolicy({
      name: 'test-nsfw-toggle-ts-example',
      description: 'NSFW threshold policy for toggle lifecycle test',
      type: 'media',
      category: 'media-safety',
      conditions: [
        {
          field: 'media.nsfw_score',
          operator: 'greater_than',
          value: 0.5,
        },
      ],
      actions: [
        {
          type: 'block',
          config: {
            message: 'Media blocked: NSFW score exceeds threshold (> 0.5)',
          },
        },
      ],
      priority: 200,
      enabled: true,
    });

    togglePolicyId = toggleCreateResp?.id || null;
    assertCheck(
      togglePolicyId !== null && togglePolicyId !== '',
      `Policy created with ID: ${togglePolicyId || '<none>'}`
    );

    const initialEnabled = toggleCreateResp?.enabled;
    assertCheck(
      initialEnabled === true,
      `Policy initially enabled (enabled=${initialEnabled})`
    );
  } catch (error) {
    console.log(`   FAIL: createDynamicPolicy failed: ${error}`);
    failures.push('Test 5a: createDynamicPolicy failed');
  }

  // 5b. Disable the policy
  console.log();
  console.log('  5b. Disabling policy (enabled=false)');

  if (togglePolicyId) {
    try {
      const disableResp = await client.updateDynamicPolicy(
        togglePolicyId,
        { enabled: false }
      );

      const disabledState = disableResp?.enabled;
      assertCheck(
        disabledState === false,
        `Policy is now disabled (enabled=${disabledState})`
      );
    } catch (error) {
      console.log(`   FAIL: updateDynamicPolicy (disable) failed: ${error}`);
      failures.push('Test 5b: updateDynamicPolicy (disable) failed');
    }
  } else {
    console.log('   SKIP: No policy ID for toggle test');
  }

  // 5c. Re-enable the policy
  console.log();
  console.log('  5c. Re-enabling policy (enabled=true)');

  if (togglePolicyId) {
    try {
      const enableResp = await client.updateDynamicPolicy(
        togglePolicyId,
        { enabled: true }
      );

      const enabledState = enableResp?.enabled;
      assertCheck(
        enabledState === true,
        `Policy is now re-enabled (enabled=${enabledState})`
      );
    } catch (error) {
      console.log(`   FAIL: updateDynamicPolicy (re-enable) failed: ${error}`);
      failures.push('Test 5c: updateDynamicPolicy (re-enable) failed');
    }
  } else {
    console.log('   SKIP: No policy ID for toggle test');
  }

  // 5d. Cleanup
  console.log();
  console.log('  5d. Cleaning up: deleting toggle test policy');

  if (togglePolicyId) {
    try {
      await client.deleteDynamicPolicy(togglePolicyId);
      assertCheck(true, 'Policy deleted successfully');
    } catch (error) {
      console.log(`   FAIL: deleteDynamicPolicy failed: ${error}`);
      failures.push('Test 5d: deleteDynamicPolicy failed');
    }
  } else {
    console.log('   SKIP: No policy to delete');
  }
  console.log();

  // ========================================
  // Test 6: Media governance disable/enable (Enterprise only)
  // ========================================
  console.log('Test 6: Media governance disable/enable (per-tenant config)');
  console.log();

  if (perTenantControl) {
    console.log('  Enterprise mode detected -- testing per-tenant media governance toggle');
    console.log();

    // 6a. Disable media governance for this tenant
    console.log('  6a. Disabling media governance (enabled=false)');

    try {
      const mgDisableResp = await client.updateMediaGovernanceConfig({
        enabled: false,
      });

      assertCheck(
        mgDisableResp.enabled === false,
        `Media governance disabled (enabled=${mgDisableResp.enabled})`
      );
    } catch (error) {
      console.log(`   FAIL: updateMediaGovernanceConfig (disable) failed: ${error}`);
      failures.push('Test 6a: updateMediaGovernanceConfig (disable) failed');
    }

    // 6b. Process request with media -- media_analysis should be absent
    console.log();
    console.log('  6b. Sending image request with media governance disabled');

    try {
      const mgOffResp = await client.proxyLLMCall({
        userToken,
        query: 'Describe this image',
        requestType: 'chat',
        media: [
          {
            source: 'base64',
            mimeType: 'image/jpeg',
            base64Data: TEST_IMAGE_BASE64,
          } as MediaContent,
        ],
      });

      assertCheck(
        mgOffResp.success === true,
        'Request still succeeds with governance disabled'
      );
      assertCheck(
        !mgOffResp.mediaAnalysis,
        'media_analysis absent when governance disabled'
      );
    } catch (error) {
      console.log(`   FAIL: proxyLLMCall (governance disabled) failed: ${error}`);
      failures.push('Test 6b: proxyLLMCall (governance disabled) failed');
    }

    // 6c. Re-enable media governance
    console.log();
    console.log('  6c. Re-enabling media governance (enabled=true)');

    try {
      const mgEnableResp = await client.updateMediaGovernanceConfig({
        enabled: true,
      });

      assertCheck(
        mgEnableResp.enabled === true,
        `Media governance re-enabled (enabled=${mgEnableResp.enabled})`
      );
    } catch (error) {
      console.log(`   FAIL: updateMediaGovernanceConfig (re-enable) failed: ${error}`);
      failures.push('Test 6c: updateMediaGovernanceConfig (re-enable) failed');
    }

    // 6d. Verify media_analysis returns after re-enable
    console.log();
    console.log('  6d. Sending image request with media governance re-enabled');

    try {
      const mgOnResp = await client.proxyLLMCall({
        userToken,
        query: 'Describe this image',
        requestType: 'chat',
        media: [
          {
            source: 'base64',
            mimeType: 'image/jpeg',
            base64Data: TEST_IMAGE_BASE64,
          } as MediaContent,
        ],
      });

      assertCheck(
        mgOnResp.success === true,
        'Request succeeds after re-enable'
      );

      if (mgOnResp.mediaAnalysis) {
        console.log('   PASS: media_analysis present after re-enable');
      } else {
        console.log(
          '   WARNING: media_analysis absent after re-enable (analyzers may not be active in this environment)'
        );
      }
    } catch (error) {
      console.log(`   FAIL: proxyLLMCall (governance re-enabled) failed: ${error}`);
      failures.push('Test 6d: proxyLLMCall (governance re-enabled) failed');
    }
  } else {
    console.log('  SKIP: Per-tenant media governance control requires Enterprise license.');
    console.log('  Community/Evaluation tiers use the global media governance setting.');
    console.log('  To test this, run with an Enterprise license key set in AXONFLOW_LICENSE_KEY.');
  }
  console.log();

  // ========================================
  // Test 7: Non-media request unaffected
  // ========================================
  console.log('Test 7: Non-media request unaffected by media policies');
  console.log('  Sending text-only request via proxyLLMCall');
  console.log();

  try {
    const resp7 = await client.proxyLLMCall({
      userToken,
      query: 'What is the capital of France?',
      requestType: 'chat',
    });

    assertCheck(
      resp7.success === true,
      'Text-only request is successful'
    );
    assertCheck(
      !resp7.mediaAnalysis,
      'No media_analysis present for text-only request'
    );
  } catch (error) {
    console.log(`   FAIL: proxyLLMCall (text-only) failed: ${error}`);
    failures.push('Test 7: proxyLLMCall (text-only) failed');
  }
  console.log();

  // ========================================
  // Summary
  // ========================================
  console.log('='.repeat(52));
  console.log();

  if (failures.length === 0) {
    console.log('ALL TESTS PASSED');
    console.log();
    console.log('Media governance policy capabilities validated:');
    console.log('  - System media policies (NSFW, violence, biometric, PII, documents)');
    console.log('  - Clean image passes system policies');
    console.log('  - Custom media policy CRUD (create, verify, process, delete)');
    console.log('  - Media governance config & status endpoints');
    console.log('  - Policy toggle lifecycle (create, disable, re-enable, delete)');
    if (perTenantControl) {
      console.log('  - Per-tenant media governance disable/enable (Enterprise)');
    }
    console.log('  - Non-media requests unaffected by media policies');
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
