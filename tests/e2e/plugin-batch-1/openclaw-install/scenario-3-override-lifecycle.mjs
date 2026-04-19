// Scenario 3: full override lifecycle.
// Deny → create override → retry allowed → revoke → retry denied.
// Asserts override_created and override_revoked audit events are present.
import { AxonFlowClient } from '@axonflow/openclaw';

const ENDPOINT = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080';
const CLIENT_ID = process.env.AXONFLOW_CLIENT_ID || 'demo-client';
const CLIENT_SECRET = process.env.AXONFLOW_CLIENT_SECRET || 'demo-secret';
const USER_EMAIL = `e2e-override-${Date.now()}@example.com`;
const TENANT_ID = 'tenant-e2e';

const client = new AxonFlowClient({
  endpoint: ENDPOINT,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  userEmail: USER_EMAIL,
  tenantId: TENANT_ID,
});

const STATEMENT = "SELECT * FROM users WHERE id='1' OR 1=1--";
const PROBE = async () => client.mcpCheckInput('postgresql', STATEMENT, 'query');

// === 1. First fire — must deny.
console.log('--- Step 1: probe first (expect deny) ---');
const r1 = await PROBE();
console.log('  allowed=', r1.allowed, 'decision_id=', r1.decision_id);
if (r1.allowed) { console.error('FAIL: should deny first'); process.exit(1); }
if (!r1.policy_matches?.[0]?.policy_id) { console.error('FAIL: no policy_id to override'); process.exit(1); }
const policyID = r1.policy_matches[0].policy_id;

// === 2. Create override on the matched policy.
console.log('\n--- Step 2: createOverride({ policy_id:', policyID, '}) ---');
let override;
try {
  override = await client.createOverride({
    policyId: policyID,
    policyType: 'static',
    overrideReason: 'E2E scenario 3 — lifecycle test',
    ttlSeconds: 300,
  });
  console.log('  id=', override.id, 'expires_at=', override.expires_at);
} catch (e) {
  console.error('FAIL: createOverride threw:', e.message, e.responseBody);
  process.exit(1);
}

// === 3. Re-fire — must allow now.
console.log('\n--- Step 3: probe again (expect allow via override) ---');
await new Promise(r => setTimeout(r, 500));
const r2 = await PROBE();
console.log('  allowed=', r2.allowed, 'override_existing_id=', r2.override_existing_id);
if (!r2.allowed) {
  console.error('FAIL: override did NOT flip deny → allow');
  console.error('  r2 body:', JSON.stringify(r2, null, 2));
  process.exit(1);
}

// === 4. Revoke.
console.log('\n--- Step 4: revokeOverride ---');
await client.revokeOverride(override.id);
console.log('  revoked');

// === 5. Re-fire — must deny again.
console.log('\n--- Step 5: probe third time (expect deny) ---');
await new Promise(r => setTimeout(r, 500));
const r3 = await PROBE();
console.log('  allowed=', r3.allowed);
if (r3.allowed) {
  console.error('FAIL: policy should re-block after revoke');
  process.exit(1);
}

// === 6. Audit trail — override_created + override_revoked recorded.
console.log('\n--- Step 6: audit trail lookup ---');
// includeRevoked=true so the revoked-at-step-4 override still surfaces
// in the listing for audit assertion. policyId accepts UUID or slug.
const listed = await client.listOverrides({ policyId: policyID, includeRevoked: true });
const match = (listed.overrides || []).find(o => o.id === override.id);
if (!match) {
  console.error('FAIL: listOverrides did not return created override');
  process.exit(1);
}
if (!match.revoked_at) {
  console.error('FAIL: override listing does not reflect revoked_at');
  console.error('  match:', JSON.stringify(match, null, 2));
  process.exit(1);
}

console.log('\nPASS: scenario 3 — override lifecycle (create → used → revoked → not-used)');
