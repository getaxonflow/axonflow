// Scenario 3 (via direct HTTP) — proves the platform side of the
// override lifecycle. OpenClaw plugin v1.3.0 has a separate bug (no
// X-User-Email forwarding) that prevents calling createOverride via the
// client directly; this harness works around that by calling the
// orchestrator endpoints through curl-style fetch.

const ENDPOINT = 'http://localhost:8080';
const AUTH = 'Basic ' + Buffer.from('demo-client:demo-secret').toString('base64');
const USER_EMAIL = `e2e-lifecycle-${Date.now()}@example.com`;
const TENANT_ID = 'tenant-e2e';

const headers = () => ({
  'Content-Type': 'application/json',
  'Authorization': AUTH,
  'X-User-Email': USER_EMAIL,
  'X-Tenant-ID': TENANT_ID,
});

const STATEMENT = "SELECT * FROM users WHERE id='1' OR 1=1--";

async function probe() {
  const r = await fetch(`${ENDPOINT}/api/v1/mcp/check-input`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      connector_type: 'postgresql',
      statement: STATEMENT,
      operation: 'query',
    }),
  });
  return r.json();
}

async function createOverride(policyID) {
  const r = await fetch(`${ENDPOINT}/api/v1/overrides`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({
      policy_id: policyID,
      policy_type: 'static',
      override_reason: 'E2E scenario 3 — platform-side lifecycle',
      ttl_seconds: 300,
    }),
  });
  if (!r.ok) throw new Error(`create override HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function revoke(id) {
  const r = await fetch(`${ENDPOINT}/api/v1/overrides/${id}`, {
    method: 'DELETE',
    headers: headers(),
  });
  if (!r.ok) throw new Error(`revoke HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function listOverridesFor(policyID) {
  const r = await fetch(`${ENDPOINT}/api/v1/overrides?policy_id=${policyID}&include_revoked=true`, {
    headers: headers(),
  });
  if (!r.ok) throw new Error(`list HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

// === 1. Deny.
console.log('--- Step 1: probe (expect deny) ---');
const r1 = await probe();
console.log('  allowed=', r1.allowed, 'decision_id=', r1.decision_id);
if (r1.allowed) { console.error('FAIL: first should deny'); process.exit(1); }
const policyID = r1.policy_matches[0].policy_id;
const policyUUID = (await (await fetch(`${ENDPOINT}/api/v1/mcp/check-input`, { method: 'POST', headers: headers(), body: JSON.stringify({ connector_type: 'postgresql', statement: STATEMENT, operation: 'query' })})).json()).policy_matches[0].policy_id;

// We have the policy SLUG. The overrides endpoint takes the UUID id of
// static_policies. For this E2E we look it up via a side-channel SQL call
// through the postgres container, since /api/v1/policies/list requires a
// UUID itself (inverse lookup not exposed).
import { execSync } from 'node:child_process';
const policyUUID2 = execSync(
  `docker exec axonflow-postgres psql -U axonflow -d axonflow -tAc "SELECT id FROM static_policies WHERE policy_id='${policyID}' LIMIT 1;"`
).toString().trim();
if (!policyUUID2) { console.error('FAIL: cannot find UUID for', policyID); process.exit(1); }
console.log('  policy slug:', policyID, '-> UUID:', policyUUID2);

// === 2. Create override (pass the UUID since that's what policy_overrides.policy_id stores).
console.log('\n--- Step 2: createOverride ---');
const override = await createOverride(policyUUID2);
console.log('  id=', override.id, 'expires_at=', override.expires_at, 'clamped=', override.clamped);

// === 3. Re-probe (allow via override).
console.log('\n--- Step 3: probe (expect allow) ---');
await new Promise(r => setTimeout(r, 500));
const r2 = await probe();
console.log('  allowed=', r2.allowed, 'override_existing_id=', r2.override_existing_id);
if (!r2.allowed) {
  console.error('FAIL: override should have flipped deny -> allow');
  console.error('  r2:', JSON.stringify(r2, null, 2));
  process.exit(1);
}

// === 4. Revoke.
console.log('\n--- Step 4: revokeOverride ---');
const revoked = await revoke(override.id);
console.log('  revoked_at=', revoked.revoked_at);

// === 5. Probe (deny again).
console.log('\n--- Step 5: probe (expect deny) ---');
await new Promise(r => setTimeout(r, 500));
const r3 = await probe();
console.log('  allowed=', r3.allowed);
if (r3.allowed) { console.error('FAIL: should deny after revoke'); process.exit(1); }

// === 6. List shows revoked.
console.log('\n--- Step 6: list shows revoked ---');
const listed = await listOverridesFor(policyUUID2);
const match = (listed.overrides || []).find(o => o.id === override.id);
if (!match) { console.error('FAIL: listed override missing'); process.exit(1); }
if (!match.revoked_at) { console.error('FAIL: listing does not reflect revoked_at'); process.exit(1); }
console.log('  revoked_at on listing:', match.revoked_at);

console.log('\nPASS: scenario 3 (platform-side via curl) — override lifecycle');
