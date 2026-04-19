// Scenario 6: cache invalidation on override create — WCP path.
// #1607 introduced idempotent step-gate caching. My override hook is
// supposed to sweep workflow_steps on override create. This exercises the
// full cycle:
//   1. POST /api/v1/workflows                                  — creates workflow
//   2. POST /api/v1/workflows/{id}/steps/{step}/gate           — deny, cached
//   3. POST /api/v1/workflows/{id}/steps/{step}/gate (same)    — served from cache
//   4. POST /api/v1/overrides                                  — invalidates cache
//   5. POST /api/v1/workflows/{id}/steps/{step}/gate (retry)   — re-evaluated, override applies
//
// Relies on a pre-seeded dynamic policy that matches
// step_input.statement containing "CACHE_TEST" (see scenario README or
// setup script). Policy is risk_level=medium, allow_override=true.

import { execSync } from 'node:child_process';

const ORCH = 'http://localhost:8081';
const AUTH = 'Basic ' + Buffer.from('demo-client:demo-secret').toString('base64');
const TENANT = 'tenant-e2e';
const USER = `e2e-cache-${Date.now()}@example.com`;

const POLICY_UUID = execSync(
  `docker exec axonflow-postgres psql -U axonflow -d axonflow -tAc "SELECT id FROM dynamic_policies WHERE name='E2E cache test blocker' AND tenant_id='${TENANT}' ORDER BY created_at DESC LIMIT 1;"`
).toString().trim();
if (!POLICY_UUID) {
  console.error('FAIL: dynamic policy "E2E cache test blocker" not seeded. Run setup first.');
  process.exit(1);
}
console.log('seeded policy UUID:', POLICY_UUID);

function hdr() {
  return {
    'Content-Type': 'application/json',
    'Authorization': AUTH,
    'X-Tenant-ID': TENANT,
    'X-User-Email': USER,
  };
}

async function createWorkflow() {
  const r = await fetch(`${ORCH}/api/v1/workflows`, {
    method: 'POST', headers: hdr(),
    body: JSON.stringify({ workflow_name: 'e2e-cache', source: 'external' }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`create workflow HTTP ${r.status}: ${JSON.stringify(j)}`);
  return j.workflow_id;
}

async function stepGate(workflowID, stepID, retryPolicy) {
  const body = {
    step_name: 'cache-probe',
    step_type: 'tool_call',
    step_input: { statement: 'SELECT 1 -- CACHE_TEST marker', tool: 'probe' },
  };
  if (retryPolicy) body.retry_policy = retryPolicy;
  const r = await fetch(`${ORCH}/api/v1/workflows/${workflowID}/steps/${stepID}/gate`, {
    method: 'POST', headers: hdr(), body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}

async function createOverride(policyUUID) {
  const r = await fetch(`${ORCH}/api/v1/overrides`, {
    method: 'POST', headers: hdr(),
    body: JSON.stringify({
      policy_id: policyUUID,
      policy_type: 'dynamic',
      override_reason: 'E2E scenario 6 — cache invalidation',
      ttl_seconds: 300,
    }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`override HTTP ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

const wfID = await createWorkflow();
console.log('workflow_id:', wfID);

// === 1. First gate call — expect deny, fresh.
console.log('\n--- Step 1: first gate (expect deny, fresh) ---');
const r1 = await stepGate(wfID, 'step-1');
console.log('  status=', r1.status, 'decision=', r1.body.decision, 'cached=', r1.body.cached, 'source=', r1.body.decision_source);

if (r1.body.decision !== 'block' && r1.body.decision !== 'deny') {
  console.error('FAIL: seeded policy did not block. Got decision=', r1.body.decision);
  console.error('  body:', JSON.stringify(r1.body, null, 2));
  process.exit(1);
}

// === 2. Repeat — expect same denial, now cached.
console.log('\n--- Step 2: repeat gate (expect cached deny) ---');
await new Promise(r => setTimeout(r, 300));
const r2 = await stepGate(wfID, 'step-1');
console.log('  decision=', r2.body.decision, 'cached=', r2.body.cached, 'source=', r2.body.decision_source);
if (!r2.body.cached && r2.body.decision_source !== 'cached') {
  console.error('FAIL: expected cached=true on repeat. cache not populated?');
  process.exit(1);
}

// === 3. Create override.
console.log('\n--- Step 3: createOverride on the blocking policy ---');
const ov = await createOverride(POLICY_UUID);
console.log('  override id=', ov.id, 'expires_at=', ov.expires_at);

// === 4. Retry same step gate. Cache should be invalidated; fresh eval hits
//     the override enforcement and flips deny -> allow.
console.log('\n--- Step 4: retry gate after override (expect allow, fresh+override) ---');
await new Promise(r => setTimeout(r, 500));
const r3 = await stepGate(wfID, 'step-1');
console.log('  decision=', r3.body.decision, 'cached=', r3.body.cached, 'source=', r3.body.decision_source, 'override_applied=', r3.body.override_applied);

if (r3.body.decision === 'block' || r3.body.decision === 'deny') {
  console.error('FAIL: step-gate still denies despite override. cache invalidation failed.');
  console.error('  body:', JSON.stringify(r3.body, null, 2));
  process.exit(1);
}
if (r3.body.cached) {
  console.error('FAIL: retry served from cache — expected fresh re-evaluation after override create.');
  process.exit(1);
}

console.log('\nPASS: scenario 6 — cache invalidation on override create');
