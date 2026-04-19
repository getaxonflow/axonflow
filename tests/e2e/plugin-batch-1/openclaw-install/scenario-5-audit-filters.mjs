// Scenario 5: audit search filter parity — decision_id, policy_name,
// override_id all narrow the result set independently, on the orchestrator's
// audit_logs table.

const ORCHESTRATOR = 'http://localhost:8081';
const AUTH = 'Basic ' + Buffer.from('demo-client:demo-secret').toString('base64');

async function search(extra) {
  const body = {
    start_time: '2026-01-01T00:00:00Z',
    end_time:   '2027-01-01T00:00:00Z',
    limit:      50,
    ...extra,
  };
  const r = await fetch(`${ORCHESTRATOR}/api/v1/audit/search`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': AUTH,
      'X-User-Email': 'e2e-filter@example.com',
      'X-Tenant-ID':  'tenant-e2e',
    },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  return { status: r.status, total: j.total ?? (j.entries?.length || 0), entries: j.entries };
}

// Pick recent seeded data: find a decision_id + an override_id from prior
// scenarios. Needs at least one of each in audit_logs/policy_overrides
// (scenarios 1-3 already produced them).
const { execSync } = await import('node:child_process');
const decisionID = execSync(
  `docker exec axonflow-postgres psql -U axonflow -d axonflow -tAc "SELECT policy_details->>'decision_id' FROM audit_logs WHERE policy_details->>'decision_id' IS NOT NULL ORDER BY timestamp DESC LIMIT 1;"`
).toString().trim();
const overrideID = execSync(
  `docker exec axonflow-postgres psql -U axonflow -d axonflow -tAc "SELECT id FROM policy_overrides ORDER BY created_at DESC LIMIT 1;"`
).toString().trim();
console.log('decision_id:', decisionID);
console.log('override_id:', overrideID);

console.log('\n--- 1. filter by decision_id ---');
const r1 = await search({ decision_id: decisionID });
console.log('  status=', r1.status, 'total=', r1.total);

console.log('\n--- 2. filter by policy_name ---');
const r2 = await search({ policy_name: 'Authentication Bypass' });
console.log('  status=', r2.status, 'total=', r2.total);

console.log('\n--- 3. filter by override_id ---');
const r3 = await search({ override_id: overrideID });
console.log('  status=', r3.status, 'total=', r3.total);

console.log('\n--- 4. baseline (no filters, capped 50) ---');
const r4 = await search({});
console.log('  total=', r4.total);

const errors = [];
if (r1.status !== 200) errors.push('decision_id filter HTTP != 200');
if (r2.status !== 200) errors.push('policy_name filter HTTP != 200');
if (r3.status !== 200) errors.push('override_id filter HTTP != 200');
if (r1.total === 0) errors.push('decision_id filter returned 0 (expected ≥1)');
if (r2.total === 0) errors.push('policy_name filter returned 0 (expected ≥1)');
if (r1.total >= r4.total && r4.total > 1) errors.push('decision_id filter should narrow baseline');

if (errors.length) {
  console.error('\nFAIL:');
  for (const e of errors) console.error('  -', e);
  process.exit(1);
}
console.log('\nPASS: scenario 5 — audit filter parity');
