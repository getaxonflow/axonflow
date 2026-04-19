// Scenario 2: client.explainDecision(decisionID) returns the frozen
// DecisionExplanation shape after a block, verifying the decision_id from
// scenario 1 resolves against the orchestrator's explain endpoint.
import { AxonFlowClient } from '@axonflow/openclaw';
import { readFileSync } from 'node:fs';

const ENDPOINT = process.env.AXONFLOW_ENDPOINT || 'http://localhost:8080';
const CLIENT_ID = process.env.AXONFLOW_CLIENT_ID || 'demo-client';
const CLIENT_SECRET = process.env.AXONFLOW_CLIENT_SECRET || 'demo-secret';
const USER_EMAIL = 'e2e-scenario1@example.com';

const client = new AxonFlowClient({
  endpoint: ENDPOINT,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  userEmail: USER_EMAIL,
});

// Fire a deny first so we have a fresh decision_id to explain.
console.log('--- Firing a deny to capture a decision_id ---');
const block = await client.mcpCheckInput(
  'postgresql',
  "SELECT * FROM users WHERE id='1' OR 1=1--",
  'query',
);
const decisionID = block.decision_id;
console.log('captured decision_id:', decisionID);
if (!decisionID) {
  console.error('FAIL: scenario 1 response missing decision_id — cannot continue');
  process.exit(1);
}

// Give the audit queue a moment to flush to audit_logs — explain reads from
// there, not from the in-flight request.
await new Promise(r => setTimeout(r, 2500));

console.log('\n--- client.explainDecision(id) ---');
const explain = await client.explainDecision(decisionID);
console.log(JSON.stringify(explain, null, 2));

const errors = [];
if (!explain) errors.push('explainDecision returned null');
if (explain) {
  if (explain.decision_id !== decisionID) errors.push('decision_id round-trip mismatch');
  if (!['deny', 'require_approval'].includes(explain.decision)) errors.push('decision should be deny|require_approval');
  if (typeof explain.reason !== 'string' || !explain.reason) errors.push('reason missing');
  if (typeof explain.risk_level !== 'string') errors.push('risk_level missing');
  if (!Array.isArray(explain.policy_matches)) errors.push('policy_matches missing');
  if (typeof explain.historical_hit_count_session !== 'number') errors.push('historical_hit_count_session missing or wrong type');
  if (typeof explain.override_available !== 'boolean') errors.push('override_available missing or wrong type');
}

if (errors.length) {
  console.error('\nFAIL:');
  for (const e of errors) console.error('  -', e);
  process.exit(1);
}
console.log('\nPASS: scenario 2 — explainDecision returns canonical context');
