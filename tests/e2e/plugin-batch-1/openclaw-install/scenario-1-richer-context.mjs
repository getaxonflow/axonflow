// Scenario 1: Block + richer context enrichment.
// Fires a mcp-checkInput the orchestrator SHOULD deny, then asserts the
// response carries decision_id, risk_level, policy_matches, and the
// override_available / override_existing_id fields.
import { AxonFlowClient } from '@axonflow/openclaw';

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

// Fire a classic SQL injection "' OR 1=1 --" which the sql_injection_or
// critical policy should block. `check_input` is what the plugin's
// governance.ts invokes before every tool call.
console.log('--- Firing check-input: "\' OR 1=1 --" (should deny) ---');
const result = await client.mcpCheckInput(
  'postgresql',
  "SELECT * FROM users WHERE id='1' OR 1=1--",
  'query',
);
console.log('allowed      :', result.allowed);
console.log('block_reason :', result.block_reason);
console.log('decision_id  :', result.decision_id);
console.log('risk_level   :', result.risk_level);
console.log('policy_matches.length :', (result.policy_matches || []).length);
console.log('override_available    :', result.override_available);
console.log('override_existing_id  :', result.override_existing_id);

// Assertions
const errors = [];
if (result.allowed !== false) errors.push('expected allowed=false');
if (!result.decision_id) errors.push('decision_id missing');
if (typeof result.risk_level !== 'string') errors.push('risk_level missing or wrong type');
if (!Array.isArray(result.policy_matches) || result.policy_matches.length === 0) {
  errors.push('policy_matches should be non-empty array');
}
// sql_injection_or is critical so override_available must be false
if (result.risk_level === 'critical' && result.override_available !== false) {
  errors.push('critical-risk policy must report override_available=false');
}

if (errors.length) {
  console.error('\nFAIL:');
  for (const e of errors) console.error('  -', e);
  process.exit(1);
}
console.log('\nPASS: scenario 1');
// Export decision_id for chained scenarios
await import('fs').then(m => m.writeFileSync('/tmp/openclaw-v1.3.1-e2e/.scenario1-decision-id', result.decision_id));
