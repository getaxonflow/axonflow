/**
 * Evaluation-tier example (TypeScript SDK variant) for Issue #1673
 * retry-aware dynamic policy. See ../http/main.go for rationale; this does
 * the same thing through @axonflow/sdk, with policy creation via raw fetch
 * (the SDK doesn't expose a createPolicy helper).
 *
 * ⚠️ Evaluation or Enterprise license required.
 */

import { AxonFlow } from '@axonflow/sdk';

function mustEnv(k: string): string {
  const v = process.env[k];
  if (!v) { console.error(`missing env: ${k}`); process.exit(1); }
  return v;
}

function fail(msg: string): never { console.error(`FAIL: ${msg}`); process.exit(1); }
function banner(s: string): void { console.log(''); console.log('━━━', s, '━━━'); }

async function createRetryAwarePolicy(baseURL: string, clientId: string, clientSecret: string): Promise<string> {
  const authHeader = 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const body = {
    name: 'Retry on gated-not-completed wire requires approval (TS)',
    description: 'Human verification required before re-executing a wire when the prior attempt never completed.',
    type: 'context_aware',
    priority: 100,
    enabled: true,
    conditions: [
      { field: 'step.gate_count', operator: 'greater_than', value: 1 },
      { field: 'step.prior_completion_status', operator: 'equals', value: 'gated_not_completed' },
      { field: 'context.tool_name', operator: 'equals', value: 'core_banking_transfer' },
    ],
    actions: [{
      type: 'require_approval',
      config: { reason: 'Retry on un-completed wire — verify with bank before re-execution', severity: 'high' },
    }],
  };
  const res = await fetch(`${baseURL}/api/v1/policies`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: authHeader },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (res.status !== 200 && res.status !== 201) {
    fail(`create policy: status=${res.status} body=${text}`);
  }
  const parsed = JSON.parse(text) as { policy?: { id?: string } };
  const id = parsed.policy?.id;
  if (!id) fail(`create policy: missing policy.id in response, body=${text}`);
  return id;
}

async function deletePolicy(baseURL: string, clientId: string, clientSecret: string, policyId: string): Promise<void> {
  const authHeader = 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  try {
    await fetch(`${baseURL}/api/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'DELETE',
      headers: { Authorization: authHeader },
    });
  } catch { /* best-effort teardown */ }
}

async function main(): Promise<void> {
  const endpoint = process.env.AXONFLOW_BASE_URL || 'http://localhost:8080';
  const clientId = process.env.AXONFLOW_CLIENT_ID || 'demo';
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || 'demo-secret';

  banner('Retry-aware policy (TypeScript SDK, Evaluation tier)');

  const policyId = await createRetryAwarePolicy(endpoint, clientId, clientSecret);
  console.log(`  policy created: ${policyId}`);

  try {
    const client = new AxonFlow({ clientId, clientSecret, endpoint });
    const wf = await client.createWorkflow({ workflow_name: 'eval-retry-aware-ts' });
    console.log(`  workflow: ${wf.workflow_id}`);

    const baseReq = {
      step_name: 'Initiate Wire',
      step_type: 'tool_call' as const,
      step_input: { amount_eur: 750, to_account: '1234' },
      tool_context: { tool_name: 'core_banking_transfer', tool_type: 'api' },
    };

    // 1) First gate — allow
    const first = await client.stepGate(wf.workflow_id, 'step-1', baseReq);
    if (first.decision !== 'allow') fail(`first gate: want allow, got ${first.decision}`);
    console.log('  first gate: allow (gate_count=1, policy doesn\'t fire) ✔');

    // 2) Cached retry — allow, policy bypassed
    const cached = await client.stepGate(wf.workflow_id, 'step-1', baseReq);
    if (!cached.cached) fail('second gate should be cached');
    if (cached.decision !== 'allow') fail(`cached gate: want allow, got ${cached.decision}`);
    console.log('  second gate cached: still allow (cache bypasses policy) ✔');

    // 3) Reevaluate — retry-aware policy fires
    const third = await client.stepGate(wf.workflow_id, 'step-1', { ...baseReq, retry_policy: 'reevaluate' });
    if (third.cached) fail('reevaluate gate should not be cached');
    if (third.decision !== 'require_approval') {
      fail(`reevaluate gate: want require_approval, got ${third.decision} (${third.reason})`);
    }
    console.log('  third gate (reevaluate): require_approval (policy FIRED) ✔');

    banner('Evaluation-tier TypeScript SDK demo passed ✔');
  } finally {
    await deletePolicy(endpoint, clientId, clientSecret, policyId);
  }
}

main().catch((err) => { console.error('UNEXPECTED:', err); process.exit(1); });
