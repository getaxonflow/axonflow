/**
 * WCP retry_context + idempotency_key E2E example (Issue #1673 Phase 1 + 2).
 *
 * Exercises the new SDK surface end-to-end against a running v7.3.0
 * enterprise stack.
 *
 * Run:
 *   source /tmp/axonflow-e2e-env.sh
 *   export AXONFLOW_BASE_URL=http://localhost:8080
 *   npx ts-node index.ts
 */

import {
  AxonFlow,
  IdempotencyKeyMismatchError,
  type StepGateRequest,
} from '@axonflow/sdk';

function mustEnv(k: string): string {
  const v = process.env[k];
  if (!v) {
    console.error(`missing env: ${k}`);
    process.exit(1);
  }
  return v;
}

function banner(s: string): void {
  console.log('');
  console.log('━━━', s, '━━━');
}

function fail(msg: string): never {
  console.error('FAIL:', msg);
  process.exit(1);
}

function assertEqStr(label: string, want: string, got: string): void {
  if (want !== got) fail(`${label}: want "${want}", got "${got}"`);
}

function assertEqInt(label: string, want: number, got: number): void {
  if (want !== got) fail(`${label}: want ${want}, got ${got}`);
}

function assertTrue(label: string, cond: boolean): void {
  if (!cond) fail(`assertion failed: ${label}`);
}

async function main(): Promise<void> {
  const endpoint = process.env.AXONFLOW_BASE_URL || 'http://localhost:8080';
  const clientId = mustEnv('AXONFLOW_CLIENT_ID');
  const clientSecret = mustEnv('AXONFLOW_CLIENT_SECRET');

  const client = new AxonFlow({ clientId, clientSecret, endpoint });

  banner('Act 1 — retry_context (TypeScript SDK)');
  await act1(client);

  banner('Act 2 — idempotency_key (TypeScript SDK)');
  await act2(client);

  banner('All assertions passed ✔');
}

async function act1(client: AxonFlow): Promise<void> {
  const wf = await client.createWorkflow({ workflow_name: 'ts-sdk-retry-context' });
  console.log(`workflow: ${wf.workflow_id}`);

  // 1) First gate — first-call invariants
  const req: StepGateRequest = { step_name: 'first-step', step_type: 'tool_call' as const };
  const first = await client.stepGate(wf.workflow_id, 'step-1', req);
  assertEqInt('first gate_count', 1, first.retry_context.gate_count);
  assertEqInt('first completion_count', 0, first.retry_context.completion_count);
  assertEqStr('first prior_completion_status', 'none', first.retry_context.prior_completion_status);
  assertTrue('first !prior_output_available', !first.retry_context.prior_output_available);
  assertEqStr('first last_decision (first-call invariant)', first.decision, first.retry_context.last_decision);
  assertEqStr('first FirstAttemptAt == LastAttemptAt', first.retry_context.first_attempt_at ?? '', first.retry_context.last_attempt_at ?? '');
  console.log('  first gate invariants ✔');

  // 2) Complete, then re-gate
  await client.markStepCompleted(wf.workflow_id, 'step-1', {
    output: { transfer_id: 'TXN-ts-1', amount: 500 },
  });
  const reGate = await client.stepGate(wf.workflow_id, 'step-1', { step_type: 'tool_call' as const });
  assertEqInt('re-gate post-complete gate_count', 2, reGate.retry_context.gate_count);
  assertEqInt('re-gate post-complete completion_count', 1, reGate.retry_context.completion_count);
  assertEqStr('re-gate post-complete prior_completion_status', 'completed', reGate.retry_context.prior_completion_status);
  assertTrue('re-gate post-complete prior_output_available', reGate.retry_context.prior_output_available);
  assertTrue('re-gate post-complete prior_output omitted by default', reGate.retry_context.prior_output === null || reGate.retry_context.prior_output === undefined);
  assertTrue('re-gate post-complete cached==true', reGate.cached);
  console.log('  re-gate post-complete ✔');

  // 3) Gate on step-2 without completion (agent-crash simulation)
  await client.stepGate(wf.workflow_id, 'step-2', { step_name: 'second-step', step_type: 'tool_call' as const });
  const reGate2 = await client.stepGate(wf.workflow_id, 'step-2', { step_type: 'tool_call' as const });
  assertEqStr('gated_not_completed status', 'gated_not_completed', reGate2.retry_context.prior_completion_status);
  assertEqInt('gated_not_completed completion_count', 0, reGate2.retry_context.completion_count);
  console.log('  gated_not_completed ✔');

  // 4) include_prior_output=true recovers the payload
  const withPrior = await client.stepGate(
    wf.workflow_id,
    'step-1',
    { step_type: 'tool_call' as const },
    { includePriorOutput: true }
  );
  assertTrue('prior_output populated', !!withPrior.retry_context.prior_output);
  assertEqStr('prior_output.transfer_id', 'TXN-ts-1', String(withPrior.retry_context.prior_output!.transfer_id));
  console.log('  prior_output recovery ✔');
}

async function act2(client: AxonFlow): Promise<void> {
  const wf = await client.createWorkflow({ workflow_name: 'ts-sdk-idempotency-key' });
  console.log(`workflow: ${wf.workflow_id}`);

  const originalKey = 'payment:wire:ts-sdk-invoice-1';

  // 5) Gate with key — echoes back
  const first = await client.stepGate(wf.workflow_id, 'step-1', {
    step_name: 'wire',
    step_type: 'tool_call' as const,
    idempotency_key: originalKey,
  });
  assertEqStr('retry_context.idempotency_key echo', originalKey, first.retry_context.idempotency_key);
  console.log('  key round-trip ✔');

  // 6) Re-gate with different key → IdempotencyKeyMismatchError
  try {
    await client.stepGate(wf.workflow_id, 'step-1', {
      step_type: 'tool_call' as const,
      idempotency_key: 'payment:wire:different-2',
    });
    fail('expected IdempotencyKeyMismatchError on gate with different key');
  } catch (err) {
    if (!(err instanceof IdempotencyKeyMismatchError)) {
      fail(`expected IdempotencyKeyMismatchError, got ${(err as Error).constructor?.name}: ${(err as Error).message}`);
    }
    assertEqStr('mismatch expected_key', originalKey, err.expectedIdempotencyKey);
    assertEqStr('mismatch received_key', 'payment:wire:different-2', err.receivedIdempotencyKey);
    assertTrue('mismatch workflow_id', err.workflowId.startsWith('wf_'));
    assertEqStr('mismatch step_id', 'step-1', err.stepId);
  }
  console.log('  typed 409 error ✔');

  // 7) Complete with matching key
  await client.markStepCompleted(wf.workflow_id, 'step-1', {
    output: { transfer_id: 'TXN-K1' },
    idempotency_key: originalKey,
  });
  console.log('  complete with matching key ✔');
}

main().catch((err) => {
  console.error('UNEXPECTED ERROR:', err);
  process.exit(1);
});
