import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AxonFlow } from '../nodes/AxonFlow/AxonFlow.node';

interface CapturedRequest {
	method?: string;
	url?: string;
	headers?: Record<string, string>;
	body?: Record<string, unknown>;
}

interface ExecuteFixture {
	params: Record<string, unknown>;
	credentials?: Record<string, unknown>;
	items?: Array<{ json: Record<string, unknown> }>;
	responses?: unknown[];
	executionId?: string;
	nodeName?: string;
	workflowId?: string;
	continueOnFail?: boolean;
}

function makeExecuteContext(fx: ExecuteFixture) {
	const requests: CapturedRequest[] = [];
	const responses = [...(fx.responses ?? [{ allowed: true }])];
	const credentials = fx.credentials ?? {
		endpoint: 'https://axonflow.local',
		clientId: 'tenant-abc',
		userToken: 'utok-xyz',
	};
	const items = fx.items ?? [{ json: { sample: true } }];
	const executionId = fx.executionId ?? 'exec-1';
	const nodeName = fx.nodeName ?? 'AxonFlow1';
	const continueOnFail = fx.continueOnFail ?? false;

	const ctx = {
		getInputData: () => items,
		getCredentials: async () => credentials,
		getNodeParameter: (
			name: string,
			_itemIndex: number,
			fallback?: unknown,
		) => {
			if (name in fx.params) return fx.params[name];
			if (fallback !== undefined) return fallback;
			throw new Error(`parameter not provided in fixture: ${name}`);
		},
		getNode: () => ({ name: nodeName }),
		getExecutionId: () => executionId,
		continueOnFail: () => continueOnFail,
		helpers: {
			httpRequestWithAuthentication: async (
				_credentialName: string,
				opts: {
					method?: string;
					url?: string;
					headers?: Record<string, string>;
					body?: Record<string, unknown>;
				},
			) => {
				requests.push({
					method: opts.method,
					url: opts.url,
					headers: opts.headers,
					body: opts.body,
				});
				const next = responses.shift();
				if (next instanceof Error) throw next;
				return next ?? { allowed: true };
			},
		},
	};
	return { ctx, requests };
}

async function runExecute(fx: ExecuteFixture) {
	const node = new AxonFlow();
	const { ctx, requests } = makeExecuteContext(fx);
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const result = await (node.execute as any).call(ctx);
	return { result, requests };
}

test('checkPolicy posts to /api/v1/mcp/check-input with Idempotency-Key', async () => {
	const { requests, result } = await runExecute({
		params: {
			operation: 'checkPolicy',
			idempotencyKey: 'exec-1-0-AxonFlow1',
			connectorType: 'n8n',
			statement: 'transfer $5000',
			mcpOperation: 'execute',
			parameters: '{"amount":5000}',
		},
		responses: [{ allowed: false, block_reason: 'requires_approval' }],
	});

	assert.equal(requests.length, 1);
	const req = requests[0];
	assert.equal(req.method, 'POST');
	assert.equal(req.url, 'https://axonflow.local/api/v1/mcp/check-input');
	assert.equal(req.headers?.['Idempotency-Key'], 'exec-1-0-AxonFlow1');
	assert.equal(req.headers?.['Content-Type'], 'application/json');
	assert.deepEqual(req.body, {
		client_id: 'tenant-abc',
		user_token: 'utok-xyz',
		tenant_id: 'tenant-abc',
		connector_type: 'n8n',
		statement: 'transfer $5000',
		operation: 'execute',
		parameters: { amount: 5000 },
	});
	assert.equal((result as Array<Array<{ json: { allowed: boolean } }>>)[0][0].json.allowed, false);
});

test('recordDecision posts to /api/v1/audit/tool-call with success=true + tool_type=n8n_decision', async () => {
	const { requests } = await runExecute({
		params: {
			operation: 'recordDecision',
			idempotencyKey: 'idem-decision-1',
			toolName: 'approve_loan',
			workflowId: 'wf-42',
			stepId: 'AxonFlowNode',
			auditInput: '{"loan_id":"L-001"}',
			auditOutput: '{"status":"approved"}',
			auditSuccess: true,
			auditErrorMessage: '',
		},
	});

	const req = requests[0];
	assert.equal(req.url, 'https://axonflow.local/api/v1/audit/tool-call');
	assert.equal(req.headers?.['Idempotency-Key'], 'idem-decision-1');
	assert.equal(req.body?.tool_name, 'approve_loan');
	assert.equal(req.body?.tool_type, 'n8n_decision');
	assert.equal(req.body?.success, true);
	assert.deepEqual(req.body?.input, { loan_id: 'L-001' });
	assert.deepEqual(req.body?.output, { status: 'approved' });
});

test('auditLog posts to /api/v1/audit/tool-call with tool_type=n8n_audit', async () => {
	const { requests } = await runExecute({
		params: {
			operation: 'auditLog',
			idempotencyKey: 'idem-audit-1',
			toolName: 'reject_loan',
			workflowId: 'wf-42',
			stepId: 'AxonFlowNode',
			auditInput: '{"loan_id":"L-001"}',
			auditOutput: '{}',
			auditSuccess: false,
			auditErrorMessage: 'downstream timeout',
		},
	});

	const req = requests[0];
	assert.equal(req.url, 'https://axonflow.local/api/v1/audit/tool-call');
	assert.equal(req.body?.tool_type, 'n8n_audit');
	assert.equal(req.body?.success, false);
	assert.equal(req.body?.error_message, 'downstream timeout');
});

test('waitForApproval posts to /api/v1/hitl/queue and unwraps approval_id from data envelope', async () => {
	const { requests, result } = await runExecute({
		params: {
			operation: 'waitForApproval',
			idempotencyKey: 'idem-approval-1',
			originalQuery: 'Approve loan L-001 for $5000',
			requestType: 'workflow_step',
			triggeredPolicyId: 'high-value-loan',
			triggeredPolicyName: 'High Value Loan',
			triggerReason: 'amount > $1000',
			severity: 'high',
			limitWaitTime: 3600,
			requestContext: '{"loan_id":"L-001"}',
		},
		responses: [
			{
				success: true,
				data: {
					id: 'approval-uuid-1',
					status: 'pending',
					expires_at: '2026-05-23T00:00:00Z',
				},
			},
		],
	});

	const req = requests[0];
	assert.equal(req.url, 'https://axonflow.local/api/v1/hitl/queue');
	assert.equal(req.headers?.['Idempotency-Key'], 'idem-approval-1');
	assert.equal(req.body?.expires_in_seconds, 3600);
	assert.equal(req.body?.severity, 'high');
	assert.deepEqual(req.body?.request_context, { loan_id: 'L-001' });

	const out = (result as Array<Array<{ json: Record<string, unknown> }>>)[0][0].json;
	assert.equal(out.approval_id, 'approval-uuid-1');
	assert.equal(out.status, 'pending');
	assert.match(String(out.resume_hint), /Wait node/);
});

test('idempotency-key default falls back to executionId-itemIndex-nodeName when not provided', async () => {
	const { requests } = await runExecute({
		params: {
			operation: 'auditLog',
			// idempotencyKey deliberately omitted — exercises the fallback branch
			toolName: 'noop',
			workflowId: 'wf-42',
			stepId: 'step',
			auditInput: '{}',
			auditOutput: '{}',
			auditSuccess: true,
			auditErrorMessage: '',
		},
		executionId: 'exec-99',
		nodeName: 'AxonFlowNode',
	});

	assert.equal(
		requests[0].headers?.['Idempotency-Key'],
		'exec-99-0-AxonFlowNode',
	);
});

test('endpoint trailing-slash is stripped so URL composition stays single-/', async () => {
	const { requests } = await runExecute({
		credentials: {
			endpoint: 'https://axonflow.local/',
			clientId: 'tenant-abc',
			userToken: 'utok-xyz',
		},
		params: {
			operation: 'checkPolicy',
			idempotencyKey: 'k',
			connectorType: 'n8n',
			statement: 'noop',
			mcpOperation: 'execute',
			parameters: '{}',
		},
	});

	assert.equal(requests[0].url, 'https://axonflow.local/api/v1/mcp/check-input');
});

test('continueOnFail wraps thrown error in json.error and proceeds', async () => {
	const { result } = await runExecute({
		params: {
			operation: 'checkPolicy',
			idempotencyKey: 'k',
			connectorType: 'n8n',
			statement: 'fail-me',
			mcpOperation: 'execute',
			parameters: '{}',
		},
		responses: [new Error('axonflow 502')],
		continueOnFail: true,
	});

	const out = (result as Array<Array<{ json: Record<string, unknown> }>>)[0][0].json;
	assert.equal(out.error, 'axonflow 502');
});

test('description copy positions as "AxonFlow API integration" — no governance/audit/compliance wording at the package level', () => {
	const node = new AxonFlow();
	const desc = node.description.description.toLowerCase();
	assert.match(desc, /axonflow api integration/);
	// Forbidden positioning words at the top-level description per brief §2:
	for (const banned of ['governance', 'compliance']) {
		assert.ok(
			!desc.includes(banned),
			`top-level description must not contain "${banned}": got ${desc}`,
		);
	}
});

test('no banned wording in any operation action/description copy (verification-submission constraint)', () => {
	const node = new AxonFlow();
	const opProp = node.description.properties.find((p) => p.name === 'operation');
	assert.ok(opProp);
	const banned = ['governance', 'compliance', 'audit log entry', 'audit logging'];
	for (const opt of opProp!.options ?? []) {
		const haystack = `${(opt as { name?: string }).name ?? ''} ${(opt as { description?: string }).description ?? ''} ${(opt as { action?: string }).action ?? ''}`.toLowerCase();
		for (const word of banned) {
			assert.ok(
				!haystack.includes(word),
				`operation "${(opt as { value: string }).value}" copy must not contain "${word}": got "${haystack}"`,
			);
		}
	}
});

test('every operation defaults to the executionId-itemIndex-nodeName Idempotency-Key when none supplied (regression for all 4 ops)', async () => {
	const ops: Array<{ op: string; extra: Record<string, unknown>; responses?: unknown[] }> = [
		{
			op: 'checkPolicy',
			extra: {
				connectorType: 'n8n',
				statement: 's',
				mcpOperation: 'execute',
				parameters: '{}',
			},
		},
		{
			op: 'recordDecision',
			extra: {
				toolName: 't',
				workflowId: 'w',
				stepId: 's',
				auditInput: '{}',
				auditOutput: '{}',
				auditSuccess: true,
				auditErrorMessage: '',
			},
		},
		{
			op: 'auditLog',
			extra: {
				toolName: 't',
				workflowId: 'w',
				stepId: 's',
				auditInput: '{}',
				auditOutput: '{}',
				auditSuccess: false,
				auditErrorMessage: 'e',
			},
		},
		{
			op: 'waitForApproval',
			extra: {
				originalQuery: 'q',
				requestType: 'workflow_step',
				triggeredPolicyId: 'p',
				triggeredPolicyName: 'P',
				triggerReason: 'r',
				severity: 'medium',
				limitWaitTime: 60,
				requestContext: '{}',
			},
			responses: [{ success: true, data: { id: 'a', status: 'pending' } }],
		},
	];

	for (const { op, extra, responses } of ops) {
		const { requests } = await runExecute({
			params: { operation: op, ...extra },
			executionId: 'exec-default',
			nodeName: 'NodeOne',
			responses,
		});
		assert.equal(
			requests[0].headers?.['Idempotency-Key'],
			'exec-default-0-NodeOne',
			`operation ${op} must default Idempotency-Key when none supplied`,
		);
	}
});

test('failureMode "open" (default) returns a fallback item on transport error (no httpCode) so downstream nodes can continue', async () => {
	const { result, requests } = await runExecute({
		params: {
			operation: 'checkPolicy',
			idempotencyKey: 'k',
			connectorType: 'n8n',
			statement: 's',
			mcpOperation: 'execute',
			parameters: '{}',
			// failureMode omitted → exercises the 'open' default fallback in
			// getNodeParameter (matches the ADK plugin's canonical default).
		},
		responses: [new Error('ECONNREFUSED axonflow:8080')],
	});

	assert.equal(requests.length, 1);
	const out = (result as Array<Array<{ json: Record<string, unknown> }>>)[0][0].json;
	assert.equal(out._axonflow_unreachable, true);
	assert.equal(out.operation, 'checkPolicy');
	assert.match(String(out.error), /ECONNREFUSED/);
});

test('failureMode "open" swallows HTTP 5xx (AxonFlow server-side fault)', async () => {
	const err = Object.assign(new Error('AxonFlow returned 503'), { httpCode: '503' });
	const { result } = await runExecute({
		params: {
			operation: 'checkPolicy',
			idempotencyKey: 'k',
			failureMode: 'open',
			connectorType: 'n8n',
			statement: 's',
			mcpOperation: 'execute',
			parameters: '{}',
		},
		responses: [err],
	});
	const out = (result as Array<Array<{ json: Record<string, unknown> }>>)[0][0].json;
	assert.equal(out._axonflow_unreachable, true);
});

test('failureMode "open" RETHROWS HTTP 401 (bad creds — must surface to user)', async () => {
	const err = Object.assign(new Error('401 Unauthorized'), { httpCode: '401' });
	await assert.rejects(
		runExecute({
			params: {
				operation: 'checkPolicy',
				idempotencyKey: 'k',
				failureMode: 'open',
				connectorType: 'n8n',
				statement: 's',
				mcpOperation: 'execute',
				parameters: '{}',
			},
			responses: [err],
		}),
		/401/,
	);
});

test('failureMode "open" RETHROWS HTTP 404 (wrong tier / endpoint missing — must surface)', async () => {
	const err = Object.assign(new Error('404 Not Found'), { httpCode: '404' });
	await assert.rejects(
		runExecute({
			params: {
				operation: 'waitForApproval',
				idempotencyKey: 'k',
				failureMode: 'open',
				originalQuery: 'q',
				requestType: 'workflow_step',
				triggeredPolicyId: 'p',
				triggeredPolicyName: 'P',
				triggerReason: 'r',
				severity: 'low',
				limitWaitTime: 60,
				requestContext: '{}',
			},
			responses: [err],
		}),
		/404/,
	);
});

test('failureMode "open" RETHROWS HTTP 422 (malformed body — programmer error)', async () => {
	const err = Object.assign(new Error('422 Unprocessable Entity'), { httpCode: '422' });
	await assert.rejects(
		runExecute({
			params: {
				operation: 'recordDecision',
				idempotencyKey: 'k',
				failureMode: 'open',
				toolName: 't',
				workflowId: 'w',
				stepId: 's',
				auditInput: '{}',
				auditOutput: '{}',
				auditSuccess: true,
				auditErrorMessage: '',
			},
			responses: [err],
		}),
		/422/,
	);
});

test('failureMode "open" RETHROWS HTTP 429 (rate limit — n8n Retry on Fail should observe this)', async () => {
	const err = Object.assign(new Error('429 Too Many Requests'), { httpCode: '429' });
	await assert.rejects(
		runExecute({
			params: {
				operation: 'checkPolicy',
				idempotencyKey: 'k',
				failureMode: 'open',
				connectorType: 'n8n',
				statement: 's',
				mcpOperation: 'execute',
				parameters: '{}',
			},
			responses: [err],
		}),
		/429/,
	);
});

test('shouldFailOpen probes both `httpCode` string and `context.statusCode` number shapes (forward-compat across n8n versions)', async () => {
	const errContext = Object.assign(new Error('boom'), { context: { statusCode: 502 } });
	const { result } = await runExecute({
		params: {
			operation: 'auditLog',
			idempotencyKey: 'k',
			failureMode: 'open',
			toolName: 't',
			workflowId: 'w',
			stepId: 's',
			auditInput: '{}',
			auditOutput: '{}',
			auditSuccess: false,
			auditErrorMessage: 'e',
		},
		responses: [errContext],
	});
	const out = (result as Array<Array<{ json: Record<string, unknown> }>>)[0][0].json;
	assert.equal(out._axonflow_unreachable, true);
});

test('failureMode "closed" re-throws on transport error (opt-in for high-stakes flows)', async () => {
	await assert.rejects(
		runExecute({
			params: {
				operation: 'checkPolicy',
				idempotencyKey: 'k',
				failureMode: 'closed',
				connectorType: 'n8n',
				statement: 's',
				mcpOperation: 'execute',
				parameters: '{}',
			},
			responses: [new Error('ECONNREFUSED axonflow:8080')],
		}),
		/ECONNREFUSED/,
	);
});

test('failureMode "open" still re-throws NodeOperationError (programmer errors are not swallowed)', async () => {
	await assert.rejects(
		runExecute({
			params: {
				operation: 'waitForApproval',
				idempotencyKey: 'k',
				originalQuery: 'q',
				requestType: 'workflow_step',
				triggeredPolicyId: 'p',
				triggeredPolicyName: 'P',
				triggerReason: 'r',
				severity: 'low',
				limitWaitTime: 60,
				requestContext: '{}',
				// failureMode default = 'open' — but bare-shape response is a
				// NodeOperationError, NOT a transport error, so it must still
				// throw rather than emit a fallback item.
			},
			responses: [{ id: 'a', status: 'pending' }],
		}),
		(err: Error) => /missing `data` envelope/.test(err.message),
	);
});

test('waitForApproval throws when AxonFlow returns a response without the data envelope (no silent empty payload)', async () => {
	await assert.rejects(
		runExecute({
			params: {
				operation: 'waitForApproval',
				idempotencyKey: 'k',
				originalQuery: 'q',
				requestType: 'workflow_step',
				triggeredPolicyId: 'p',
				triggeredPolicyName: 'P',
				triggerReason: 'r',
				severity: 'low',
				limitWaitTime: 60,
				requestContext: '{}',
			},
			// Bare shape — no APIResponse envelope. The node should refuse rather
			// than emit an approval-id-less item downstream.
			responses: [{ id: 'a', status: 'pending' }],
		}),
		(err: Error) => /missing `data` envelope/.test(err.message),
	);
});

test('credentials list requires AxonFlow API and operation enum has exactly the four documented operations', () => {
	const node = new AxonFlow();
	assert.deepEqual(
		node.description.credentials,
		[{ name: 'axonFlowApi', required: true }],
	);

	const opProp = node.description.properties.find((p) => p.name === 'operation');
	assert.ok(opProp, 'operation property must exist');
	const values = (opProp!.options ?? []).map(
		(o) => (o as { value: string }).value,
	);
	assert.deepEqual(values.sort(), [
		'auditLog',
		'checkPolicy',
		'recordDecision',
		'waitForApproval',
	]);
});
