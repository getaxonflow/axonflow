import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AxonFlowApi } from '../credentials/AxonFlowApi.credentials';

test('credential uses Header Auth pattern (Authorization in authenticate.headers), NOT Bearer Auth class', () => {
	const cred = new AxonFlowApi();
	assert.equal(cred.authenticate.type, 'generic');
	const headers = (cred.authenticate.properties as { headers: Record<string, string> })
		.headers;
	assert.ok(headers, 'authenticate.properties.headers must be set');
	assert.match(
		headers.Authorization,
		/=Basic /,
		'Authorization header must be an n8n expression that constructs a Basic auth header inline (Header Auth pattern). Using n8n built-in Bearer Auth class is forbidden per n8n issue #15261.',
	);
	// X-Tenant-ID is deliberately not set in the credential — the agent's
	// auth middleware injects the canonical tenant after Basic validation.
	assert.equal(headers['X-Tenant-ID'], undefined);
});

test('credential test targets an authenticated endpoint that exists on BOTH community and enterprise tiers (regression for hitl/queue 404 in community)', () => {
	const cred = new AxonFlowApi();
	assert.notEqual(
		cred.test.request.url,
		'/health',
		'/health is unauthenticated — the test would pass with garbage creds.',
	);
	assert.notEqual(
		cred.test.request.url,
		'/api/v1/hitl/queue',
		'/api/v1/hitl/queue is enterprise-only — false-fails on community-tier hosts with valid creds.',
	);
	// /api/v1/mcp/check-input is available on both tiers (mcp_check_endpoints
	// capability since 4.7.0) and 401s on bad creds in enterprise.
	assert.equal(cred.test.request.url, '/api/v1/mcp/check-input');
	assert.equal(cred.test.request.method, 'POST');
});

test('credential test body wires the credential fields as expression references (no leaked literals)', () => {
	const cred = new AxonFlowApi();
	const body = (cred.test.request.body ?? {}) as Record<string, string>;
	assert.match(body.client_id, /\$credentials\.clientId/);
	assert.match(body.user_token, /\$credentials\.userToken/);
	// connector_type identifies these audit rows so operators can filter them
	// out of dashboards / detection rules.
	assert.equal(body.connector_type, 'credential_test');
});

test('credential has endpoint + clientId + userToken properties, userToken is password-typed', () => {
	const cred = new AxonFlowApi();
	const byName = Object.fromEntries(cred.properties.map((p) => [p.name, p]));
	assert.ok(byName.endpoint, 'endpoint required');
	assert.ok(byName.clientId, 'clientId required');
	assert.ok(byName.userToken, 'userToken required');
	assert.equal(
		(byName.userToken.typeOptions as { password?: boolean } | undefined)
			?.password,
		true,
		'userToken must be a password field',
	);
});
