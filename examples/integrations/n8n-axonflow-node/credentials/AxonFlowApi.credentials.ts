import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

/**
 * AxonFlowApi credential.
 *
 * Uses the Header Auth pattern (Authorization header explicitly attached in
 * `authenticate.headers`) rather than n8n's built-in Bearer Auth class. The
 * Bearer Auth class silently drops the header in some n8n versions
 * (https://github.com/n8n-io/n8n/issues/15261), so credentials would appear
 * configured but every AxonFlow call would 401.
 */
export class AxonFlowApi implements ICredentialType {
	name = 'axonFlowApi';

	displayName = 'AxonFlow API';

	documentationUrl = 'https://docs.getaxonflow.com/docs/integration/n8n/';

	properties: INodeProperties[] = [
		{
			displayName: 'Endpoint',
			name: 'endpoint',
			type: 'string',
			default: 'https://try.getaxonflow.com',
			placeholder: 'https://try.getaxonflow.com',
			description:
				'Base URL of your AxonFlow Agent (port 8080 in self-hosted, or your SaaS host).',
			required: true,
		},
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			description:
				'AxonFlow client identifier (the tenant your workflow runs under).',
			required: true,
		},
		{
			displayName: 'User Token',
			name: 'userToken',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'AxonFlow user token. Sent as the password half of HTTP Basic auth.',
			required: true,
		},
	];

	/**
	 * Header Auth pattern: build the Authorization header ourselves so it lands
	 * even on n8n versions affected by the Bearer Auth class header-drop bug.
	 *
	 * AxonFlow's policy and audit endpoints accept HTTP Basic auth
	 * (clientId:userToken). The injected header is base64 encoded by n8n's
	 * httpRequest helper at send time via expressions.
	 *
	 * X-Tenant-ID is deliberately NOT set here: the AxonFlow agent's auth
	 * middleware injects the canonical tenant from the authenticated client
	 * license after the Basic credential is validated, overwriting any
	 * client-supplied value. Sending it from the credential would create a
	 * misleading impression that the client controls tenant attribution.
	 */
	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization:
					'=Basic {{ Buffer.from($credentials.clientId + ":" + $credentials.userToken).toString("base64") }}',
			},
		},
	};

	/**
	 * Credential test — hits an authenticated endpoint so wrong credentials
	 * surface in n8n's UI rather than silently passing the test.
	 *
	 * Endpoint choice: POST /api/v1/mcp/check-input with a tier-agnostic noop
	 * body. This endpoint exists on BOTH community and enterprise tiers (look
	 * for the `mcp_check_endpoints` capability in the agent's /health output,
	 * added in 4.7.0). Behavior:
	 *  - Enterprise tier: authenticator validates Basic creds. Bad creds → 401,
	 *    good creds → 200. The credential test correctly fails on wrong creds.
	 *  - Community tier: the platform is intentionally permissive — bad creds
	 *    still return 200. The test then validates "endpoint reachable + auth
	 *    header well-formed" but cannot distinguish wrong creds in community.
	 *    This is a platform-permissiveness constraint, not a credential bug.
	 *
	 * Side effect: the call emits a single audit row tagged
	 * `connector_type: credential_test`. That's the trade vs. the previous
	 * `/health` test, which had zero side effect but accepted any creds.
	 *
	 * The previous `/api/v1/hitl/queue` test 404'd on community-tier hosts
	 * (HITL is enterprise-only) even with valid creds, false-failing for
	 * three of four operations that work on community.
	 */
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{ $credentials.endpoint }}',
			url: '/api/v1/mcp/check-input',
			method: 'POST',
			body: {
				client_id: '={{ $credentials.clientId }}',
				user_token: '={{ $credentials.userToken }}',
				tenant_id: '={{ $credentials.clientId }}',
				connector_type: 'credential_test',
				statement: 'n8n_credential_test_noop',
			},
		},
	};
}
