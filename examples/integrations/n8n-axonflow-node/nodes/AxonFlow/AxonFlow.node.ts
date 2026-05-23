import {
	IExecuteFunctions,
	IDataObject,
	INodeExecutionData,
	INode,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
	IHttpRequestOptions,
} from 'n8n-workflow';

/**
 * AxonFlow node — calls AxonFlow API endpoints from an n8n workflow.
 *
 * Operations:
 *   - checkPolicy        → POST /api/v1/mcp/check-input
 *   - recordDecision     → POST /api/v1/audit/tool-call (success path)
 *   - auditLog           → POST /api/v1/audit/tool-call (error / generic path)
 *   - waitForApproval    → POST /api/v1/hitl/queue, then pause until webhook resume
 *
 * Every operation sends an Idempotency-Key header by default so n8n's
 * `Retry on Fail` re-runs don't double-record. The header value is
 * `{{ $execution.id }}-{{ $itemIndex }}-{{ $nodeName }}` and is overridable.
 */

const DEFAULT_IDEMPOTENCY_TEMPLATE =
	'={{ $execution.id }}-{{ $itemIndex }}-{{ $node.name }}';

export class AxonFlow implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'AxonFlow',
		name: 'axonFlow',
		icon: 'file:axonflow.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{ $parameter["operation"] }}',
		description: 'AxonFlow API integration — call policy and HITL endpoints from your workflow.',
		defaults: {
			name: 'AxonFlow',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'axonFlowApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Check Policy',
						value: 'checkPolicy',
						description: 'Submit a proposed action to AxonFlow and receive an allow/deny response',
						action: 'Check policy for a proposed action',
					},
					{
						name: 'Record Decision',
						value: 'recordDecision',
						description: 'Record the outcome of a downstream action in AxonFlow',
						action: 'Record a decision',
					},
					{
						name: 'Audit Log',
						value: 'auditLog',
						description: 'Record an event in AxonFlow (typically for error branches)',
						action: 'Record an event',
					},
					{
						name: 'Wait for Approval',
						value: 'waitForApproval',
						description: 'Create a HITL approval request and pause the workflow until a reviewer responds',
						action: 'Wait for HITL approval',
					},
				],
				default: 'checkPolicy',
			},

			// ─── Shared options ───────────────────────────────────────────────
			{
				displayName: 'Idempotency Key',
				name: 'idempotencyKey',
				type: 'string',
				default: DEFAULT_IDEMPOTENCY_TEMPLATE,
				description:
					'Sent as the Idempotency-Key header. The default is unique per execution-item-node, so n8n retries do not double-record. Override only if you need a domain-specific key.',
			},
			{
				displayName: 'Failure Mode',
				name: 'failureMode',
				type: 'options',
				options: [
					{
						name: 'Open (Continue If AxonFlow Is Unreachable)',
						value: 'open',
					},
					{
						name: 'Closed (Fail If AxonFlow Is Unreachable)',
						value: 'closed',
					},
				],
				default: 'open',
				description:
					'On network errors / 5xx responses from AxonFlow. Open matches the AxonFlow ADK plugin default — the workflow proceeds with a structured fallback payload so the underlying action is not held hostage by an AxonFlow outage. Closed re-throws and stops the workflow; choose this for high-stakes flows where you would rather fail than skip the policy check.',
			},

			// ─── checkPolicy ────────────────────────────────────────────────
			{
				displayName: 'Connector Type',
				name: 'connectorType',
				type: 'string',
				default: 'n8n',
				displayOptions: { show: { operation: ['checkPolicy'] } },
				description:
					'AxonFlow connector type for this request. Use "n8n" unless you have a custom connector wired up.',
				required: true,
			},
			{
				displayName: 'Statement',
				name: 'statement',
				type: 'string',
				default: '',
				displayOptions: { show: { operation: ['checkPolicy'] } },
				description:
					'The proposed action as a string (e.g. SQL, prompt, API verb+path). AxonFlow evaluates this against policies.',
				required: true,
			},
			{
				displayName: 'Operation Type',
				name: 'mcpOperation',
				type: 'options',
				options: [
					{ name: 'Execute', value: 'execute' },
					{ name: 'Query', value: 'query' },
				],
				default: 'execute',
				displayOptions: { show: { operation: ['checkPolicy'] } },
			},
			{
				displayName: 'Parameters (JSON)',
				name: 'parameters',
				type: 'json',
				default: '{}',
				displayOptions: { show: { operation: ['checkPolicy'] } },
				description: 'Optional parameters passed alongside the statement',
			},

			// ─── recordDecision + auditLog (share ToolCallAuditEntry shape) ──
			{
				displayName: 'Tool Name',
				name: 'toolName',
				type: 'string',
				default: '',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
				description: 'Name of the tool / action being recorded (e.g. "approve_loan")',
				required: true,
			},
			{
				displayName: 'Workflow ID',
				name: 'workflowId',
				type: 'string',
				default: '={{ $workflow.id }}',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
				description: 'Defaults to the running n8n workflow ID so entries are searchable',
			},
			{
				displayName: 'Step ID',
				name: 'stepId',
				type: 'string',
				default: '={{ $node.name }}',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
			},
			{
				displayName: 'Input (JSON)',
				name: 'auditInput',
				type: 'json',
				default: '={{ JSON.stringify($json) }}',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
				description: 'Inputs to record alongside the decision. Defaults to the current item.',
			},
			{
				displayName: 'Output (JSON)',
				name: 'auditOutput',
				type: 'json',
				default: '{}',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
			},
			{
				displayName: 'Success',
				name: 'auditSuccess',
				type: 'boolean',
				default: true,
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
				description:
					'Whether the recorded action succeeded. Set false from error branches.',
			},
			{
				displayName: 'Error Message',
				name: 'auditErrorMessage',
				type: 'string',
				default: '',
				displayOptions: {
					show: { operation: ['recordDecision', 'auditLog'] },
				},
			},

			// ─── waitForApproval ─────────────────────────────────────────────
			{
				displayName: 'Request Type',
				name: 'requestType',
				type: 'string',
				default: 'workflow_step',
				displayOptions: { show: { operation: ['waitForApproval'] } },
				description: 'AxonFlow request_type for the approval entry',
			},
			{
				displayName: 'Original Query / Action',
				name: 'originalQuery',
				type: 'string',
				default: '',
				displayOptions: { show: { operation: ['waitForApproval'] } },
				description: 'Short description of what needs approval',
				required: true,
			},
			{
				displayName: 'Triggered Policy ID',
				name: 'triggeredPolicyId',
				type: 'string',
				default: 'n8n-manual',
				displayOptions: { show: { operation: ['waitForApproval'] } },
				description: 'AxonFlow static_policies.ID that triggered this approval. Use "n8n-manual" for workflow-initiated approvals not tied to a specific policy.',
			},
			{
				displayName: 'Triggered Policy Name',
				name: 'triggeredPolicyName',
				type: 'string',
				default: 'n8n manual approval',
				displayOptions: { show: { operation: ['waitForApproval'] } },
			},
			{
				displayName: 'Trigger Reason',
				name: 'triggerReason',
				type: 'string',
				default: 'Approval requested from n8n workflow',
				displayOptions: { show: { operation: ['waitForApproval'] } },
			},
			{
				displayName: 'Severity',
				name: 'severity',
				type: 'options',
				options: [
					{ name: 'Low', value: 'low' },
					{ name: 'Medium', value: 'medium' },
					{ name: 'High', value: 'high' },
					{ name: 'Critical', value: 'critical' },
				],
				default: 'medium',
				displayOptions: { show: { operation: ['waitForApproval'] } },
			},
			{
				displayName: 'Limit Wait Time (Seconds)',
				name: 'limitWaitTime',
				type: 'number',
				default: 86400,
				displayOptions: { show: { operation: ['waitForApproval'] } },
				description:
					'Maps to expires_in_seconds on the AxonFlow approval. Defaults to 24h.',
			},
			{
				displayName: 'Request Context (JSON)',
				name: 'requestContext',
				type: 'json',
				default: '={{ JSON.stringify($json) }}',
				displayOptions: { show: { operation: ['waitForApproval'] } },
				description:
					'Arbitrary context surfaced in the AxonFlow portal. Defaults to the current item.',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const credentials = await this.getCredentials('axonFlowApi');
		const endpoint = String(credentials.endpoint || '').replace(/\/+$/, '');
		const clientId = String(credentials.clientId || '');

		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			const operation = this.getNodeParameter('operation', i) as string;
			const idempotencyKey = this.getNodeParameter(
				'idempotencyKey',
				i,
				`${this.getExecutionId()}-${i}-${this.getNode().name}`,
			) as string;
			const failureMode = this.getNodeParameter('failureMode', i, 'open') as
				| 'open'
				| 'closed';

			try {
				let result: IDataObject;

				switch (operation) {
					case 'checkPolicy':
						result = await this.helpers.httpRequestWithAuthentication.call(
							this,
							'axonFlowApi',
							buildRequest({
								endpoint,
								method: 'POST',
								path: '/api/v1/mcp/check-input',
								idempotencyKey,
								body: {
									client_id: clientId,
									user_token: String(credentials.userToken || ''),
									tenant_id: clientId,
									connector_type: this.getNodeParameter('connectorType', i) as string,
									statement: this.getNodeParameter('statement', i) as string,
									operation: this.getNodeParameter('mcpOperation', i) as string,
									parameters: parseJsonParam(
										this.getNodeParameter('parameters', i, '{}') as string | object,
									),
								},
							}),
						);
						break;

					case 'recordDecision':
					case 'auditLog':
						result = await this.helpers.httpRequestWithAuthentication.call(
							this,
							'axonFlowApi',
							buildRequest({
								endpoint,
								method: 'POST',
								path: '/api/v1/audit/tool-call',
								idempotencyKey,
								body: {
									tool_name: this.getNodeParameter('toolName', i) as string,
									tool_type: operation === 'auditLog' ? 'n8n_audit' : 'n8n_decision',
									workflow_id: this.getNodeParameter('workflowId', i) as string,
									step_id: this.getNodeParameter('stepId', i) as string,
									input: parseJsonParam(
										this.getNodeParameter('auditInput', i, '{}') as string | object,
									),
									output: parseJsonParam(
										this.getNodeParameter('auditOutput', i, '{}') as string | object,
									),
									success: this.getNodeParameter('auditSuccess', i) as boolean,
									error_message: this.getNodeParameter('auditErrorMessage', i, '') as string,
								},
							}),
						);
						break;

					case 'waitForApproval': {
						const limitWaitTime = this.getNodeParameter('limitWaitTime', i) as number;
						const createResp = (await this.helpers.httpRequestWithAuthentication.call(
							this,
							'axonFlowApi',
							buildRequest({
								endpoint,
								method: 'POST',
								path: '/api/v1/hitl/queue',
								idempotencyKey,
								body: {
									client_id: clientId,
									original_query: this.getNodeParameter('originalQuery', i) as string,
									request_type: this.getNodeParameter('requestType', i) as string,
									request_context: parseJsonParam(
										this.getNodeParameter('requestContext', i, '{}') as string | object,
									),
									triggered_policy_id: this.getNodeParameter('triggeredPolicyId', i) as string,
									triggered_policy_name: this.getNodeParameter(
										'triggeredPolicyName',
										i,
									) as string,
									trigger_reason: this.getNodeParameter('triggerReason', i) as string,
									severity: this.getNodeParameter('severity', i) as string,
									expires_in_seconds: limitWaitTime,
								},
							}),
						)) as IDataObject;

						const approvalData = extractApprovalData(createResp, this.getNode());

						// Surface the approval payload + a hint about how to resume.
						// As of v8.1.0+, the AxonFlow platform supports outbound
						// webhooks via notify_url. When create_hitl_request includes
						// a notify_url, the platform POSTs approval/rejection events
						// to that URL automatically. For n8n, point notify_url at a
						// Wait node webhook URL.
						result = {
							approval_id: approvalData.id,
							status: approvalData.status ?? 'pending',
							expires_at: approvalData.expires_at,
							resume_hint:
								'Use notify_url (v8.1.0+) to auto-POST approval events to a Wait node webhook, or poll GET /api/v1/hitl/queue/{id}. See https://docs.getaxonflow.com/docs/integration/n8n/#hitl.',
							raw: createResp,
						};
						break;
					}

					default:
						throw new NodeOperationError(
							this.getNode(),
							`Unknown operation: ${operation}`,
						);
				}

				returnData.push({
					json: result,
					pairedItem: { item: i },
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}

				// Fail-open default mirrors the AxonFlow ADK plugin: when
				// AxonFlow itself is unhealthy (network unreachable, or 5xx
				// server-side fault), the workflow continues with a structured
				// fallback item so the underlying action isn't held hostage by
				// an AxonFlow outage.
				//
				// 4xx responses are NEVER swallowed under fail-open — they
				// represent caller-side problems (bad creds, malformed body,
				// tier mismatch, rate limit) that the user needs to see and
				// fix. Silently proceeding on a 401 would let a workflow run
				// without policy enforcement and never alarm the operator.
				//
				// NodeOperationError is reserved for true programmer errors
				// (unknown operation, missing-envelope response) — always
				// rethrown regardless of failureMode.
				if (failureMode === 'open' && shouldFailOpen(error)) {
					returnData.push({
						json: {
							_axonflow_unreachable: true,
							error: (error as Error).message,
							operation,
						},
						pairedItem: { item: i },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}

interface BuildRequestArgs {
	endpoint: string;
	method: 'GET' | 'POST';
	path: string;
	idempotencyKey: string;
	body?: IDataObject;
}

function buildRequest(args: BuildRequestArgs): IHttpRequestOptions {
	const headers: IDataObject = {
		'Content-Type': 'application/json',
		Accept: 'application/json',
	};
	if (args.idempotencyKey) {
		headers['Idempotency-Key'] = args.idempotencyKey;
	}

	return {
		method: args.method,
		url: `${args.endpoint}${args.path}`,
		headers,
		body: args.body,
		json: true,
	};
}

/**
 * Decides whether a thrown error should be swallowed under `failureMode: open`.
 *
 * Swallowed:
 *   - Transport-level failures (no httpCode — fetch threw before getting a
 *     response, e.g. ECONNREFUSED / ETIMEDOUT / ENOTFOUND / ENETUNREACH /
 *     ECONNRESET / network-down).
 *   - HTTP 5xx responses (server-side AxonFlow fault).
 *
 * Rethrown:
 *   - NodeOperationError — programmer errors (always surface).
 *   - HTTP 4xx — caller-side errors. 401 (bad creds), 403 (forbidden), 404
 *     (missing endpoint / wrong tier), 422 (malformed body), 429 (rate limit)
 *     are problems the user needs to see and fix. Swallowing them would let a
 *     workflow run un-governed and never alarm the operator.
 *
 * n8n's `httpRequestWithAuthentication` throws `NodeApiError` (not
 * `NodeOperationError`) on non-2xx responses, with the HTTP code on
 * `error.httpCode` (string) or `error.context?.statusCode` (number). We probe
 * both shapes to stay forward-compatible across n8n versions.
 */
function shouldFailOpen(error: unknown): boolean {
	if (error instanceof NodeOperationError) return false;

	const err = error as { httpCode?: string | number; context?: { statusCode?: number }; cause?: { code?: string } };
	const httpCode =
		(typeof err.httpCode === 'string' ? parseInt(err.httpCode, 10) : err.httpCode) ??
		err.context?.statusCode;

	if (typeof httpCode === 'number' && !Number.isNaN(httpCode)) {
		// 5xx → AxonFlow itself is faulting → swallow.
		// 4xx → caller error → rethrow so the user sees it.
		return httpCode >= 500 && httpCode < 600;
	}

	// No httpCode → transport-level failure → swallow.
	return true;
}

function parseJsonParam(value: string | object): IDataObject {
	if (value === null || value === undefined) return {};
	if (typeof value === 'object') return value as IDataObject;
	if (typeof value === 'string') {
		const trimmed = value.trim();
		if (!trimmed) return {};
		try {
			const parsed = JSON.parse(trimmed);
			return (typeof parsed === 'object' && parsed !== null
				? parsed
				: { value: parsed }) as IDataObject;
		} catch {
			return { raw: value };
		}
	}
	return {};
}

/**
 * AxonFlow's CreateRequest handler returns the canonical APIResponse envelope:
 *   { success: true, data: { id, status, expires_at, ... } }
 * Pull approval_id + status off the inner data object. If the envelope is
 * missing — e.g. a misconfigured reverse proxy stripped it — surface a clear
 * NodeOperationError rather than silently emitting an empty approval payload
 * downstream.
 */
function extractApprovalData(
	resp: IDataObject,
	node: INode,
): { id?: string; status?: string; expires_at?: string } {
	const inner = resp.data as IDataObject | undefined;
	if (!inner || typeof inner !== 'object') {
		throw new NodeOperationError(
			node,
			'AxonFlow returned an unexpected response shape from /api/v1/hitl/queue — missing `data` envelope. ' +
				'Check that the request is hitting the AxonFlow Agent directly (not a proxy that strips the wrapping object).',
		);
	}
	return {
		id: (inner.id as string | undefined) ?? (inner.approval_id as string | undefined),
		status: inner.status as string | undefined,
		expires_at: inner.expires_at as string | undefined,
	};
}
