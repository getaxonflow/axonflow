# n8n-nodes-axonflow

AxonFlow API integration for [n8n](https://n8n.io). Call the AxonFlow policy and HITL endpoints directly from your n8n workflows.

> **Status: v1 (unverified).** Installs on n8n self-hosted via the community-nodes GUI or `npm install`. Submission to n8n's verified registry is tracked separately.

## What it does

This package contributes a single `AxonFlow` node with four operations against an AxonFlow Agent:

| Operation | Endpoint | When to use |
|---|---|---|
| **Check Policy** | `POST /api/v1/mcp/check-input` | Before a workflow takes a sensitive action — receive `{allowed, block_reason?}` and branch on it. |
| **Record Decision** | `POST /api/v1/audit/tool-call` | After a successful action — capture inputs, outputs, policies applied. |
| **Audit Log** | `POST /api/v1/audit/tool-call` | From error branches — record the failed action with `success: false` and `error_message`. |
| **Wait for Approval** | `POST /api/v1/hitl/queue` | When the workflow needs a human in the loop — creates an approval entry and pairs with an n8n Wait node for webhook resume. |

Plus a single `AxonFlow API` credential type holding the endpoint + Basic-auth (`clientId` + `userToken`).

## Install

### n8n GUI (self-hosted)

1. Settings → Community Nodes → Install.
2. npm package name: `n8n-nodes-axonflow`.
3. Restart n8n.

### Manual

```bash
cd ~/.n8n/custom
npm install n8n-nodes-axonflow
# restart n8n
```

> n8n Cloud does not currently allow unverified community nodes. Use the [stock-HTTP-node recipe](https://docs.getaxonflow.com/docs/integration/n8n/) on n8n Cloud until this package is verified.

## Build from source

```bash
npm install
npm run build       # tsc → dist/
npm run lint
npm test            # node --test
```

## Three things to know before using

1. **Bearer Auth → Header Auth.** This credential uses the Header Auth pattern (Authorization built inline) rather than n8n's built-in Bearer Auth class, which silently drops the header in some n8n versions ([n8n#15261](https://github.com/n8n-io/n8n/issues/15261)).
2. **Idempotency by default.** Every operation sends `Idempotency-Key: {executionId}-{itemIndex}-{nodeName}` so n8n's `Retry on Fail` doesn't double-record. Override at the node parameter level if you need a domain-specific key.
3. **HITL pairs with the Wait node.** `Wait for Approval` creates the AxonFlow approval entry; pair it with a downstream Wait node configured for **On Webhook Call** mode. As of platform v8.1.0+, pass the Wait node's webhook URL as `notify_url` in the HITL queue request and AxonFlow will POST to it automatically on approval/rejection — no polling sidecar needed. For self-hosted deployments on v8.0.x, two manual paths work: (a) run a small **polling sidecar** that watches `GET /api/v1/hitl/queue/{id}` and POSTs to the Wait node's webhook URL when status changes, or (b) have a reviewer trigger the resume URL manually from the portal. See [`docs/integration/n8n.md#hitl`](https://docs.getaxonflow.com/docs/integration/n8n/#hitl) for details.

## Example workflow

[`examples/governed-loan-workflow.json`](./examples/governed-loan-workflow.json) — an importable workflow that:

1. Receives a loan request via HTTP trigger,
2. Calls **Check Policy** on the amount,
3. If `allowed=false`, branches to **Wait for Approval** (workflow pauses),
4. On approval, calls the downstream loan-issuance HTTP endpoint,
5. Records the outcome with **Record Decision**, with an error branch to **Audit Log**.

## License

MIT
