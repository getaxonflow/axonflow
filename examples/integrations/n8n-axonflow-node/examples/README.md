# Example workflows

## `governed-loan-workflow.json`

A complete HTTP-triggered loan-approval workflow that exercises all four AxonFlow operations.

```
Loan Request (Webhook)
        │
        ▼
AxonFlow Check Policy ─── allowed=false ──▶ AxonFlow Wait for Approval
        │                                           │
        │ allowed=true                              ▼
        │                                  Wait for Reviewer Webhook
        │                                           │
        ▼                                           ▼
  Issue Loan (HTTP) ◀─────────────────────────────  ┘
        │
        ├──▶ AxonFlow Record Decision ──▶ Respond
        └──▶ AxonFlow Audit Log (Error)
```

### Import

In n8n: **Workflows → Import from File →** `governed-loan-workflow.json`.

You will need:

1. An **AxonFlow API** credential filled in (endpoint + Client ID + User Token).
2. The `n8n-nodes-axonflow` community node installed (Settings → Community Nodes).
3. The `Issue Loan (HTTP)` node pointed at a real downstream service (it defaults to `https://loan-service.internal/v1/loans` as a placeholder).

### How HITL resume works in this workflow

`AxonFlow Wait for Approval` creates the approval entry, then immediately returns the `approval_id`. The next node — a built-in n8n `Wait` configured for **On Webhook Call** mode — pauses the workflow.

Two resume paths are supported on v8.0.x:

1. **Polling sidecar** (recommended for unattended workflows). A small process polls `GET /api/v1/hitl/queue/{approval_id}` on a short interval. When the request status changes to `approved` or `rejected`, the sidecar POSTs the reviewer decision to the Wait node's webhook URL. Reference implementation is documented in the [n8n integration docs](https://docs.getaxonflow.com/docs/integration/n8n/#hitl).
2. **Manual portal resume** (works without any sidecar). The reviewer copies the Wait node's webhook URL from the n8n workflow editor and POSTs to it from the AxonFlow portal's approval-detail screen after deciding.

As of platform v8.1.0+, AxonFlow supports outbound webhooks via the `notify_url` field on `/api/v1/hitl/queue`. Pass the Wait node's webhook URL as `notify_url` and the platform will POST to it automatically on approval/rejection — the polling sidecar can be retired. The Wait-node side of the workflow is unchanged.
