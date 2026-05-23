# axonflow-google-adk-plugin

AxonFlow governance plugin for [Google Agent Development Kit (ADK)](https://adk.dev/).

Register `AxonFlowPlugin` once on a `Runner` and **every model call and every
tool call across every agent on that Runner** is governed by AxonFlow
policies: pre-check, HITL approval, deny short-circuit, audit trail, PII
redaction on tool I/O.

## Install

```bash
pip install -e ./examples/integrations/google-adk-plugin
# or directly from the path:
pip install -e /path/to/axonflow-enterprise/examples/integrations/google-adk-plugin
```

The plugin depends on `google-adk>=2.0` and `axonflow>=8.0`.

## Quickstart (5 lines)

```python
from google.adk.runners import InMemoryRunner
from google.adk.agents import LlmAgent
from axonflow_adk import AxonFlowPlugin

agent = LlmAgent(model="gemini-2.0-flash", name="loan_desk", instruction="...")
runner = InMemoryRunner(
    agent=agent,
    app_name="loan_desk",
    plugins=[AxonFlowPlugin(
        endpoint="http://localhost:8080",
        client_id="loan-desk",
        client_secret="secret-from-axonflow",
    )],
)
```

## Hook → AxonFlow endpoint mapping

| ADK hook                     | AxonFlow call             | Deny shape                                     |
|------------------------------|---------------------------|------------------------------------------------|
| `before_model_callback`      | `pre_check`               | `LlmResponse` with policy-denial text          |
| `after_model_callback`       | `audit_llm_call`          | never blocks (audit only)                      |
| `before_tool_callback`       | `check_tool_input`        | `{"error": "[AxonFlow] <reason>"}`             |
| `after_tool_callback`        | `check_tool_output`       | redacted dict OR `{"error": ...}` on hard deny |
| `on_tool_error_callback`     | `audit_tool_call`         | never blocks (audit only)                      |
| `on_user_message_callback`   | no-op (v1)                | n/a                                            |

The `on_user_message_callback` hook is intentionally a no-op in v1 — returning
non-None Content there would silently **replace** the user's message, which is
the wrong tool for governance.

## HITL approval flow — 4-step

When AxonFlow policy evaluates to `require_approval`, the plugin runs the
full **4-step HITL flow** by default (`enable_hitl_polling=True`):

```
before_model_callback / before_tool_callback
    │
    ├─ STEP 1 — gate (pre_check / check_tool_input)
    │           returns blocked, BlockReason == "require_approval"
    │
    ├─ STEP 2 — POST /api/v1/hitl/queue
    │           plugin calls client.create_hitl_request(request=HITLCreateInput(...))
    │           returns approval_id (uuid)
    │
    ├─ STEP 3 — GET /api/v1/hitl/queue/{approval_id}
    │           polled every approval_poll_interval_seconds (default 2s);
    │           local consecutive-failure counter (NOT the shared
    │           breaker) so a polling outage can't disable governance
    │           for other in-flight calls
    │
    └─ STEP 4 — terminal state:
        ├─ "approved"            → return None (let LLM / tool proceed)
        ├─ "rejected" | "expired" → return deny short-circuit
        ├─ N consecutive poll failures → deny
        └─ time > approval_max_wait_seconds → deny
```

The plugin's `before_model_callback` and `before_tool_callback` both run
this flow. Detection is an exact-string match against the platform's
`require_approval` sentinel (set at `platform/agent/gateway_handlers.go`
+ `platform/agent/run.go`). Substring matching previously false-positived
on any policy whose reason text contained the word "approval".

The 4-step flow is the only **fail-closed** path in the plugin —
everything else fails open. Approvals are safety-critical; defaulting to
"allow" on an AxonFlow outage during an approval gate would defeat the
gate.

### Approving / rejecting out-of-band

When step 2 returns an `approval_id`, the plugin emits a single INFO log:

```
axonflow hitl AWAITING APPROVAL: request_id=<uuid>; approve via
POST /api/v1/hitl/queue/<uuid>/{approve|reject}
```

The reviewer (UI, Slack bot, internal portal) posts the decision via:

```bash
# Approve
curl -X POST $AXONFLOW_ENDPOINT/api/v1/hitl/queue/<approval_id>/approve \
     -H 'Content-Type: application/json' \
     -d '{"reviewer_id":"compliance","reviewer_email":"compliance@bank.example"}'

# Reject (same shape)
curl -X POST $AXONFLOW_ENDPOINT/api/v1/hitl/queue/<approval_id>/reject \
     -H 'Content-Type: application/json' \
     -d '{"reviewer_id":"compliance","reviewer_email":"compliance@bank.example"}'
```

The plugin's polling loop sees the status change on its next iteration
and resumes the agent or short-circuits.

### Opting out — deny-fast mode

Set `enable_hitl_polling=False` on the config to short-circuit
`require_approval` immediately without enqueuing a row. The host app
then drives its own approval workflow (ticket system, Slack, internal
portal). Use this when AxonFlow's HITL queue is not your system of
record for approvals.

## Authenticating in enterprise mode

ADK does not carry a first-class `user_token` concept. To propagate the
end-user identity AxonFlow's enterprise-mode policy enforcement requires,
set `state["axonflow_user_token"]` to a valid JWT on the session BEFORE
calling `runner.run_async(...)`:

```python
session = runner.session_service.create_session(
    app_name="loan_desk", user_id="cust-001", session_id="sess-A",
)
session.state["axonflow_user_token"] = generate_axonflow_jwt(user_id="cust-001")
```

Where `generate_axonflow_jwt` signs a JWT with the tenant's signing key
(see [Getting Started — Enterprise auth](https://docs.getaxonflow.com/docs/getting-started/)).
The plugin will NOT fall back to ADK's `user_id` for `user_token` —
passing a raw identifier where a JWT is expected would 401 the AxonFlow
API and silently disable governance (the plugin would fail open).

For **community mode** (no tenant signing key), leave the state key
unset; the plugin will use `config.default_user_token` (default
`"anonymous"`), and the platform's community-mode policy enforcement
will accept it.

## Audit endpoints are enterprise-only

`audit_llm_call` and `audit_tool_call` are enterprise-tier features.
When run against a community-mode platform they return 401 and the
plugin fails open. The audit hooks therefore become silent no-ops in
community deployments — this is intentional and matches the rest of the
AxonFlow SDK surface.

## Failure semantics

A buggy or unreachable AxonFlow **must not** break the agent. The plugin
ships with:

- **Per-hook timeout** (default 5s, configurable via `call_timeout_seconds`)
- **Half-open circuit breaker** (default open after 5 consecutive failures,
  recover after 30s). HALF_OPEN admits exactly one probe; concurrent
  hooks during recovery are skipped without leaking a thundering herd.
- **`asyncio.Lock` around breaker state** so concurrent hook invocations
  do not race the failure counter. If you use the plugin from multiple
  threads (uncommon for ADK), wrap with `asyncio.run_coroutine_threadsafe`.
- **Fail-open default** — every hook except `_await_hitl_decision`
  returns `None` on error/timeout/open-circuit, letting the model or
  tool call proceed.

## MCP toolset helper

```python
from google.adk.agents import LlmAgent
from axonflow_adk import axonflow_mcp_toolset

agent = LlmAgent(
    model="gemini-2.0-flash",
    name="postgres_governed",
    instruction="Answer questions about the production DB.",
    tools=[axonflow_mcp_toolset(
        endpoint="http://localhost:8080",
        client_id="my-app",
        client_secret="secret",
    )],
)
```

The helper returns an ADK `McpToolset` pointed at AxonFlow's MCP endpoint
(`{endpoint}/mcp/`) over Streamable HTTP. All MCP tools surfaced by
AxonFlow are then governed both at the MCP layer (by AxonFlow's
connectors) AND at the ADK-tool layer (by the plugin's
`before_tool_callback` / `after_tool_callback`) — two independent gates,
by design.

## Known ADK gotchas

| Issue                                                                  | Behavior                                                                          | Plugin stance     |
|------------------------------------------------------------------------|-----------------------------------------------------------------------------------|-------------------|
| [google/adk-python#2809](https://github.com/google/adk-python/issues/2809) `AgentTool` plugin isolation | Sub-agents invoked via `AgentTool` create an isolated `Runner` that does NOT inherit plugins. Sub-agent tool calls are **not** governed by this plugin. | Document only.    |
| [google/adk-python#4464](https://github.com/google/adk-python/issues/4464) `InMemoryRunner` plugin lifecycle | Plugin lifecycle is bound to the runner, not the session. Re-creating the runner re-creates the AxonFlow client.   | Document only.    |
| [google/adk-python#4509](https://github.com/google/adk-python/issues/4509) `before_model_callback` corner | A non-None LlmResponse return from `before_model_callback` can corner-case downstream tool dispatch in older ADK builds.  | Document only.    |

The plugin includes an explicit test (`tests/test_plugin.py::test_agent_tool_plugin_isolation_gotcha`) that
**documents** the `AgentTool` bypass behavior rather than hides it. If you
need governance on sub-agents, register the plugin on the inner Runner as
well, or use `RemoteA2aAgent` for cross-process delegation.

## Run the example

```bash
cd examples/integrations/google-adk-plugin
pip install -e .
pip install -e .[dev]
# Bring up an AxonFlow agent on :8080 (community mode is fine):
docker compose -f /path/to/axonflow-enterprise/docker-compose.yml up -d
# Run the loan-desk example:
GOOGLE_API_KEY=... python examples/loan_disbursement_agent.py
```

## Tests

```bash
pytest tests/ -v
```

The test suite covers:

- Deny short-circuit at `before_model_callback`
- Allow passthrough on `pre_check` success
- HITL approval polling: approved-after-N-polls + rejected + expired + polling timeout
- Circuit-breaker behavior on AxonFlow-down
- Per-hook timeout fail-open
- `AgentTool` plugin-isolation gotcha (documented, not hidden)

## License

Apache 2.0. See [LICENSE](LICENSE).
