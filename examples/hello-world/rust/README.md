# Hello World — Rust

The minimum AxonFlow integration in Rust: build a client, send a governed query, print the result.

## Prerequisites

- Rust 1.78+ (`rustup`)
- AxonFlow stack running locally (`docker compose ps` from the repo root should show services as `healthy`)

## Run

```bash
# Community mode (no credentials needed — defaults to Basic auth with community tenant)
cargo run

# Evaluation / Enterprise mode (setup-e2e-testing.sh writes these into
# /tmp/axonflow-e2e-env.sh; source it before running):
export AXONFLOW_CLIENT_ID=your-client-id
export AXONFLOW_CLIENT_SECRET=your-client-secret
export AXONFLOW_USER_TOKEN=<JWT-from-setup-script>  # platform validates as JWT in eval/enterprise
cargo run
```

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AXONFLOW_AGENT_URL` | no | `http://localhost:8080` | The agent base URL |
| `AXONFLOW_CLIENT_ID` | for enterprise | _none_ | Tenant credential |
| `AXONFLOW_CLIENT_SECRET` | for enterprise | _none_ | Tenant credential |
| `AXONFLOW_USER_TOKEN` | for enterprise | `hello-world-user` | Per-request user identity — validated as JWT in eval/enterprise, any string accepted in community |

## What it does

1. Builds an `AxonFlowClient` (defaults to `http://localhost:8080`; override with `AXONFLOW_AGENT_URL`).
2. Calls `proxy_llm_call` with a benign query.
3. Prints whether the query was blocked, succeeded, or errored.
