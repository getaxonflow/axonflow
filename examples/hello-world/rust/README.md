# Hello World — Rust

The minimum AxonFlow integration in Rust: build a client, send a governed query, print the result.

## Prerequisites

- Rust 1.78+ (`rustup`)
- AxonFlow stack running locally (`docker compose ps` from the repo root should show services as `healthy`)

## Run

```bash
# Community mode (no credentials needed — defaults to Basic auth with community tenant)
cargo run

# Enterprise mode
export AXONFLOW_CLIENT_ID=your-client-id
export AXONFLOW_CLIENT_SECRET=your-client-secret
cargo run
```

## What it does

1. Builds an `AxonFlowClient` (defaults to `http://localhost:8080`; override with `AXONFLOW_AGENT_URL`).
2. Calls `proxy_llm_call` with a benign query.
3. Prints whether the query was blocked, succeeded, or errored.
