# Execution Replay CLI & Embedded UI Validation

This example validates the `axonctl executions` CLI commands and the embedded Execution Viewer web UI.

## What It Validates

| # | Feature | How |
|---|---------|-----|
| 1 | `axonctl executions list` (table) | Runs command, checks table output |
| 2 | `axonctl executions list` (JSON) | Runs command, parses JSON, validates fields |
| 3 | `axonctl executions get` (table) | Runs command, checks detail output |
| 4 | `axonctl executions get` (JSON) | Runs command, parses JSON, validates summary + steps |
| 5 | `axonctl executions export` | Exports to file, validates JSON content |
| 6 | Embedded UI list page | HTTP GET `/ui/executions/`, checks HTML content |
| 7 | Embedded UI detail page | HTTP GET `/ui/executions/detail.html`, checks HTML |
| 8 | Embedded UI static assets | HTTP GET `app.js` and `styles.css`, checks content |
| 9 | Agent proxy UI route | HTTP GET `/ui/executions/` via agent port |

## Prerequisites

- `docker compose up -d` (AxonFlow running)
- At least one execution must exist (run `../go/main.go` first to generate data)

## Running

```bash
cd examples/execution-replay/cli
go run main.go
```

The example automatically builds `axonctl` from source before running tests.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AXONFLOW_ENDPOINT` | Agent URL | `http://localhost:8080` |
| `AXONFLOW_ORCHESTRATOR_URL` | Orchestrator URL | `http://localhost:8081` |
| `AXONFLOW_CLIENT_ID` | Client ID | `demo-org` |
| `AXONFLOW_CLIENT_SECRET` | Client secret | `demo` |

## Expected Output

```
AxonFlow Execution Replay - CLI & Embedded UI Validation
========================================================

0. Building axonctl...
   Built: /tmp/axonctl-test-xxx/axonctl

1. axonctl executions list - Table output...
   ✓ PASS: Table output contains header or empty state message

2. axonctl executions list --format json - JSON output...
   ✓ PASS: JSON output is valid JSON
   ✓ PASS: Total is a valid count

...

========================================================
✓ ALL TESTS PASSED
```
