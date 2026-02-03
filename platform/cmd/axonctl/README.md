# axonctl

Command-line tool for AxonFlow administration.

## Build

```bash
go build -o axonctl .
```

## Commands

### `axonctl docs`

Manage protected documentation access via Cloudflare Access.

```bash
axonctl docs grant --email user@example.com --reason "Evaluation"
axonctl docs revoke --email user@example.com
axonctl docs list
```

Requires: `CF_API_TOKEN`, `CF_ACCOUNT_ID`, `CF_ACCESS_GROUP_ID`

### `axonctl executions`

Inspect, replay, and export workflow executions.

```bash
axonctl executions list [--status STATUS] [--workflow-id ID] [--format json]
axonctl executions get <id> [--format json]
axonctl executions replay <id> [--show-io]
axonctl executions export <id> [--output FILE] [--include-io]
```

Requires: `AXONFLOW_CLIENT_ID`, `AXONFLOW_CLIENT_SECRET`
Optional: `AXONFLOW_ENDPOINT` (default: `http://localhost:8080`)

## Testing

```bash
go test ./... -cover
```
