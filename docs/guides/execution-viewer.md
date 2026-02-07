# Execution Viewer

AxonFlow provides two interfaces for inspecting workflow executions: the `axonctl` CLI and an embedded web UI.

## CLI: `axonctl executions`

### Setup

```bash
cd platform/cmd/axonctl
go build -o axonctl .
export AXONFLOW_ENDPOINT="http://localhost:8080"
export AXONFLOW_CLIENT_ID="your-org"
export AXONFLOW_CLIENT_SECRET="your-secret"
```

### Commands

#### List executions

```bash
axonctl executions list
axonctl executions list --status completed --limit 50
axonctl executions list --workflow-id my-workflow --format json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Max results | 20 |
| `--offset` | Pagination offset | 0 |
| `--status` | Filter: pending, running, completed, failed | (all) |
| `--workflow-id` | Filter by workflow name | (all) |
| `--format` | Output format: table, json | table |

#### Get execution details

```bash
axonctl executions get <execution-id>
axonctl executions get <execution-id> --format json
```

Shows the execution summary, all steps with timing and LLM details, and triggered policy events.

#### Replay execution

```bash
axonctl executions replay <execution-id>
axonctl executions replay <execution-id> --show-io
```

Interactive step-by-step replay. Press Enter to advance, `q` to quit. Steps are color-coded by status (green=completed, red=failed, yellow=running).

| Flag | Description | Default |
|------|-------------|---------|
| `--show-io` | Show full input/output for each step | false |

#### Export execution

```bash
axonctl executions export <execution-id>
axonctl executions export <execution-id> --output report.json --include-io
```

Downloads execution data as JSON for compliance and auditing.

| Flag | Description | Default |
|------|-------------|---------|
| `--output`, `-o` | Output file path | `execution-<id>.json` |
| `--include-io` | Include full input/output data | false |

## Embedded Web UI

AxonFlow includes a lightweight execution viewer at `/ui/executions/`, accessible through the agent.

### Access

```
http://localhost:8080/ui/executions/
```

The agent proxies UI requests to the orchestrator, which serves the static files. This follows the single-entry-point architecture where all user traffic goes through the agent.

### Features

**List view** (`/ui/executions/`)
- Table of all executions with ID, workflow, status, steps, duration, cost
- Filter by status and workflow name
- Pagination controls

**Detail view** (`/ui/executions/detail.html?id=<execution-id>`)
- Summary card with execution metadata
- Expandable step timeline with input/output, LLM details, and policy events
- JSON export download button

### Architecture

The UI uses vanilla JavaScript with Tailwind CSS (CDN). Static files are embedded in the Go binary via `embed.FS`, requiring no additional services or build steps.

Files:
- `platform/orchestrator/ui/static/index.html` - List view
- `platform/orchestrator/ui/static/detail.html` - Detail view
- `platform/orchestrator/ui/static/app.js` - Client-side logic
- `platform/orchestrator/ui/static/styles.css` - Custom styles
- `platform/orchestrator/ui/handler.go` - Go handler with embed.FS

### API Endpoints Used

The UI fetches data from the same REST API used by the SDKs:

| Endpoint | Used by |
|----------|---------|
| `GET /api/v1/executions` | List view |
| `GET /api/v1/executions/{id}` | Detail view |
| `GET /api/v1/executions/{id}/export` | Export button |
