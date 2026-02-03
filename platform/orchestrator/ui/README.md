# Embedded Execution Viewer UI

Lightweight web UI for inspecting workflow executions, served by the orchestrator.

## Architecture

- **Vanilla JS + Tailwind CSS (CDN)** — no build step required
- **Go `embed.FS`** — static files are compiled into the orchestrator binary
- **Same-origin API** — UI fetches from `/api/v1/executions` endpoints on the same host

## Files

```
ui/
├── handler.go          # Go HTTP handler with embed.FS
├── handler_test.go     # HTTP handler tests
└── static/
    ├── index.html      # List view (filters, pagination, table)
    ├── detail.html     # Detail view (summary card, step timeline)
    ├── app.js          # Client-side API client and rendering
    └── styles.css      # Status badges and step card styles
```

## Routes

| Route | Description |
|-------|-------------|
| `GET /ui/executions/` | List view (index.html) |
| `GET /ui/executions/detail.html?id=<id>` | Execution detail view |
| `GET /ui/executions/app.js` | JavaScript application |
| `GET /ui/executions/styles.css` | Stylesheet |

## Access

The UI is accessed via the **agent** (`:8080`), which proxies requests to the orchestrator. This follows AxonFlow's single-entry-point architecture where all user traffic goes through the agent.

```
http://localhost:8080/ui/executions/
```

## Testing

```bash
go test ./orchestrator/ui/... -cover
```
