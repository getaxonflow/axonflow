# AxonFlow Webhook Management Examples

Demonstrates webhook subscription CRUD operations across all supported languages.

## What These Examples Test

| # | Operation | API |
|---|-----------|-----|
| 1 | Create webhook subscription | `POST /api/v1/webhooks` |
| 2 | Get webhook subscription | `GET /api/v1/webhooks/{id}` |
| 3 | List webhook subscriptions | `GET /api/v1/webhooks` |
| 4 | Update webhook subscription | `PUT /api/v1/webhooks/{id}` |
| 5 | Delete webhook subscription | `DELETE /api/v1/webhooks/{id}` |
| 6 | Error handling | Invalid webhook ID |

## Available Events

| Event | Description |
|-------|-------------|
| `step.approval_required` | A WCP step requires approval |
| `step.approved` | A WCP step was approved |
| `step.rejected` | A WCP step was rejected |
| `workflow.completed` | A WCP workflow completed |
| `workflow.aborted` | A WCP workflow was aborted |

## Prerequisites

```bash
docker compose up -d
```

## Running

### HTTP/curl
```bash
cd http && bash webhooks.sh
```

### Go
```bash
cd go && go run main.go
```

### Python
```bash
cd python && pip install -r requirements.txt && python main.py
```

### TypeScript
```bash
cd typescript && npm install && npx ts-node src/index.ts
```

### Java
```bash
cd java && mvn compile exec:java
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | AxonFlow Agent URL |
| `AXONFLOW_CLIENT_ID` | `demo-org` | Client ID |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret |
