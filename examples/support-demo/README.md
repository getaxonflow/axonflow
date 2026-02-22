# Customer Support Demo

A complete example application demonstrating AxonFlow's AI governance capabilities for customer support operations.

## What This Demo Shows

- **PII Detection & Redaction**: Automatic detection and redaction of SSNs, credit cards, phone numbers
- **Role-Based Access Control**: Different permissions for agents, managers, and admins
- **Policy Enforcement**: SQL injection prevention, dangerous query blocking
- **Audit Logging**: Complete trail of all data access operations
- **LLM Integration**: Natural language to SQL conversion with governance

## Quick Start

### Prerequisites

- Docker and Docker Compose
- At least one LLM API key (OpenAI, Anthropic, or local Ollama)

### 1. Start AxonFlow Platform (from repo root)

```bash
# From the repository root directory
cp .env.example .env
```

Edit `.env` and add your API keys. For policy routing demo, configure multiple providers:

```bash
# OpenAI API Key (get from https://platform.openai.com/api-keys)
OPENAI_API_KEY=sk-your-key-here

# Anthropic API Key (get from https://console.anthropic.com/)
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Local Ollama (run: ollama serve)
OLLAMA_ENDPOINT=http://host.docker.internal:11434
OLLAMA_MODEL=llama3.2:latest
```

> **Policy Routing Demo**: To test LLM routing policies (e.g., "agents can't use OpenAI"),
> configure multiple LLM providers. The demo shows how policies can route requests
> to different providers based on user role, content sensitivity, or region.

Start the AxonFlow platform:

```bash
docker compose up -d
```

### 2. Start Support Demo

```bash
cd examples/support-demo
./support-demo.sh
```

This will:
1. Build and start the demo containers
2. Wait for services to be healthy
3. Configure demo policies automatically

### 3. Access the Demo

- **Frontend**: http://localhost:3001
- **Backend API**: http://localhost:8082/api/health

### Demo Users

| Email | Role | Password | Permissions |
|-------|------|----------|-------------|
| john.doe@company.com | Support Agent | demo123 | Limited PII, US West region |
| sarah.manager@company.com | Manager | demo123 | Full PII, escalation handling |
| admin@company.com | Admin | demo123 | Global access, system admin |

> **Tip**: Both `demo123` and `AxonFlow2024Demo!` passwords work.

## Demo Scenarios

### 1. Agent Query (PII Redaction)

Login as `john.doe@company.com` and query:
```
Show open tickets for premium customers
```
**Result**: SSNs and credit card numbers are automatically redacted.

### 2. Manager Query (Full PII Access)

Login as `sarah.manager@company.com` and query:
```
Find all tickets with SSN references
```
**Result**: Full PII visible due to manager permissions.

### 3. SQL Injection Prevention

Try this query as any user:
```
SELECT * FROM users; DROP TABLE users;
```
**Result**: Query blocked by static policy enforcement.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  React Frontend │────▶│   Go Backend    │────▶│   PostgreSQL    │
│   (Port 3001)   │     │   (Port 8082)   │     │   (Port 5433)   │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  AxonFlow Agent │
                        │  (Port 8080)*   │
                        └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │    LLM APIs     │
                        │ (OpenAI/Claude) │
                        └─────────────────┘

* When running with main platform, agent is at platform's port
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| OPENAI_API_KEY | OpenAI API key | One of these |
| ANTHROPIC_API_KEY | Anthropic API key | required |
| AXONFLOW_ENDPOINT | AxonFlow agent URL | Optional (default: localhost:8080) |
| JWT_SECRET | JWT signing secret | Optional (has default) |
| DATABASE_URL | PostgreSQL connection | Optional (has default) |

### axonflow-config.json

The `axonflow-config.json` file configures:
- Client identification
- Policy enforcement settings
- LLM provider preferences
- Demo user definitions

## Development

### Running Backend Locally

```bash
cd backend
go mod download
go run .
```

### Running Frontend Locally

```bash
cd frontend
npm install
npm start
```

### Database Migrations

Migrations run automatically on backend startup. See `backend/migrations/` for schema.

## Tech Stack

- **Backend**: Go 1.21, Gorilla Mux, lib/pq
- **Frontend**: React, Modern UI
- **Database**: PostgreSQL 15
- **SDK**: [@axonflow/sdk-go](https://github.com/getaxonflow/axonflow-sdk-go)

## Learn More

- [AxonFlow Documentation](https://docs.getaxonflow.com)
- [Getting Started Guide](https://docs.getaxonflow.com/docs/getting-started)
- [Policy Configuration](https://docs.getaxonflow.com/docs/policies/overview)
