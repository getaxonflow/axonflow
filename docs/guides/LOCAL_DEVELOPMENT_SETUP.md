# AxonFlow Local Development Setup

**Version:** 1.0
**Created:** December 6, 2025
**Purpose:** Complete guide for setting up AxonFlow development environment

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.23+ | Backend development |
| Node.js | 20+ | Portal frontend |
| Docker | 24+ | Container runtime |
| Docker Compose | 2.20+ | Multi-container orchestration |
| PostgreSQL | 15+ | Database (or use Docker) |
| Redis | 7+ | Rate limiting (optional) |
| Git | 2.40+ | Version control |

### Verify Installations

```bash
# Check all prerequisites
go version          # go1.23.x or higher
node --version      # v20.x.x or higher
docker --version    # Docker version 24.x.x
docker compose version  # v2.20.x or higher
psql --version      # psql 15.x or higher
git --version       # git version 2.40+
```

---

## Repository Setup

### Clone Repository

```bash
# Enterprise (full access)
git clone git@github.com:getaxonflow/axonflow-enterprise.git
cd axonflow-enterprise

# Community (public)
git clone git@github.com:getaxonflow/axonflow.git
cd axonflow
```

### Repository Structure

```
axonflow-enterprise/
├── platform/
│   ├── agent/           # Policy enforcement agent
│   ├── orchestrator/    # LLM routing & policy engine
│   └── connectors/      # MCP connectors
├── examples/            # Demo applications & SDK examples
├── ee/                  # Enterprise-only code
│   ├── platform/        # Enterprise implementations
│   └── docs/            # Enterprise documentation
├── docs/                # Public documentation
├── technical-docs/      # Internal technical docs (enterprise repo only)
└── .github/workflows/   # CI/CD pipelines
```

---

## Quick Start (Docker Compose)

### 1. Start All Services

```bash
# Start PostgreSQL, Redis, Agent, Orchestrator
docker compose up -d

# Verify services
docker compose ps
```

### 2. Check Health

```bash
# Agent health
curl http://localhost:8080/health

# Orchestrator health
curl http://localhost:8081/health
```

### 3. View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f agent
docker compose logs -f orchestrator
```

---

## Manual Setup (Without Docker)

### 1. Database Setup

```bash
# Start PostgreSQL (if not running)
brew services start postgresql@15  # macOS
# or
sudo systemctl start postgresql    # Linux

# Create database
createdb axonflow

# Run migrations
psql axonflow < platform/agent/migrations/001_initial.sql
psql axonflow < platform/orchestrator/migrations/001_initial.sql
```

### 2. Environment Configuration

Create `.env` file in project root:

```bash
# Database
DATABASE_URL=postgresql://localhost:5432/axonflow?sslmode=disable

# Redis (optional - enables distributed rate limiting)
REDIS_URL=redis://localhost:6379

# Community mode (development only)
DEPLOYMENT_MODE=community
ENVIRONMENT=development

# Logging
LOG_LEVEL=debug

# Ports
AGENT_PORT=8080
ORCHESTRATOR_PORT=8081
```

### 3. Build Services

```bash
# Build all
go build ./platform/...

# Build specific services
go build -o bin/agent ./platform/agent
go build -o bin/orchestrator ./platform/orchestrator
```

### 4. Run Services

```bash
# Terminal 1: Agent
./bin/agent

# Terminal 2: Orchestrator
./bin/orchestrator
```

---

## Development Workflows

### Running Tests

```bash
# All tests
go test ./platform/... -v

# With coverage
go test ./platform/... -cover -coverprofile=coverage.out

# Specific package
go test ./platform/agent/... -v
go test ./platform/orchestrator/... -v
go test ./platform/connectors/... -v

# Run with race detection
go test ./platform/... -race
```

### Coverage Thresholds

| Module | Current | Threshold |
|--------|---------|-----------|
| Agent | 74.9% | 74% |
| Orchestrator | 73.0% | 72% |
| Connectors | 68.6% | 66% |

```bash
# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

### Linting

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.2

# Run linter
golangci-lint run ./platform/...

# Auto-fix issues
golangci-lint run --fix ./platform/...
```

### Code Generation

```bash
# Generate mocks (if using mockgen)
go generate ./platform/...

# Generate OpenAPI docs
swag init -g platform/agent/main.go -o docs/api
```

---

## Service Configuration

### Agent Configuration

```yaml
# platform/agent/config.yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

database:
  url: ${DATABASE_URL}
  max_connections: 25
  idle_connections: 5

audit:
  mode: COMPLIANCE  # COMPLIANCE, MINIMAL, DISABLED
  retention_days: 90

license:
  hmac_secret: ${AXONFLOW_LICENSE_HMAC_SECRET}
```

### Orchestrator Configuration

```yaml
# platform/orchestrator/config.yaml
server:
  port: 8081
  read_timeout: 30s
  write_timeout: 30s

database:
  url: ${DATABASE_URL}

redis:
  url: ${REDIS_URL}
  enable_distributed_rate_limiting: true

routing:
  default_temperature: 0.7
  max_retries: 3
  timeout: 60s
```

### Agent Registry (MAP 0.5)

```yaml
# platform/orchestrator/agents/travel.yaml
name: travel-agent
description: "Handles travel booking and flight operations"
version: "1.0.0"
enabled: true
routing_rules:
  - pattern: "(?i)flight|booking|travel|amadeus"
    priority: 100
    domain: travel
llm_config:
  temperature: 0.3
  max_tokens: 4096
connectors:
  - amadeus
  - http
```

---

## Debugging

### Enable Debug Logging

```bash
export LOG_LEVEL=debug
export LOG_FORMAT=json  # or 'text'
```

### Debug with Delve

```bash
# Install Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug agent
dlv debug ./platform/agent -- --config=config.yaml

# Debug with breakpoints
dlv debug ./platform/agent
(dlv) break main.go:50
(dlv) continue
```

### Profile Performance

```bash
# CPU profile
go test -cpuprofile cpu.out -bench . ./platform/orchestrator/...
go tool pprof cpu.out

# Memory profile
go test -memprofile mem.out -bench . ./platform/orchestrator/...
go tool pprof mem.out
```

---

## Common Issues

### 1. Database Connection Failed

```bash
# Error: connection refused
# Solution: Start PostgreSQL
brew services start postgresql@15

# Or check connection string
psql "$DATABASE_URL"
```

### 2. Community Mode Not Working

```bash
# Error: Authentication required
# Solution: Set community mode
export DEPLOYMENT_MODE=community
```

### 3. Port Already in Use

```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use different port
export AGENT_PORT=9080
```

### 4. Go Module Issues

```bash
# Clear module cache
go clean -modcache

# Re-download dependencies
go mod download

# Tidy modules
go mod tidy
```

### 5. Docker Compose Issues

```bash
# Reset everything
docker compose down -v
docker system prune -f
docker compose up -d --build
```

---

## IDE Setup

### VS Code

Recommended extensions:
- Go (golang.go)
- Docker (ms-azuretools.vscode-docker)
- GitLens (eamodio.gitlens)
- YAML (redhat.vscode-yaml)

`.vscode/settings.json`:
```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "go.testFlags": ["-v"],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  }
}
```

### GoLand / IntelliJ

1. Open project as Go module
2. Enable Go modules integration
3. Set GOROOT to Go 1.23+
4. Configure run configurations for agent/orchestrator

---

## Testing with SDKs

### Go SDK

```bash
# Install SDK
go get github.com/getaxonflow/axonflow-sdk-go/v3@v3.3.1

# Run example
cd examples/hello-world/go
go run main.go
```

### TypeScript SDK

```bash
# Install SDK
npm install @axonflow/sdk

# Run example
cd examples/hello-world/typescript
npm install && npm start
```

### Python SDK

```bash
# Install SDK
pip install axonflow-sdk

# Run example
cd examples/hello-world/python
python main.py
```

---

## Git Workflow

### Branch Naming

```
feature/<issue-number>-<description>
bugfix/<issue-number>-<description>
hotfix/<issue-number>-<description>
```

### Commit Messages

```bash
# Format
<type>: <description>

# Types: feat, fix, docs, style, refactor, test, chore

# Examples
git commit -m "feat: add Cassandra connector support"
git commit -m "fix: resolve rate limiting race condition"
git commit -m "docs: update API reference for v1.4"
```

### Pull Request

```bash
# Create PR
gh pr create --title "feat: add feature X" --body "Description..."

# Run checks locally before PR
go test ./platform/...
golangci-lint run ./platform/...
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `REDIS_URL` | No | - | Redis for distributed rate limiting |
| `DEPLOYMENT_MODE` | No | community | community, enterprise, or saas |
| `AXONFLOW_LICENSE_HMAC_SECRET` | Enterprise | - | License HMAC secret (32+ chars) |
| `ENVIRONMENT` | No | development | Environment name |
| `LOG_LEVEL` | No | info | debug, info, warn, error |
| `LOG_FORMAT` | No | text | text or json |
| `AGENT_PORT` | No | 8080 | Agent HTTP port |
| `ORCHESTRATOR_PORT` | No | 8081 | Orchestrator HTTP port |

---

## Related Documentation

- [Getting Started](/docs/getting-started/) - Quick start guide
- [Configuration](/docs/configuration/) - Platform configuration reference
- [MCP Connectors](/docs/mcp/) - Connector setup and configuration

---

**Last Updated:** December 6, 2025
