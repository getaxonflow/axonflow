# Local Development Guide

Fast feedback loop for testing AxonFlow changes locally before deploying to AWS.

**Replaces:** 2-4 hour AWS deployment cycle  
**With:** 5-10 minute local test cycle

---

## Quick Start

```bash
# 1. Start all services
./scripts/local-dev/start.sh

# 2. Access services
open http://localhost:8080    # Agent
open http://localhost:8081    # Orchestrator
open http://localhost:8082    # Customer Portal
open http://localhost:3000    # Grafana (admin / grafana_localdev456)
open http://localhost:9090    # Prometheus

# 3. Follow logs
docker-compose logs -f agent

# 4. Stop services (keep data for faster restart)
./scripts/local-dev/stop.sh --keep-data

# 5. Clean stop (remove all data)
./scripts/local-dev/stop.sh --clean
```

---

## Prerequisites

- Docker Desktop installed and running
- At least 4GB RAM available for Docker
- Ports 3000, 5432, 6379, 8080-8082, 9090 available

---

## Architecture

The local environment replicates the AWS deployment:

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                       │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  Agent   │  │Orchestr. │  │Customer  │             │
│  │  :8080   │  │  :8081   │  │Portal    │             │
│  └────┬─────┘  └────┬─────┘  │:8082     │             │
│       │             │         └────┬─────┘             │
│       └─────────┬───┴──────────────┘                   │
│                 │                                       │
│         ┌───────▼────────┐                             │
│         │   PostgreSQL   │                             │
│         │     :5432      │                             │
│         │                │                             │
│         │  ┌──────────┐  │                             │
│         │  │axonflow  │  │  (Agent runs migrations)    │
│         │  │grafana   │  │                             │
│         │  └──────────┘  │                             │
│         └────────────────┘                             │
│                                                         │
│  ┌──────────┐           ┌──────────┐                  │
│  │Prometheus│           │ Grafana  │                  │
│  │  :9090   │◄──────────│  :3000   │                  │
│  └──────────┘           └──────────┘                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## LLM Providers (Ollama)

### Adding Ollama for Local LLM Testing

For cost-effective local development with LLM capabilities, you can add Ollama to your local environment. This eliminates OpenAI API costs during development.

#### Quick Setup

```bash
# 1. Create docker-compose.ollama.yaml
cat > docker-compose.ollama.yaml <<'EOF'
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: axonflow-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    restart: unless-stopped
    networks:
      - axonflow-local
    # Optional: GPU support (requires NVIDIA Docker runtime)
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: all
    #           capabilities: [gpu]

volumes:
  ollama-data:

networks:
  axonflow-local:
    external: true
EOF

# 2. Start Ollama
docker-compose -f docker-compose.ollama.yaml up -d

# 3. Pull models (choose one or more)
docker exec axonflow-ollama ollama pull llama3.1       # 8B, general purpose
docker exec axonflow-ollama ollama pull mistral        # 7B, efficient
docker exec axonflow-ollama ollama pull codellama      # 7B, code generation

# 4. Verify Ollama is running
curl http://localhost:11434/api/version

# 5. Configure AxonFlow to use Ollama
# Ollama is auto-enabled when OLLAMA_ENDPOINT is set
export OLLAMA_ENDPOINT=http://ollama:11434
export OLLAMA_MODEL=llama3.1

# 6. Restart orchestrator
docker-compose restart orchestrator
```

#### Integrated Setup (Recommended)

Add Ollama to your main docker-compose.yaml:

```yaml
# Add to docker-compose.yaml services section
services:
  # ... existing services ...

  ollama:
    image: ollama/ollama:latest
    container_name: axonflow-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama-data:/root/.ollama
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/version"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - axonflow-local

# Add to volumes section
volumes:
  ollama-data:
```

Then update orchestrator environment:

```yaml
services:
  orchestrator:
    # ... existing config ...
    environment:
      # Ollama is auto-enabled when OLLAMA_ENDPOINT is set
      - OLLAMA_ENDPOINT=http://ollama:11434
      - OLLAMA_MODEL=llama3.1
      - OLLAMA_TIMEOUT_SECONDS=60
    depends_on:
      - ollama
```

#### Testing Ollama

```bash
# Test direct API call
curl -X POST http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.1",
    "prompt": "What is the capital of France?",
    "stream": false
  }'

# Test via AxonFlow orchestrator
curl -X POST http://localhost:8081/api/v1/complete \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is the capital of France?",
    "max_tokens": 100
  }'
```

#### Model Management

```bash
# List installed models
docker exec axonflow-ollama ollama list

# Pull additional models
docker exec axonflow-ollama ollama pull llama3.1:70b  # Larger model (requires 80GB RAM)

# Remove model to free space
docker exec axonflow-ollama ollama rm mistral

# Show model details
docker exec axonflow-ollama ollama show llama3.1
```

#### Benefits for Local Development

- ✅ **Zero API costs**: No OpenAI charges during development
- ✅ **Fast iteration**: No network latency, instant responses
- ✅ **Offline capable**: Work without internet
- ✅ **Privacy**: Data never leaves your machine
- ✅ **Model experimentation**: Try different models easily

#### Resource Requirements

| Model | Size | RAM | Speed (CPU) | Speed (GPU) |
|-------|------|-----|-------------|-------------|
| **llama3.1** (8B) | 4.7 GB | 8 GB | 10-20 tokens/s | 50-100 tokens/s |
| **mistral** (7B) | 4.1 GB | 8 GB | 10-20 tokens/s | 50-100 tokens/s |
| **codellama** (7B) | 4.1 GB | 8 GB | 10-20 tokens/s | 50-100 tokens/s |
| **llama3.1:70b** (70B) | 40 GB | 80 GB | 1-3 tokens/s | 10-30 tokens/s |

**Recommendation for laptops**: Use 7-8B models (llama3.1, mistral, codellama)

#### Troubleshooting Ollama

**Issue: Ollama not accessible**
```bash
# Check Ollama is running
docker ps | grep ollama

# Check logs
docker logs axonflow-ollama

# Restart Ollama
docker restart axonflow-ollama
```

**Issue: Model not found**
```bash
# Pull the model
docker exec axonflow-ollama ollama pull llama3.1

# Verify model installed
docker exec axonflow-ollama ollama list
```

**Issue: Out of memory**
```bash
# Use smaller model
docker exec axonflow-ollama ollama pull mistral  # 7B instead of 70B

# Or increase Docker memory limit in Docker Desktop settings
# Docker Desktop → Preferences → Resources → Memory → 8+ GB
```

**Issue: Slow responses**
```bash
# Check CPU usage
docker stats axonflow-ollama

# Solution: Use smaller model or enable GPU
# For GPU: Uncomment the deploy section in docker-compose.yaml
```

---

## Testing Migrations

Before deploying to AWS, test migrations locally:

```bash
# Test all migrations
./scripts/local-dev/test-migrations.sh

# Verify specific migration
docker-compose exec postgres psql -U axonflow -d axonflow -c "\dt"

# Check Grafana database created (migration 017)
docker-compose exec postgres psql -U postgres -l | grep grafana
```

**What this verifies:**
- ✅ All SQL migrations run successfully
- ✅ Migration 017 creates grafana database and user
- ✅ Migration 005 creates customer_portal_api_keys table
- ✅ Migrations 010/011 create orchestrator tables
- ✅ No password issues (GRAFANA_PASSWORD substitution works)

---

## Environment Variables

Create `.env` file for optional settings:

```bash
cp .env.example .env
# Edit .env and add your API keys
```

**Default values (no .env needed):**
- Database: `postgres://axonflow:localdev123@localhost:5432/axonflow`
- Grafana: `admin / grafana_localdev456`
- License: `AXON-LOCAL-testorg-20250101-testkey12345` (test key)

---

## Community Mode

When running in community mode (`DEPLOYMENT_MODE=community` or unset), authentication is bypassed for local development convenience.

### Configuration

Set the deployment mode in your environment:

```bash
DEPLOYMENT_MODE=community  # Or leave unset (defaults to community)
```

### What Community Mode Does

In community mode:
- Accepts **any** token value (no JWT validation)
- Returns a local dev user with admin permissions
- Grants access to all features (query, llm, mcp_query, admin)
- Skips license validation

### docker-compose.yml Configuration

The included `docker-compose.yml` already has the correct configuration:

```yaml
environment:
  DEPLOYMENT_MODE: community
```

### Enabling Enterprise Mode

For production or secure environments, set the deployment mode to enterprise:

```yaml
environment:
  DEPLOYMENT_MODE: enterprise
  # Requires valid license and JWT authentication
```

### DEPLOYMENT_MODE Values

| Value | Auth Required | Features | Use Case |
|-------|---------------|----------|----------|
| `community` (or unset) | No | Core | Local development |
| `enterprise` | Yes | Core + Enterprise | Production |
| `saas` | Yes | All | Multi-tenant SaaS |

---

## Troubleshooting

### Services won't start
```bash
# Check Docker is running
docker info

# Check port conflicts
lsof -i :5432   # PostgreSQL
lsof -i :8080   # Agent
lsof -i :3000   # Grafana

# Clean start
./scripts/local-dev/stop.sh --clean
./scripts/local-dev/start.sh
```

### Migrations failing
```bash
# View Agent logs (migrations run in Agent)
docker-compose logs agent

# Connect to database directly
docker-compose exec postgres psql -U axonflow -d axonflow

# Check if grafana password is set
docker-compose exec axonflow-agent env | grep GRAFANA_PASSWORD
```

### Grafana can't connect
```bash
# Verify grafana database exists
docker-compose exec postgres psql -U postgres -l | grep grafana

# Verify grafana user exists
docker-compose exec postgres psql -U postgres -c "\du" | grep grafana

# Check migration 017 ran
docker-compose exec postgres psql -U axonflow -d axonflow -c \
  "SELECT version FROM schema_migrations WHERE version = '017';"
```

### Service unhealthy
```bash
# Check service status
docker-compose ps

# View specific service logs
docker-compose logs agent
docker-compose logs orchestrator
docker-compose logs customer-portal

# Restart specific service
docker-compose restart agent
```

---

## Development Workflow

### 1. Make code changes

```bash
# Edit code in your IDE
vim platform/agent/handler.go
```

### 2. Test locally (5-10 minutes)

```bash
# Rebuild and restart
docker-compose build agent
docker-compose up -d agent

# Check logs
docker-compose logs -f agent

# Test endpoint
curl http://localhost:8080/health
```

### 3. Deploy to AWS (only after local testing passes)

```bash
cd /Users/saurabhjain/Development/axonflow-worktree-deployment
./scripts/deploy.sh staging
```

---

## Useful Commands

```bash
# View all service logs
docker-compose logs -f

# Follow specific service
docker-compose logs -f agent

# Check service status
docker-compose ps

# Restart specific service
docker-compose restart agent

# Rebuild after code changes
docker-compose build agent
docker-compose up -d agent

# Access PostgreSQL
docker-compose exec postgres psql -U axonflow -d axonflow

# Access Redis
docker-compose exec redis redis-cli

# Clean restart (fresh database)
./scripts/local-dev/stop.sh --clean
./scripts/local-dev/start.sh
```

---

## Testing End-to-End

```bash
# 1. Start environment
./scripts/local-dev/start.sh

# 2. Verify all services healthy
curl http://localhost:8080/health   # Agent
curl http://localhost:8081/health   # Orchestrator
curl http://localhost:8082/health   # Customer Portal

# 3. Check Prometheus targets
open http://localhost:9090/targets

# 4. View Grafana dashboards
open http://localhost:3000
# Login: admin / grafana_localdev456

# 5. Query database
docker-compose exec postgres psql -U axonflow -d axonflow -c "SELECT * FROM schema_migrations;"
```

---

## Performance

**Local development is MUCH faster than AWS:**

| Task | AWS | Local |
|------|-----|-------|
| Build images | 10-15 min | 3-5 min |
| Start services | 15-20 min | 2-3 min |
| Run migrations | 5 min | 30 sec |
| Debug failure | 20-40 min | 2-5 min |
| **Total cycle** | **2-4 hours** | **5-10 min** |

**Cost savings:**
- AWS: $50-100/day for failed deployments
- Local: $0 (runs on your machine)

---

## Why This Matters for Community Edition

When AxonFlow goes source-available, contributors MUST have fast local testing:

- ✅ Test changes in 5-10 minutes (not 2-4 hours)
- ✅ No AWS account required
- ✅ No deployment costs
- ✅ Standard Docker Compose workflow
- ✅ Easy CI/CD integration
- ✅ Works offline (after images built)

**Without local testing, Community adoption will be slow.**

---

## Next Steps

1. ✅ Test migration 017 locally
2. ✅ Verify all services start successfully
3. ✅ Document any issues found
4. Deploy to AWS with confidence
5. Add this workflow to CONTRIBUTING.md (Community edition prep)

---

## Support

If you encounter issues:
1. Check troubleshooting section above
2. View logs: `docker-compose logs -f`
3. Clean restart: `./scripts/local-dev/stop.sh --clean && ./scripts/local-dev/start.sh`
4. File an issue with logs attached
