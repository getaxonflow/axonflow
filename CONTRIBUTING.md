# Contributing to AxonFlow

Thank you for your interest in contributing to AxonFlow! This guide will help you get started with local development and making contributions.

## Table of Contents

- [Contributor License Agreement](#contributor-license-agreement)
- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Making Changes](#making-changes)
- [Types of Contributions](#types-of-contributions)
- [Contributing Connectors](#contributing-connectors)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Getting Help](#getting-help)

## Contributor License Agreement

Before your first contribution can be merged, you must sign our [Contributor License Agreement (CLA)](.github/CLA.md).

### Why We Require a CLA

The CLA protects both you and AxonFlow:
- **For you**: Confirms you have the right to submit the code and protects your rights as the author
- **For the project**: Ensures we can legally distribute your contributions under the Apache 2.0 license
- **For users**: Provides assurance that the code they're using has clear legal provenance

### How to Sign

When you open your first pull request:

1. The CLA Assistant bot will automatically check if you've signed
2. If you haven't signed, it will post a comment with instructions
3. Simply reply with: `I have read the CLA Document and I hereby sign the CLA`
4. That's it! Your signature is recorded and applies to all future contributions

**This is a one-time process** - once signed, all your future PRs are covered.

### Corporate Contributors

If you're contributing on behalf of your employer, please ensure you have authorization to do so. The CLA includes provisions for corporate contributions.

## Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# 2. Start local development environment
./scripts/local-dev/start.sh

# 3. Verify all services are healthy (takes ~30 seconds)
docker-compose ps
```

That's it! You now have:
- Agent API running on http://localhost:8080
- Orchestrator API on http://localhost:8081
- Customer Portal on http://localhost:8082
- Grafana dashboards on http://localhost:3000 (admin / grafana_localdev456)
- Prometheus metrics on http://localhost:9090
- PostgreSQL on localhost:5432

## Development Environment

### Prerequisites

**Required:**
- Docker Desktop (or Docker Engine + Docker Compose)
- Git
- macOS, Linux, or Windows with WSL2

**Optional (for contributing):**
- Go 1.25+ (for running tests locally without Docker)
- Node.js 18+ (for frontend work)
- make (usually pre-installed on macOS/Linux)

### Local Development Setup

AxonFlow uses Docker Compose for local development, providing a complete environment that matches AWS production.

**Why Docker Compose?**
- 5-10 minute feedback loop (vs 2-4 hours with AWS)
- Zero cost (vs $50-100/day AWS testing)
- Works identically to production
- No AWS account needed for development

### First Time Setup

```bash
# 1. Start all services
make start
# OR
./scripts/local-dev/start.sh

# 2. Check service health (should see all "healthy")
make status
# OR
docker-compose ps

# 3. View logs (optional)
make logs
# OR
docker-compose logs -f agent orchestrator

# 4. Test API endpoints
curl http://localhost:8080/health  # Agent
curl http://localhost:8081/health  # Orchestrator
curl http://localhost:8082/health  # Customer Portal
```

### Daily Development Workflow

```bash
# Start services (if not running)
make start

# Make code changes in your editor
vim platform/agent/main.go

# Rebuild and restart specific service
make rebuild service=agent
# OR
docker-compose up -d --build axonflow-agent

# View logs for debugging
make logs service=agent
# OR
docker-compose logs -f axonflow-agent

# Run tests
make test
# OR
go test ./...

# Stop everything when done
make stop
# OR
docker-compose down
```

## Making Changes

### Branch Strategy

```bash
# 1. Create a feature branch
git checkout -b feat/your-feature-name

# 2. Make your changes
# ... edit files ...

# 3. Test locally
make test
make start  # Verify in Docker Compose

# 4. Commit with conventional commits format
git add .
git commit -m "feat(agent): add new MCP connector for XYZ"

# 5. Push to your fork
git push origin feat/your-feature-name

# 6. Open a Pull Request on GitHub
```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

**Examples:**
```bash
feat(agent): add support for Anthropic Claude Opus
fix(orchestrator): prevent memory leak in policy cache
docs: update local development guide
test(connectors): add integration tests for Amadeus API
```

## Types of Contributions

We welcome all types of contributions to AxonFlow! Here are some ways you can contribute:

### Bug Fixes
Found a bug? We'd love your help fixing it:
1. Check existing issues or create a new one describing the bug
2. Fork the repo and create a fix on a feature branch
3. Write tests to prevent regression
4. Submit a PR referencing the issue

### New Features
Want to add functionality? Great!
1. Open an issue to discuss the feature first
2. Ensure it fits the OSS scope (see [OSS vs Enterprise](#oss-vs-enterprise))
3. Implement with tests and documentation
4. Submit a PR

### Documentation
Help us improve our docs:
- Fix typos or unclear explanations
- Add examples and tutorials
- Improve API documentation
- Translate documentation

### Test Improvements
Help us maintain quality:
- Add missing test cases
- Improve test coverage
- Add integration tests
- Fix flaky tests

### Performance Improvements
Make AxonFlow faster:
- Profile and identify bottlenecks
- Optimize critical paths
- Reduce memory usage
- Improve startup time

### OSS vs Enterprise

AxonFlow follows an open-core model:

**OSS (Open Source) - Contributions Welcome:**
- `platform/agent/` - Core agent functionality
- `platform/orchestrator/` - Policy engine and LLM routing
- `platform/connectors/` - OSS connectors (postgres, redis, http, cassandra)
- `platform/connectors/community/` - Community-contributed connectors
- `platform/shared/` - Shared utilities
- `docs/` - Documentation
- `migrations/core/` - Core database migrations

**Enterprise (ee/) - Not Open for Contributions:**
- `ee/platform/connectors/` - Enterprise connectors (Amadeus, Salesforce, Slack, Snowflake)
- `ee/platform/agent/license/` - License validation
- `ee/platform/customers/` - Customer demos

Contributions to the OSS codebase are synced from the OSS repo to the enterprise repo, ensuring your work benefits all users.

## Contributing Connectors

AxonFlow uses the Model Context Protocol (MCP) for connecting to external data sources. Community connectors are a great way to contribute!

### Understanding the Connector Architecture

**Directory Structure:**
```
platform/connectors/
├── base/              # Base interface (Connector interface)
├── community/         # Community-contributed connectors
│   └── your-connector/
│       ├── connector.go
│       └── connector_test.go
├── config/            # Configuration loading
├── registry/          # Connector registry
├── postgres/          # OSS connector example
├── cassandra/         # OSS connector example
├── redis/             # OSS connector example
└── http/              # OSS connector example
```

**OSS vs Enterprise Connectors:**
- **OSS connectors** (`postgres`, `cassandra`, `redis`, `http`): Full implementations, included in open source
- **Community connectors** (`community/*`): Contributed by the community, included in open source
- **Enterprise connectors** (`ee/platform/connectors/*`): Commercial features with OSS stubs

### Creating a New Connector

#### Step 1: Implement the Connector Interface

Your connector must implement the `Connector` interface from `platform/connectors/base`:

```go
package yourconnector

import (
    "context"
    "axonflow/platform/connectors/base"
)

type YourConnector struct {
    config *base.ConnectorConfig
    // your fields here
}

func NewYourConnector() *YourConnector {
    return &YourConnector{}
}

// Connect establishes connection to the external service
func (c *YourConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
    c.config = config
    // Initialize your client here
    return nil
}

// Disconnect closes the connection
func (c *YourConnector) Disconnect(ctx context.Context) error {
    // Cleanup resources
    return nil
}

// HealthCheck verifies the service is accessible
func (c *YourConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
    // Check connectivity
    return &base.HealthStatus{Healthy: true}, nil
}

// Query executes a read operation
func (c *YourConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
    // Implement query logic based on query.Statement
    return &base.QueryResult{Data: yourData}, nil
}

// Execute executes a write operation
func (c *YourConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
    // Implement write/mutation logic
    return &base.CommandResult{Success: true}, nil
}

// Name returns the connector instance name
func (c *YourConnector) Name() string {
    return c.config.Name
}

// Type returns the connector type
func (c *YourConnector) Type() string {
    return "your-connector-type"
}

// Version returns the connector version
func (c *YourConnector) Version() string {
    return "1.0.0"
}

// Capabilities returns the list of capabilities
func (c *YourConnector) Capabilities() []string {
    return []string{"query", "execute"}
}
```

#### Step 2: Add Comprehensive Tests

```go
package yourconnector_test

import (
    "context"
    "testing"

    "axonflow/platform/connectors/base"
    yourconnector "axonflow/platform/connectors/community/your-connector"
)

func TestConnect(t *testing.T) {
    c := yourconnector.NewYourConnector()

    config := &base.ConnectorConfig{
        Name:      "test-connector",
        Type:      "your-connector-type",
        Settings: map[string]interface{}{
            "endpoint": "https://api.example.com",
        },
    }

    err := c.Connect(context.Background(), config)
    if err != nil {
        t.Fatalf("Connect failed: %v", err)
    }

    defer c.Disconnect(context.Background())

    // Test health check
    status, err := c.HealthCheck(context.Background())
    if err != nil || !status.Healthy {
        t.Fatalf("HealthCheck failed: %v", err)
    }
}

func TestQuery(t *testing.T) {
    // Test your query operations
}

func TestExecute(t *testing.T) {
    // Test your execute operations
}
```

#### Step 3: Document Your Connector

Create a README.md in your connector directory:

```markdown
# Your Connector Name

Connector for [External Service Name](https://example.com).

## Configuration

| Setting | Type | Required | Description |
|---------|------|----------|-------------|
| endpoint | string | Yes | API endpoint URL |
| api_key | string | Yes | API key for authentication |

## Supported Operations

### Queries
- `list_items` - List all items
- `get_item` - Get item by ID

### Commands
- `create_item` - Create new item
- `update_item` - Update existing item

## Example Usage

\`\`\`yaml
connectors:
  - name: my-service
    type: your-connector-type
    settings:
      endpoint: https://api.example.com
      api_key: ${YOUR_API_KEY}
\`\`\`
```

### Submitting Your Connector

1. **Create your connector** in `platform/connectors/community/your-connector/`
2. **Write tests** with >65% coverage
3. **Add documentation** (README.md in your connector folder)
4. **Open a PR** on the [axonflow](https://github.com/getaxonflow/axonflow) repository
5. **Wait for review** - a maintainer will review and provide feedback
6. **Address feedback** - make requested changes
7. **Get merged** - once approved, your connector is imported to the main codebase

### Connector Contribution Guidelines

- **License:** All contributions must be Apache 2.0 compatible
- **Testing:** Minimum 65% test coverage required
- **Documentation:** README with configuration and usage examples
- **Dependencies:** Minimize external dependencies
- **Security:** No hardcoded credentials, use configuration
- **Error Handling:** Wrap errors with context using `base.NewConnectorError()`

### Example Community Connectors

See existing OSS connectors for reference:
- `platform/connectors/postgres/` - PostgreSQL connector
- `platform/connectors/http/` - Generic HTTP connector
- `platform/connectors/redis/` - Redis connector

## Testing

### Running Tests Locally

```bash
# Run all tests
make test

# Run tests for specific module
cd platform/agent && go test ./...

# Run with coverage
make test-coverage

# Test migrations
./scripts/local-dev/test-migrations.sh
```

### Test Coverage Requirements

- All new code should have tests
- Aim for >65% test coverage
- Integration tests for critical paths

## Submitting Changes

### Pull Request Checklist

Before submitting:

- [ ] Code builds successfully (`make build`)
- [ ] All tests pass (`make test`)
- [ ] Linting passes (`golangci-lint run ./...`)
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow conventional commits
- [ ] Local Docker Compose testing completed

## Code Style

### Go Code Style

```bash
# Format code
gofmt -s -w .

# Run linter
golangci-lint run ./...
```

**Guidelines:**
- Use `gofmt` for formatting
- Always check and handle errors
- Document all public functions/types
- Keep functions small and focused

## Common Tasks

### Debugging Issues

```bash
# View all logs
make logs

# View specific service logs
docker-compose logs -f axonflow-agent

# Check service health
curl http://localhost:8080/health

# Connect to database
docker-compose exec postgres psql -U axonflow -d axonflow

# Restart a service
docker-compose restart axonflow-agent
```

### Database Migrations

```bash
# Create new migration
touch migrations/NNN_description.sql

# Test migration
./scripts/local-dev/test-migrations.sh

# Verify in database
docker-compose exec postgres psql -U axonflow -d axonflow -c "\\dt"
```

## Getting Help

### Resources

- **Documentation:** https://docs.getaxonflow.com
- **GitHub Issues:** https://github.com/getaxonflow/axonflow/issues
- **GitHub Discussions:** https://github.com/getaxonflow/axonflow/discussions

### Asking Questions

1. Check existing issues and discussions
2. Review documentation
3. Provide context and error messages
4. Share relevant code snippets

## Project Structure

```
axonflow/
├── platform/                   # Core platform services
│   ├── agent/                  # AxonFlow Agent
│   ├── orchestrator/           # LLM orchestration
│   ├── customer-portal/        # Customer management
│   └── connectors/             # MCP connectors
│
├── migrations/                 # Database migrations
├── scripts/local-dev/          # Local development helpers
├── docs/                       # Documentation
├── config/                     # Configuration files
├── docker-compose.yml          # Local development environment
└── Makefile                    # Development commands
```

## Troubleshooting

### Common Issues

**Services won't start:**
```bash
make clean
make start
```

**Port already in use:**
```bash
docker-compose down
lsof -i :8080
kill -9 <PID>
```

**Migrations fail:**
```bash
docker-compose down -v  # WARNING: loses data
make start
```

## License

By contributing to AxonFlow, you agree that your contributions will be licensed under the Apache 2.0 license. All contributors must sign our [Contributor License Agreement (CLA)](.github/CLA.md) before their first contribution can be merged.

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- GitHub contributor graph

Thank you for contributing to AxonFlow!
