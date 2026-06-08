# Contributing to AxonFlow

Thank you for your interest in contributing to AxonFlow! This guide will help you get started with local development and making contributions.

## Sign your commits — Developer Certificate of Origin (DCO) is required

All contributions to this repository must be **signed off** under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). The DCO is a per-commit affirmation that you wrote the code (or otherwise have the right to submit it) and are licensing it under the same license as the rest of this repository.

Add the sign-off automatically with `-s` (or `--signoff`) on every commit:

```bash
git commit -s -m "your commit message"
```

This appends a trailer like:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match `git config user.name` / `git config user.email`.

If you forgot `-s` on an existing commit, fix it with one of:

```bash
# most recent commit
git commit --amend --signoff --no-edit

# every commit on the current branch
git rebase --signoff origin/main
```

A DCO check runs automatically on every PR opened in the `getaxonflow` org. **PRs with any unsigned commit will be blocked from merging until the missing sign-offs are added.** No exceptions, including for maintainers.

## No partner/customer names in community source

Partner-driven features are named for the **capability** (e.g. `Indonesia`, `KTP`, `OJK`), never for the partner. Partner-specific artifacts (policy bundles, eval configs, partner runbooks) live **gated or internal** (`ee/`, `technical-docs/`, `docs/protected/`) — never in community source. A CI denylist (`.github/partner-name-denylist.txt`, enforced by the Partner Name Denylist workflow and as a fail-closed gate in the community sync) blocks any denylisted name from appearing in synced paths (`platform/`, `migrations/`, `config/seed-data/`, `docs/`, `examples/`, `infra/`) or public docs.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Making Changes](#making-changes)
- [Types of Contributions](#types-of-contributions)
- [Contributing Connectors](#contributing-connectors)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Getting Help](#getting-help)
- [Community](#community)

## Quick Start

Get up and running in 5 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# 2. (Optional) Set up LLM API keys for AI features
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY or ANTHROPIC_API_KEY

# 3. Start local development environment
./scripts/local-dev/start.sh   # Recommended: includes health checks and waits
# OR: docker compose up -d     # Quick start (see README.md)

# 4. Verify all services are healthy
docker compose ps
```

> **Tip:** The `start.sh` script builds images, waits for services to be healthy, and displays all endpoints. For a minimal setup without health checks, use `docker compose up -d` as shown in the main README.

That's it! You now have:
- Agent API running on http://localhost:8080
- Orchestrator API on http://localhost:8081
- Customer Portal on http://localhost:3001
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
docker compose ps

# 3. View logs (optional)
make logs
# OR
docker compose logs -f agent orchestrator

# 4. Test API endpoints
curl http://localhost:8080/health  # Agent
curl http://localhost:8081/health  # Orchestrator
curl http://localhost:3001/health  # Customer Portal
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
docker compose up -d --build axonflow-agent

# View logs for debugging
make logs service=agent
# OR
docker compose logs -f axonflow-agent

# Run tests
make test
# OR
go test ./...

# Stop everything when done
make stop
# OR
docker compose down
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
2. Ensure it fits the Community scope (see [Community vs Enterprise](#community-vs-enterprise))
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

### Community vs Enterprise

AxonFlow follows a source-available model:

**Community (Source-Available) - Contributions Welcome:**
- `platform/agent/` - Core agent functionality
- `platform/orchestrator/` - Policy engine and LLM routing
- `platform/connectors/` - Community connectors (postgres, redis, http, cassandra)
- `platform/connectors/community/` - Community-contributed connectors
- `platform/shared/` - Shared utilities
- `docs/` - Documentation
- `migrations/core/` - Core database migrations

**Enterprise (ee/) - Not Open for Contributions:**
- `ee/platform/connectors/` - Enterprise connectors (Amadeus, Salesforce, Slack, Snowflake)
- `ee/platform/agent/license/` - License validation
- `ee/platform/customers/` - Customer demos

Contributions to the Community codebase are synced from the Community repo to the enterprise repo, ensuring your work benefits all users.

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
├── postgres/          # Community connector example
├── cassandra/         # Community connector example
├── redis/             # Community connector example
└── http/              # Community connector example
```

**Community vs Enterprise Connectors:**
- **Community connectors** (`postgres`, `cassandra`, `redis`, `http`): Full implementations, included in source-available release
- **Community-contributed connectors** (`community/*`): Contributed by the community, included in source-available release
- **Enterprise connectors** (`ee/platform/connectors/*`): Commercial features with Community stubs

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
- **Testing:** Minimum 76% test coverage required
- **Documentation:** README with configuration and usage examples
- **Dependencies:** Minimize external dependencies
- **Security:** No hardcoded credentials, use configuration
- **Error Handling:** Wrap errors with context using `base.NewConnectorError()`

### Example Community Connectors

See existing Community connectors for reference:
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
- Aim for >76% test coverage
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
- [ ] **Bug fixes include a regression test** (see [Regression-test-per-bug](#regression-test-per-bug))

### Regression-test-per-bug

Every bug-fix PR must include a test at the layer that failed. This is W12 of
the [Quality Freeze epic](https://github.com/getaxonflow/axonflow-enterprise/issues/1697)
and is enforced in CI by `.github/workflows/regression-test-required.yml`
(QF-19, issue #1732).

**When the gate runs**

A PR is treated as a bug fix when either:

- The PR title matches the Conventional Commits "fix" type — `fix:`,
  `fix(scope):`, `fix!:` (breaking), or `fix(scope)!:` — or
- The PR carries the `bug` label.

**What the gate accepts**

The gate scans the PR diff for at least one **added or modified** file
matching one of these patterns. Deletions and pure renames do **not** satisfy
the gate (`git diff --diff-filter=AM --no-renames`):

| Layer        | Pattern                                                                |
|--------------|------------------------------------------------------------------------|
| Go           | `*_test.go`                                                            |
| Python       | `*_test.py`                                                            |
| TypeScript   | `*.test.ts`, `*.test.tsx`, `*.spec.ts`, `*.spec.tsx`                   |
| Java         | `*Test.java`, `*Tests.java`, `*IT.java`                                |
| Any language | a file under a `tests/` or `test/` directory **with a code extension** |

The directory branch is restricted to code extensions: `.go`, `.py`, `.ts`,
`.tsx`, `.java`, `.sh`, `.rb`, `.rs`, `.kt`. Non-code churn under `tests/`
(JSON snapshots, YAML fixtures, markdown helpers, CSV goldens, images, etc.)
does **not** satisfy the gate — the test must exercise the failing layer.

The matcher's behaviour is pinned by
`tests/regression-test-required/path_pattern_test.sh`; run it locally if you
edit the pattern.

**Why "added or modified" only:** the previous version of the gate accepted any
changed test path, so the gate could be satisfied by deleting `foo_test.go`,
renaming an unrelated test, or touching a comment in a `tests/` fixture. Bug
fixes need new or updated regression coverage at the failing layer — deletions
don't add coverage and pure renames don't change behaviour.

**Why code-extension only under `tests/`:** the directory branch was originally
permissive — any path under `tests/` counted, including JSON snapshots, YAML
fixtures, and markdown notes. That let a bug-fix PR satisfy the gate without
adding executable coverage. The matcher now requires a code extension on the
directory branch, closing the loophole. The naming-convention branches
(`*_test.go`, `*Test.java`, `*.test.tsx`, etc.) already imply code, so they
are unchanged.

**Choosing the right layer**

Match the test to where the bug was caught:

| Bug surfaced via                          | Add a test at                                                  |
|-------------------------------------------|----------------------------------------------------------------|
| Live `docker-compose` E2E run             | `examples/` example or `tests/integration/`                    |
| Portal UI regression                      | Playwright spec under `ee/platform/customer-portal-ui/e2e/`    |
| Wrong wire shape between SDK and platform | SDK contract test plus an integration test that exercises the path |
| Handler enforcement / tier gate           | `*_test.go` under the handler's package                        |
| Cross-plane parity (WCP/MAP)              | `*_parity_test.go` under `platform/orchestrator/` (e.g. `hitl_response_parity_test.go`, `pending_approvals_plane_parity_test.go`) |
| Migration / backfill                      | A historical-fixture test (Phase 2 QF-22)                      |

**Escape hatch: `regression-test-exempt`**

A small set of changes legitimately can't be tested at the layer that failed:

- Pure infra changes (CFN/Terraform, IAM, GitHub Actions plumbing) where the
  failure mode is the deploy itself
- Generated-artifact regenerations (e.g. regenerated SDK clients) where the
  generator already has tests
- Build-config and dependency bumps with no executable behaviour change
- Documentation-only fixes that happen to match the `fix(docs):` Conventional
  Commits prefix

Apply the `regression-test-exempt` label and **justify in the PR body under
the "If exempt" section** of the PR template. Reviewers must confirm the
exemption is genuine; an exemption is not a license to skip writing a test
that *could* exist.

**Why this rule exists**

Per the QF epic post-mortem, a meaningful share of v7.x post-release bugs were
caught in the next release cycle by a test that we hadn't written yet. Forcing
the test into the same PR as the fix is the cheapest place to catch the next
recurrence. See `axonflow-internal-docs/engineering/QUALITY_FREEZE_EPIC_2026-04-24.md`
for the full motivation.

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
docker compose logs -f axonflow-agent

# Check service health
curl http://localhost:8080/health

# Connect to database
docker compose exec postgres psql -U axonflow -d axonflow

# Restart a service
docker compose restart axonflow-agent
```

### Database Migrations

```bash
# Create new migration
touch migrations/NNN_description.sql

# Test migration
./scripts/local-dev/test-migrations.sh

# Verify in database
docker compose exec postgres psql -U axonflow -d axonflow -c "\\dt"
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
docker compose down
lsof -i :8080
kill -9 <PID>
```

**Migrations fail:**
```bash
docker compose down -v  # WARNING: loses data
make start
```

## Legal

By submitting a Pull Request, you disavow any rights or claims to any changes submitted to the AxonFlow project and assign the copyright of those changes to AxonFlow, Inc.

If you cannot or do not want to reassign those rights (your employment contract for your employer may not allow this), you should not submit a PR. Open an issue and someone else can do the work.

This is a legal requirement for all contributions to AxonFlow.

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- GitHub contributor graph

## Community

Join our growing community of developers building AI governance solutions:
- [GitHub Discussions](https://github.com/getaxonflow/axonflow/discussions) - Ask questions and share ideas
- [Issue Tracker](https://github.com/getaxonflow/axonflow/issues) - Report bugs and request features

Thank you for contributing to AxonFlow!
