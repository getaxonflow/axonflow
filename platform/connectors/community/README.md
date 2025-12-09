# Community Connectors

This directory contains connectors contributed by the AxonFlow community.

## Overview

Community connectors extend AxonFlow's MCP (Model Context Protocol) capabilities by integrating with additional external services. These connectors are contributed by the community and maintained alongside the core OSS connectors.

## Directory Structure

```
community/
├── README.md                 # This file
├── your-connector/           # Each connector in its own directory
│   ├── connector.go          # Implementation
│   ├── connector_test.go     # Tests (required, >65% coverage)
│   └── README.md             # Documentation
└── another-connector/
    ├── connector.go
    ├── connector_test.go
    └── README.md
```

## Available Community Connectors

| Connector | Description | Status |
|-----------|-------------|--------|
| *None yet* | *Be the first contributor!* | - |

## Contributing a New Connector

See [CONTRIBUTING.md](../../../CONTRIBUTING.md#contributing-connectors) for detailed instructions on how to create and submit a new connector.

### Quick Start

1. Create a new directory: `platform/connectors/community/your-connector/`
2. Implement the `Connector` interface from `platform/connectors/base/`
3. Add comprehensive tests with >65% coverage
4. Create a README.md documenting configuration and usage
5. Open a PR on the [axonflow](https://github.com/getaxonflow/axonflow) repository

### Connector Interface

```go
type Connector interface {
    Connect(ctx context.Context, config *ConnectorConfig) error
    Disconnect(ctx context.Context) error
    HealthCheck(ctx context.Context) (*HealthStatus, error)
    Query(ctx context.Context, query *Query) (*QueryResult, error)
    Execute(ctx context.Context, cmd *Command) (*CommandResult, error)
    Name() string
    Type() string
    Version() string
    Capabilities() []string
}
```

## Review Process

Community connectors go through the following review process:

1. **PR Submitted** - Contributor opens a PR with their connector
2. **Automated Checks** - CI runs tests, linting, and coverage checks
3. **Maintainer Review** - A maintainer reviews code quality and security
4. **Feedback Loop** - Contributor addresses any requested changes
5. **Approval & Merge** - Once approved, the connector is merged
6. **Enterprise Sync** - The connector syncs to the enterprise repository

## Guidelines

- **Apache 2.0 License** - All contributions must be Apache 2.0 compatible
- **No External Dependencies** - Minimize dependencies; prefer stdlib
- **Security First** - No hardcoded credentials; use configuration
- **Error Handling** - Use `base.NewConnectorError()` for consistent errors
- **Documentation** - README with config options and usage examples
- **Test Coverage** - Minimum 65% test coverage required

## Questions?

- **GitHub Issues:** https://github.com/getaxonflow/axonflow/issues
- **GitHub Discussions:** https://github.com/getaxonflow/axonflow/discussions
- **Documentation:** https://docs.getaxonflow.com

## License

All community connectors are licensed under Apache 2.0.
