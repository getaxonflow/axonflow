# Contributing to AxonFlow Go SDK

Thank you for your interest in contributing to the AxonFlow Go SDK! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/axonflow-go.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit your changes: `git commit -m "Add your feature"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

```bash
git clone https://github.com/getaxonflow/axonflow-go.git
cd axonflow-go
go mod download
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

### Running Examples

Set up your environment variables:

```bash
export AXONFLOW_AGENT_URL="https://staging-eu.getaxonflow.com"
export AXONFLOW_CLIENT_ID="your-client-id"
export AXONFLOW_CLIENT_SECRET="your-client-secret"
```

Run examples:

```bash
# Basic example
go run examples/basic/main.go

# Connectors example
go run examples/connectors/main.go

# Planning example
go run examples/planning/main.go
```

## Code Style

- Follow standard Go formatting: `go fmt ./...`
- Run linting: `go vet ./...`
- Keep functions focused and well-documented
- Use meaningful variable and function names
- Add comments for exported functions and types

## Pull Request Guidelines

1. **Keep PRs focused**: One feature or fix per PR
2. **Update documentation**: If you change the API, update README.md
3. **Add tests**: All new features should include tests
4. **Pass CI checks**: Ensure all tests pass before submitting
5. **Write clear commit messages**: Describe what and why, not how

### Commit Message Format

```
Add feature: brief description

Detailed explanation of the changes and why they were made.
Any breaking changes should be clearly noted.
```

## Feature Requests

Have an idea for a new feature? We'd love to hear it!

1. Check existing issues to avoid duplicates
2. Open a new issue with the "Feature Request" label
3. Describe the feature and its use case
4. Discuss implementation approach

## Bug Reports

Found a bug? Help us fix it!

1. Check existing issues to avoid duplicates
2. Open a new issue with the "Bug" label
3. Include:
   - Go version
   - Operating system
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Error messages or logs

## Testing

We use Go's built-in testing framework. When adding new features:

1. Add unit tests for new functions
2. Add integration tests for API interactions
3. Ensure test coverage remains high
4. Mock external dependencies when appropriate

Example test structure:

```go
func TestClientExecuteQuery(t *testing.T) {
    client := NewClientSimple("https://example.com", "id", "secret")

    resp, err := client.ExecuteQuery("token", "query", "chat", nil)

    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }

    if resp == nil {
        t.Error("Expected response, got nil")
    }
}
```

## Documentation

- Update README.md for user-facing changes
- Add GoDoc comments for all exported functions and types
- Include usage examples in comments when helpful
- Keep documentation clear and concise

## Code Review Process

1. All PRs require at least one approval
2. Maintainers will review your PR within 3-5 business days
3. Address feedback and update your PR
4. Once approved, a maintainer will merge your PR

## License

By contributing to AxonFlow Go SDK, you agree that your contributions will be licensed under the MIT License.

## Questions?

If you have questions about contributing, feel free to:

- Open a discussion on GitHub
- Email us at dev@getaxonflow.com
- Check our documentation at https://docs.getaxonflow.com

Thank you for contributing to AxonFlow!
