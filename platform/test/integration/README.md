# Usage Recording Integration Tests

This directory contains integration tests for the AxonFlow usage recording system. These tests verify end-to-end functionality from API requests to database storage.

## Overview

The usage recording system tracks:
- **API Calls**: Every HTTP request to AxonFlow agents
- **LLM Requests**: AI model inference calls with token counts and costs

Integration tests verify:
1. ✅ API calls are recorded to `usage_events` table
2. ✅ LLM requests with tokens/costs are recorded
3. ✅ Concurrent requests don't cause race conditions
4. ✅ Database failures don't block API requests

## Prerequisites

- PostgreSQL 15+ (local or Docker)
- Go 1.23+
- AxonFlow agent running (local or remote)

## Quick Start

### 1. Setup Test Environment

```bash
cd /Users/saurabhjain/Development/axonflow/platform/test/integration
./setup_test_env.sh
```

This script will:
- Create test database (or use existing)
- Apply migrations
- Create test organization with license key
- Generate `.env.test` file

### 2. Start AxonFlow Agent (if not already running)

```bash
# Option A: Use existing production agent
export TEST_AGENT_URL="http://63.178.85.84:8080"

# Option B: Start local agent for testing
cd ../../agent
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/axonflow_test?sslmode=disable"
export ORCHESTRATOR_URL="http://localhost:8081"
go run main.go
```

### 3. Run Integration Tests

```bash
# Source environment variables
source .env.test

# Run all integration tests
go test -v

# Run specific test
go test -v -run TestAPICallRecording

# Skip slow tests
go test -short
```

## Test Cases

### TestAPICallRecording
- **Duration**: ~10 seconds
- **Tests**: API request → usage_events record
- **Verifies**: org_id, http_method, http_path, status_code, latency_ms

### TestLLMRequestRecording
- **Duration**: ~15 seconds
- **Tests**: API request → LLM call → usage_events record
- **Verifies**: llm_provider, llm_model, tokens, cost_cents

### TestConcurrentRecording
- **Duration**: ~20 seconds
- **Tests**: 10 concurrent requests → all events recorded
- **Verifies**: No race conditions, no lost events

### TestRecordingDoesNotBlockRequests
- **Duration**: ~5 seconds
- **Tests**: API requests complete quickly despite async recording
- **Verifies**: Latency < 30 seconds (implies async recording)

## Configuration

Environment variables (set by `setup_test_env.sh`):

```bash
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/axonflow_test?sslmode=disable
TEST_AGENT_URL=http://localhost:8080
TEST_LICENSE_KEY=AXON-ENT-test-integration-usage-20261101-12345678
TEST_ORG_ID=test-integration-usage
```

## Troubleshooting

### Test fails with "TEST_DATABASE_URL not set"
```bash
source .env.test  # Make sure to source environment variables
```

### Test fails with connection refused
```bash
# Check if agent is running
curl http://localhost:8080/health

# Check if PostgreSQL is running
pg_isready -h localhost -p 5432
```

### Test fails with "organization not found"
```bash
# Re-run setup script
./setup_test_env.sh
```

### Tests are slow (> 30 seconds)
- This is expected for LLM tests (they make real OpenAI/Anthropic calls)
- Use `go test -short` to skip slow tests
- Or mock LLM responses in test agent

## Cleanup

To remove test data and containers:

```bash
./cleanup_test_env.sh
```

This will:
- Delete test organization
- Delete test usage events
- Stop and remove test PostgreSQL container (if started by setup script)

## Architecture

Integration tests use the **real stack**:

```
Integration Test
    ↓ HTTP POST
Agent (real instance)
    ↓ async goroutine
usage.RecordAPICall()
    ↓ SQL INSERT
PostgreSQL (test database)
    ↓ SELECT
Integration Test (verify)
```

This differs from unit tests which use:
- Mocked databases (sqlmock)
- Mocked HTTP handlers
- No actual network calls

## CI/CD Integration

To run integration tests in CI/CD:

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: axonflow_test
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.23'

      - name: Setup test environment
        run: |
          cd platform/test/integration
          ./setup_test_env.sh

      - name: Run integration tests
        run: |
          cd platform/test/integration
          source .env.test
          go test -v
```

## Future Improvements

1. **Mock LLM responses** - Speed up tests by mocking OpenAI/Anthropic
2. **Performance tests** - Measure recording overhead under load
3. **Error injection tests** - Simulate database failures gracefully
4. **Multi-region tests** - Verify recording across distributed agents
5. **Cost calculation tests** - Verify pricing for all LLM providers

## Related Documentation

- [Usage Metering Architecture](../../../technical-docs/USAGE_METERING_ARCHITECTURE.md)
- [Customer Portal Architecture](../../../technical-docs/CUSTOMER_PORTAL_ARCHITECTURE.md)
- [Comprehensive Test Plan](../../../../tmp/COMPREHENSIVE_TEST_PLAN_NOV01.md)
