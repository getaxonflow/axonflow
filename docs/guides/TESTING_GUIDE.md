# AxonFlow Platform - Testing Guide

**Version**: 3.1
**Last Updated**: December 6, 2025
**Agent Coverage**: 74.9% ✅ (Threshold: 74%)
**Orchestrator Coverage**: 73.0% ✅ (Threshold: 72%)
**Connectors Coverage**: 68.6% ✅ (Threshold: 66%)
**Status**: ✅ Production-ready (200+ tests passing)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Test Architecture](#test-architecture)
3. [Running Tests](#running-tests)
4. [Writing New Tests](#writing-new-tests)
5. [Coverage Requirements](#coverage-requirements)
6. [CI/CD Integration](#cicd-integration)
7. [Debugging Test Failures](#debugging-test-failures)
8. [Best Practices](#best-practices)

---

## Quick Start

### Run Agent Tests (74.9% Coverage)
```bash
cd platform/agent
go test -v -cover
```

**Expected Output**:
```
=== RUN   TestValidateClientLicense
--- PASS: TestValidateClientLicense (0.00s)
...
PASS
coverage: 74.9% of statements
ok      axonflow/platform/agent    8.430s
```

### Run Orchestrator Tests (73.0% Coverage)
```bash
cd platform/orchestrator
go test -v -cover
```

**Expected Output**:
```
=== RUN   TestNewLLMRouter
--- PASS: TestNewLLMRouter (0.00s)
...
PASS
coverage: 73.0% of statements
ok      axonflow/platform/orchestrator    86.117s
```

### Run Specific Test Suite

**Agent Tests:**
```bash
cd platform/agent

# Database authentication tests
go test -v -run TestValidateClientLicenseDB

# Redis rate limiting tests
go test -v -run TestCheckRateLimitRedis

# MCP connector tests
go test -v -run TestInitializeMCPRegistry

# Policy engine tests
go test -v -run TestEvaluateStaticPolicies
```

**Orchestrator Tests:**
```bash
cd platform/orchestrator

# Policy engine tests only
go test -v -run TestEvaluateStaticPolicies

# LLM router tests only
go test -v -run TestLLMRouter

# Integration tests only
go test -v -run TestEndToEnd
```

### Run with Race Detection
```bash
go test -v -race
```

### Generate Coverage Report
```bash
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

---

## Test Architecture

### File Organization

```
platform/
├── agent/
│   ├── auth_test.go                    # 9 tests - License & JWT validation
│   ├── static_policies_test.go         # 15 tests - SQL injection, PII detection
│   └── db_policies_test.go             # 8 tests - Table/column access control
├── orchestrator/
│   ├── llm_router_test.go              # 16 tests - Provider management
│   ├── dynamic_policy_engine_test.go   # 16 tests - Risk scoring, context policies
│   ├── workflow_engine_test.go         # 21 tests - Workflow execution
│   ├── planning_engine_test.go         # 22 tests - Query analysis, plan generation
│   ├── integration_test.go             # 10 tests - End-to-end workflows
│   └── phase7_test.go                  # 29 tests - Result aggregator, metrics, PII
└── shared/
    └── logger/
        └── logger_test.go              # 8 tests - Structured logging
```

### Test Categories

| Category | Files | Tests | Purpose |
|----------|-------|-------|---------|
| **Unit Tests** | 8 files | 102 tests | Individual component behavior |
| **Integration Tests** | 1 file | 10 tests | Multi-component workflows |
| **Security Tests** | 3 files | 39 tests | Policy enforcement, PII protection |
| **Performance Tests** | Embedded | ~15 benchmarks | Latency, throughput validation |

---

## Running Tests

### Local Development

#### Basic Test Run
```bash
# From project root
cd platform/orchestrator
go test -v

# Run specific test
go test -v -run TestNewLLMRouter

# Run tests matching pattern
go test -v -run ".*Policy.*"
```

#### With Coverage
```bash
# Show coverage percentage
go test -cover

# Generate detailed coverage report
go test -coverprofile=coverage.out
go tool cover -func=coverage.out | grep total

# Visual coverage report
go tool cover -html=coverage.out
```

#### Race Condition Detection
```bash
# Critical before production deployment
go test -race

# Run specific test with race detector
go test -race -run TestConcurrentMetricRecording
```

#### Verbose Output with Timing
```bash
go test -v -timeout 30s
```

### CI/CD Pipeline

#### GitHub Actions (Conceptual)
```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run Unit Tests
        run: |
          cd platform/orchestrator
          go test -v -cover -coverprofile=coverage.out

      - name: Check Coverage Threshold
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$coverage < 40.0" | bc -l) )); then
            echo "Coverage $coverage% is below 40% threshold"
            exit 1
          fi

      - name: Race Detection
        run: go test -race ./...

      - name: Integration Tests
        run: go test -v -run "TestEndToEnd|TestIntegration"
```

#### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running tests before commit..."
cd platform/orchestrator
go test -short

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Commit aborted."
    exit 1
fi

echo "✅ All tests passed!"
```

### Pre-deployment Validation

```bash
#!/bin/bash
# scripts/pre-deploy-test.sh

set -e

echo "🧪 Running pre-deployment test suite..."

# 1. Unit tests with coverage
echo "Running unit tests..."
go test -v -cover ./platform/...

# 2. Race detection
echo "Running race detector..."
go test -race ./platform/...

# 3. Integration tests
echo "Running integration tests..."
go test -v -run "TestIntegration" ./platform/orchestrator/

# 4. Coverage check
coverage=$(go test -cover ./platform/orchestrator | grep coverage | awk '{print $2}' | sed 's/%//')
if (( $(echo "$coverage < 40.0" | bc -l) )); then
    echo "❌ Coverage $coverage% is below 40% threshold"
    exit 1
fi

echo "✅ All pre-deployment tests passed!"
echo "📊 Coverage: $coverage%"
```

---

## Writing New Tests

### Test Function Naming Convention

```go
// ✅ GOOD: Clear, descriptive names
func TestLLMRouterFailover(t *testing.T) {}
func TestPIIDetection_SSN(t *testing.T) {}
func TestWorkflowExecution_WithTimeout(t *testing.T) {}

// ❌ BAD: Vague or generic names
func TestCase1(t *testing.T) {}
func TestFunction(t *testing.T) {}
func Test1(t *testing.T) {}
```

### Table-Driven Test Pattern

```go
func TestPIIDetection(t *testing.T) {
    detector := NewPIIDetector()

    tests := []struct {
        name        string
        input       string
        shouldDetect bool
        piiType     string
    }{
        {
            name:        "Valid SSN",
            input:       "My SSN is 123-45-6789",
            shouldDetect: true,
            piiType:     "ssn",
        },
        {
            name:        "Valid Email",
            input:       "Contact: user@example.com",
            shouldDetect: true,
            piiType:     "email",
        },
        {
            name:        "No PII",
            input:       "Normal text",
            shouldDetect: false,
            piiType:     "",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            detected := detector.detectPII(tt.input)

            hasDetection := len(detected) > 0
            if hasDetection != tt.shouldDetect {
                t.Errorf("Expected detection=%v, got %v",
                    tt.shouldDetect, hasDetection)
            }
        })
    }
}
```

### Mocking External Dependencies

```go
// TestMockProvider simulates LLM API without external calls
type TestMockProvider struct {
    shouldFail bool
}

func (m *TestMockProvider) Call(ctx context.Context, req LLMRequest) (*LLMResponse, error) {
    if m.shouldFail {
        return nil, errors.New("simulated failure")
    }

    return &LLMResponse{
        Content:  "Mocked response",
        Model:    "test-model",
        TokensUsed: 100,
    }, nil
}

func TestLLMRouterWithMock(t *testing.T) {
    router := &LLMRouter{
        providers: map[string]LLMProvider{
            "test": &TestMockProvider{shouldFail: false},
        },
    }

    resp, err := router.RouteRequest(ctx, req)
    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if resp.Content != "Mocked response" {
        t.Errorf("Expected mocked response, got: %s", resp.Content)
    }
}
```

### Testing Goroutine Safety

```go
func TestConcurrentMetricRecording(t *testing.T) {
    collector := NewMetricsCollector()
    done := make(chan bool, 100)

    // Launch 100 concurrent operations
    for i := 0; i < 100; i++ {
        go func() {
            collector.RecordRequest("sql", "openai", 50*time.Millisecond)
            done <- true
        }()
    }

    // Wait for all goroutines
    for i := 0; i < 100; i++ {
        <-done
    }

    metrics := collector.GetMetrics()
    if metrics.RequestMetrics["sql"].TotalRequests != 100 {
        t.Errorf("Expected 100 requests, got %d (thread safety issue)",
            metrics.RequestMetrics["sql"].TotalRequests)
    }
}
```

### Edge Case Testing

```go
func TestAggregateEmptyResults(t *testing.T) {
    aggregator := NewResultAggregator(router)

    // Test with empty task results
    taskResults := []StepExecution{}

    result, err := aggregator.AggregateResults(ctx, taskResults, "query", user)

    // Should return error for empty results
    if err == nil {
        t.Error("Expected error for empty results")
    }
}

func TestNilPointerSafety(t *testing.T) {
    // Ensure nil inputs don't cause panics
    processor := NewResponseProcessor()

    // This should not panic
    processed, info := processor.ProcessResponse(ctx, user, nil)

    if processed != nil {
        t.Error("Expected nil response for nil input")
    }
}
```

---

## Coverage Requirements

### Current Baseline (December 2025)
- **Per-Module Thresholds**: Enforced per module (agent: 74%, orchestrator: 72%, connectors: 66%)
- **Current Overall**: ~72% across platform
- **CI Enforcement**: Thresholds enforced in GitHub Actions - builds fail if coverage drops

### Coverage by Component (December 2025)

| Component | Threshold | Current | Status |
|-----------|-----------|---------|--------|
| **Agent** | 74% | 74.9% | ✅ Passing |
| **Orchestrator** | 72% | 73.0% | ✅ Passing |
| **Connectors (total)** | 66% | 68.6% | ✅ Passing |
| - postgres | - | 86.7% | ✅ |
| - redis | - | 92.7% | ✅ |
| - http | - | 82.1% | ✅ |
| - config | - | 73.5% | ✅ |
| - mysql | - | 40.1% | ⚠️ |
| - cassandra | - | 34.2% | ⚠️ |
| - mongodb | - | 27.6% | ⚠️ |

### New Code Requirements

When adding new code:
1. **Critical Security Code**: Minimum 90% coverage
   - Authentication, authorization
   - Policy enforcement
   - PII handling

2. **Business Logic**: Minimum 70% coverage
   - Workflow execution
   - Planning engine
   - Result aggregation

3. **Utility Functions**: Minimum 50% coverage
   - Logging, metrics
   - Configuration loading

### Measuring Coverage

```bash
# Overall coverage
go test -cover ./...

# Detailed coverage by function
go test -coverprofile=coverage.out
go tool cover -func=coverage.out

# Example output:
# axonflow/platform/orchestrator/llm_router.go:45:    NewLLMRouter         100.0%
# axonflow/platform/orchestrator/llm_router.go:72:    RouteRequest         87.5%
# axonflow/platform/orchestrator/llm_router.go:134:   failover             100.0%

# Visual HTML report
go tool cover -html=coverage.out
```

---

## CI/CD Integration

### ✅ ACTIVE: GitHub Actions Workflow

**Status**: 🟢 **LIVE** - Automatically runs on every push
**Location**: `.github/workflows/test.yml`
**Triggers**: Push to main/develop, Pull Requests
**Coverage Threshold**: 40% (enforced)

#### Viewing Test Results

**Check Current Status**:
```bash
# Visit your repository on GitHub
https://github.com/getaxonflow/axonflow/actions

# Or check from CLI
gh run list --workflow=test.yml --limit 5
gh run view <run-id>
```

**What Runs Automatically**:

1. **Orchestrator Tests** (15 min timeout)
   - All 112 tests
   - Coverage calculation
   - 40% threshold enforcement
   - HTML coverage report artifact

2. **Agent Tests** (10 min timeout)
   - Static policy tests
   - Database policy tests
   - Authentication tests

3. **Shared Tests** (5 min timeout)
   - Logger tests
   - Utility tests

4. **Race Detector** (15 min timeout)
   - Goroutine safety validation
   - Concurrent execution checks

5. **Integration Tests** (10 min timeout)
   - End-to-end workflows
   - Multi-component coordination

6. **Test Summary**
   - Aggregates all job results
   - Fails if any job fails

#### Coverage Threshold Enforcement

```yaml
# Automatic check on every test run
- name: Check coverage threshold
  run: |
    coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    echo "Coverage: $coverage%"

    threshold=40.0
    if (( $(echo "$coverage < $threshold" | bc -l) )); then
      echo "❌ Coverage $coverage% is below threshold $threshold%"
      exit 1  # Blocks merge!
    fi
    echo "✅ Coverage $coverage% meets threshold $threshold%"
```

**Result**: Pull requests CANNOT merge if coverage drops below 40%

#### Downloading Coverage Reports

```bash
# After workflow completes:
# 1. Go to GitHub Actions run
# 2. Scroll to "Artifacts" section
# 3. Download "coverage-report"
# 4. Open coverage.html in browser

# Or via CLI
gh run download <run-id> -n coverage-report
open coverage.html
```

### Deployment Gates

**Automated Gates** (enforced by CI/CD):
1. ✅ All unit tests pass (112/112)
2. ✅ Coverage ≥ 40%
3. ✅ No race conditions
4. ✅ Integration tests pass
5. ✅ All jobs complete successfully

**Manual Gates** (before production deploy):
- [ ] Security review (for policy changes)
- [ ] Performance review (for high-traffic paths)
- [ ] Architecture review (for structural changes)

### Workflow Triggers

**Automatic Triggers**:
- ✅ Push to `main` branch (Go files)
- ✅ Push to `develop` branch (Go files)
- ✅ Pull requests to `main` or `develop`
- ✅ Path-filtered (only when `platform/**/*.go` changes)

**Manual Trigger**:
```bash
# Trigger workflow manually from GitHub UI
# Actions → Test Suite → Run workflow
```

### Current Status

**Check Live Status**:
```bash
# See latest workflow runs
gh run list --workflow=test.yml

# Example output:
# ✓  Test Suite  main  ef5c364  55s ago
# ✓  Test Suite  main  a5472d6  2h ago
```

**Badge** (add to README.md):
```markdown
[![Test Suite](https://github.com/getaxonflow/axonflow/actions/workflows/test.yml/badge.svg)](https://github.com/getaxonflow/axonflow/actions/workflows/test.yml)
```

---

## Debugging Test Failures

### Common Failure Patterns

#### 1. Race Condition Detected
```
WARNING: DATA RACE
Write at 0x00c0001a8180 by goroutine 23:
  axonflow/platform/orchestrator.(*MetricsCollector).RecordRequest()
      /Users/user/axonflow/platform/orchestrator/metrics_collector.go:85 +0x15c
```

**Fix**: Add mutex protection
```go
func (c *MetricsCollector) RecordRequest(...) {
    c.mu.Lock()         // ← Add this
    defer c.mu.Unlock() // ← And this

    // ... existing code
}
```

#### 2. Test Timeout
```
panic: test timed out after 2m0s
```

**Fix**: Increase timeout or optimize test
```bash
# Increase timeout
go test -timeout 5m

# Or optimize slow operations
func TestSlowOperation(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping slow test in short mode")
    }
    // ... test code
}
```

#### 3. Flaky Test (Intermittent Failures)
```
--- FAIL: TestConcurrentExecution (0.01s)
    test.go:45: Expected 100, got 99
```

**Fix**: Add proper synchronization
```go
// ❌ BAD: Race condition
for i := 0; i < 100; i++ {
    go worker()
}
time.Sleep(1 * time.Second) // Unreliable!

// ✅ GOOD: Proper synchronization
done := make(chan bool, 100)
for i := 0; i < 100; i++ {
    go func() {
        worker()
        done <- true
    }()
}
for i := 0; i < 100; i++ {
    <-done
}
```

#### 4. Nil Pointer Dereference
```
panic: runtime error: invalid memory address or nil pointer dereference
```

**Fix**: Add nil checks
```go
// ❌ BAD
result := workflow.Spec.Steps[0].Output

// ✅ GOOD
if workflow == nil || len(workflow.Spec.Steps) == 0 {
    t.Fatal("Expected workflow with steps")
}
result := workflow.Spec.Steps[0].Output
```

### Debugging Techniques

#### 1. Verbose Test Output
```bash
go test -v -run TestSpecificTest

# Shows all t.Log() and t.Logf() output
```

#### 2. Debug-Level Logging
```go
func TestWithDebugLogs(t *testing.T) {
    // Enable debug logging for this test
    os.Setenv("LOG_LEVEL", "debug")
    defer os.Unsetenv("LOG_LEVEL")

    // Now all debug logs will print
    result := functionUnderTest()

    t.Logf("Result: %+v", result)
}
```

#### 3. Delve Debugger
```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug specific test
dlv test -- -test.run TestSpecificTest

# Set breakpoint
(dlv) break planning_engine.go:142
(dlv) continue
(dlv) print workflow
```

#### 4. Test in Isolation
```bash
# Run only one test
go test -v -run "^TestExactName$"

# Run one test 100 times to catch flakiness
go test -count 100 -run TestFlakyTest
```

---

## Best Practices

### 1. Test Independence
```go
// ✅ GOOD: Each test is isolated
func TestA(t *testing.T) {
    collector := NewMetricsCollector()  // New instance
    // ... test logic
}

func TestB(t *testing.T) {
    collector := NewMetricsCollector()  // Separate instance
    // ... test logic
}

// ❌ BAD: Shared state between tests
var sharedCollector = NewMetricsCollector()  // Don't do this!

func TestA(t *testing.T) {
    sharedCollector.RecordRequest(...)  // Affects TestB!
}
```

### 2. Clear Assertions
```go
// ✅ GOOD: Clear error messages
if result != expected {
    t.Errorf("Expected %v, got %v (input: %s)", expected, result, input)
}

// ❌ BAD: Unclear failures
if result != expected {
    t.Error("test failed")  // Not helpful!
}
```

### 3. Test Names Describe Behavior
```go
// ✅ GOOD: Describes what is being tested
func TestLLMRouter_FailsOver_WhenPrimaryProviderDown(t *testing.T) {}
func TestPolicyEngine_BlocksSQLInjection_WithUnionKeyword(t *testing.T) {}

// ❌ BAD: Generic or unclear
func TestRouter(t *testing.T) {}
func TestFunction1(t *testing.T) {}
```

### 4. Use Subtests for Variations
```go
func TestPolicyEngine(t *testing.T) {
    t.Run("SQL Injection Detection", func(t *testing.T) {
        // Test SQL injection
    })

    t.Run("PII Detection", func(t *testing.T) {
        // Test PII detection
    })

    t.Run("Empty Query Handling", func(t *testing.T) {
        // Test empty queries
    })
}
```

### 5. Mock External Dependencies
```go
// ✅ GOOD: Mock LLM API calls
router := &LLMRouter{
    providers: map[string]LLMProvider{
        "test": &TestMockProvider{},
    },
}

// ❌ BAD: Real API calls in tests (slow, unreliable, costs money!)
router := NewLLMRouter(LLMRouterConfig{
    OpenAIKey: os.Getenv("OPENAI_API_KEY"),
})
```

### 6. Test Error Paths
```go
func TestErrorHandling(t *testing.T) {
    // Test happy path
    result, err := function(validInput)
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }

    // Test error path
    result, err = function(invalidInput)
    if err == nil {
        t.Error("Expected error for invalid input")
    }
}
```

---

## Performance Testing

### Benchmark Tests

```go
func BenchmarkLLMRouting(b *testing.B) {
    router := setupTestRouter()
    req := setupTestRequest()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        router.RouteRequest(context.Background(), req)
    }
}

// Run benchmarks
// go test -bench=. -benchmem
```

### Load Testing

```go
func TestConcurrentWorkflowExecution(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }

    engine := NewWorkflowEngine()

    const concurrency = 100
    done := make(chan bool, concurrency)

    start := time.Now()

    for i := 0; i < concurrency; i++ {
        go func() {
            engine.ExecuteWorkflow(ctx, workflow, input, user)
            done <- true
        }()
    }

    for i := 0; i < concurrency; i++ {
        <-done
    }

    elapsed := time.Since(start)
    t.Logf("Executed %d workflows in %v (%.2f/sec)",
        concurrency, elapsed, float64(concurrency)/elapsed.Seconds())
}
```

---

## Troubleshooting

### Test Discovery Issues

**Problem**: Tests not running
```bash
go test -v
# testing: warning: no tests to run
```

**Solution**: Check test function signature
```go
// ✅ CORRECT
func TestMyFunction(t *testing.T) {}  // Exported, takes *testing.T

// ❌ WRONG
func testMyFunction(t *testing.T) {}  // Not exported
func TestMyFunction() {}              // No *testing.T parameter
```

### Import Cycle Errors

**Problem**: Circular dependency between packages

**Solution**: Extract shared test utilities to `testutil` package
```
platform/
├── orchestrator/
│   ├── llm_router.go
│   ├── llm_router_test.go
│   └── testutil/          ← Shared test helpers
│       └── mocks.go
```

---

## Additional Resources

- **Go Testing Documentation**: https://golang.org/pkg/testing/
- **Table-Driven Tests**: https://github.com/golang/go/wiki/TableDrivenTests
- **Delve Debugger**: https://github.com/go-delve/delve
- **Test Coverage Tools**: `go tool cover -help`

---

## Quick Reference

### Essential Commands
```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -cover ./...

# Run with race detection
go test -race ./...

# Run specific test
go test -v -run TestName

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=.

# Skip slow tests
go test -short
```

### Test File Template
```go
package orchestrator

import (
    "context"
    "testing"
    "time"
)

func TestNewComponent(t *testing.T) {
    component := NewComponent()

    if component == nil {
        t.Fatal("Expected component to be initialized")
    }

    if !component.IsHealthy() {
        t.Error("Expected component to be healthy")
    }
}

func TestComponentBehavior(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
    }{
        {"Case 1", "input1", "output1"},
        {"Case 2", "input2", "output2"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := component.Process(tt.input)

            if result != tt.expected {
                t.Errorf("Expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

---

**Document Version**: 3.1
**Last Updated**: December 6, 2025
**Maintained By**: AxonFlow Platform Team
