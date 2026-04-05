# SDK Comprehensive Audit Examples

These examples validate all SDK methods work correctly against live AxonFlow services.

## Prerequisites

1. Start AxonFlow services:
   ```bash
   docker compose up -d
   ```

2. Wait for services to be healthy:
   ```bash
   curl http://localhost:8080/health
   ```

## What's Tested

Each SDK example tests:

1. **Agent Health Check** - Verify Agent service is healthy
2. **Orchestrator Health Check** - Verify Orchestrator service is healthy
3. **Gateway Mode - Safe Query** - Policy approval for a safe query
4. **Gateway Mode - Blocked Query** - SQL injection should be blocked
5. **Audit LLM Call** - Record an audit entry
6. **List Connectors** - Retrieve available MCP connectors
7. **Static Policy CRUD** - Create, Read, Update, Delete policies
8. **List Static Policies** - Retrieve all static policies

## Running Examples

### Go

```bash
cd go
go mod tidy
go run main.go
```

### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript

```bash
cd typescript
npm install
npm start
```

### Java

```bash
cd java
mvn compile exec:java
```

## Expected Output

All tests should pass when running against a healthy AxonFlow deployment:

```
AxonFlow SDK Comprehensive Audit - [SDK Name]
==============================================

Test 1: Agent Health Check
  ✅ PASSED: Agent is healthy
Test 2: Orchestrator Health Check
  ✅ PASSED: Orchestrator is healthy
Test 3: Gateway Mode - Safe Query
  ✅ PASSED: Query approved (contextId: abc123)
Test 4: Gateway Mode - Blocked Query (SQL Injection)
  ✅ PASSED: Query correctly blocked (sql-injection-detection)
Test 5: Audit LLM Call
  ✅ PASSED: Audit recorded (auditId: xyz789)
Test 6: List Connectors
  ✅ PASSED: Found 5 connectors
Test 7: Static Policy CRUD
  ✅ Create: Policy created (id: policy-123)
  ✅ Get: Policy retrieved correctly
  ✅ Update: Policy updated correctly
  ✅ Delete: Policy deleted correctly
Test 8: List Static Policies
  ✅ PASSED: Found 10 policies

==============================================
Summary: 8 passed, 0 failed
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | Agent service URL |
| `AXONFLOW_CLIENT_ID` | (empty) | OAuth2 client ID |
| `AXONFLOW_CLIENT_SECRET` | (empty) | OAuth2 client secret |

## Issue Reference

These examples were created as part of Issue #849 - SDK Comprehensive Audit.
