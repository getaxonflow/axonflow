# AxonFlow Agent

The authentication and static policy enforcement gateway of the AxonFlow platform that provides the first line of defense for enterprise AI governance.

## Overview

The AxonFlow Agent is the security gateway that:
- Authenticates and authorizes all client requests using JWT tokens
- Enforces static security policies (SQL injection, malicious queries, privilege escalation)
- Provides tenant isolation and multi-client routing
- Integrates with client applications via Go SDK
- Maintains health monitoring and policy testing endpoints

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Client Apps    │────▶│   AxonFlow Agent     │────▶│AxonFlow         │
│                 │     │                      │     │Orchestrator     │
│ • Support Demo  │     │  • Authentication    │     │                 │
│ • Healthcare    │     │  • Static Policies   │     │ • LLM Routing   │
│ • E-commerce    │     │  • Tenant Isolation  │     │ • Dynamic Rules │
│ • Custom Apps   │     │  • SDK Integration   │     │ • Response Proc │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

## Key Features

### 🔐 Authentication & Authorization
- **JWT Token Validation**: Secure token-based authentication
- **Client Verification**: Multi-tenant client identification and routing
- **Permission Management**: Role-based access control integration
- **Session Management**: Token lifecycle and refresh handling

### 🛡️ Static Policy Enforcement
- **SQL Injection Prevention**: Blocks malicious SQL patterns
- **Query Sanitization**: Validates and cleans user inputs  
- **Privilege Escalation Protection**: Prevents unauthorized access attempts
- **Dangerous Command Blocking**: Blocks DROP, TRUNCATE, DELETE operations

### 🏢 Multi-Tenant Architecture
- **Tenant Isolation**: Secure separation of client data and requests
- **Client Routing**: Intelligent routing based on client configuration
- **Resource Allocation**: Per-tenant rate limiting and quotas
- **Audit Segregation**: Separate audit trails per tenant

### 🔌 SDK Integration
- **Go SDK**: Native Go integration for client applications
- **Type Safety**: Strongly typed request/response structures
- **Error Handling**: Comprehensive error reporting and retry logic
- **Configuration**: Environment-based configuration management

## API Endpoints

### Health & Monitoring
```
GET  /health           - Health check endpoint
GET  /policies/test    - Policy enforcement testing
POST /api/policies/test - Test specific policy rules
```

### Request Processing  
```
POST /api/process      - Main request processing endpoint
POST /api/validate     - Request validation without processing
```

## Configuration

### Environment Variables
```bash
# Server Configuration
PORT=8080                                    # Agent listening port
JWT_SECRET=your-secret-key                   # JWT signing secret

# AxonFlow Integration
ORCHESTRATOR_URL=http://orchestrator:8081    # Orchestrator endpoint
CLIENT_TIMEOUT=30s                           # Request timeout

# Multi-tenant Setup
TENANT_CONFIG_PATH=/etc/axonflow/tenants     # Tenant configuration
DEFAULT_TENANT=default                       # Fallback tenant
```

### Client SDK Configuration
```go
client := axonflow.NewClient(&axonflow.Config{
    AgentURL:    "http://localhost:8080",
    ClientID:    "your-client-id", 
    ClientSecret: "your-client-secret",
    Timeout:     30 * time.Second,
})
```

## Security Policies

### SQL Injection Prevention
- Pattern matching against known injection vectors
- Parameter validation and sanitization
- Query structure analysis
- Blocked patterns: `'; DROP`, `UNION SELECT`, `-- `, etc.

### Access Control
- Request origin validation
- Client certificate verification (optional)
- IP allowlisting/blocklisting
- Rate limiting per client/tenant

### Audit & Compliance
- All requests logged with full context
- Policy violation tracking
- Performance metrics collection
- Compliance report generation

## Development

### Local Development
```bash
# Clone and build
git clone <repository>
cd platform/agent
go mod tidy
go build -o agent .

# Run with development config
export JWT_SECRET=dev-secret
export ORCHESTRATOR_URL=http://localhost:8081
./agent
```

### Testing

**Test Coverage**: 70.3% ✅ (Exceeds 70% target)
**Test Suite**: 149+ comprehensive tests
**Status**: All tests passing, zero flaky tests

```bash
# Run all tests with coverage
go test -v -cover

# Expected output:
# PASS
# coverage: 70.3% of statements
# ok      axonflow/platform/agent    30.431s

# Run specific test suites
go test -v -run TestValidateClientLicenseDB  # DB authentication
go test -v -run TestCheckRateLimitRedis       # Rate limiting
go test -v -run TestInitializeMCPRegistry     # MCP connectors
go test -v -run TestEvaluateStaticPolicies    # Policy engine

# Generate HTML coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Test policy enforcement via API
curl -X POST http://localhost:8080/api/policies/test \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users; DROP TABLE users;", "user_email": "test@example.com"}'
```

**Test Quality Standards:**
- ✅ Fast: <30 seconds total execution
- ✅ Deterministic: 100% pass rate, zero flaky tests
- ✅ Independent: All tests run in isolation
- ✅ Comprehensive: Success + error + edge cases
- ✅ Well-documented: Clear test names and comments

**Key Test Files:**
- `db_auth_test.go` - Database authentication (12 tests)
- `redis_rate_limit_test.go` - Rate limiting (11 tests)
- `mcp_handler_test.go` - MCP connectors (5 tests)
- `db_policies_test.go` - Policy engine (9 tests)
- `static_policies_test.go` - Static policies (15 tests)
- `audit_queue_test.go` - Audit logging (13 tests)

For detailed testing documentation, see: `technical-docs/TESTING_GUIDE.md`

### Docker
```bash
# Build image
docker build -t axonflow-agent .

# Run container
docker run -p 8080:8080 \
  -e JWT_SECRET=your-secret \
  -e ORCHESTRATOR_URL=http://orchestrator:8081 \
  axonflow-agent
```

## Integration Examples

### Go SDK Usage
```go
package main

import (
    "context"
    "log"
    "github.com/your-org/axonflow-sdk"
)

func main() {
    client := axonflow.NewClient(&axonflow.Config{
        AgentURL:     "http://localhost:8080",
        ClientID:     "support-demo-client",
        ClientSecret: "demo-secret",
    })

    response, err := client.ProcessQuery(context.Background(), &axonflow.QueryRequest{
        Query:     "SELECT * FROM customers WHERE region = 'US'",
        UserEmail: "agent@company.com", 
        QueryType: "sql",
    })
    
    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }
    
    log.Printf("Query results: %+v", response)
}
```

### Policy Testing
```bash
# Test SQL injection prevention
curl -X POST localhost:8080/api/policies/test \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
    "user_email": "test@example.com",
    "request_type": "sql"
  }'

# Expected response: Policy violation detected
```

## Monitoring & Operations

### Health Checks
The agent provides comprehensive health monitoring:
- Database connectivity status
- Orchestrator communication health  
- Policy engine status
- Memory and CPU utilization

### Metrics
Key operational metrics tracked:
- Request throughput and latency
- Policy violation rates
- Authentication success/failure rates
- Tenant-specific usage statistics

### Logging
Structured logging with:
- Request/response correlation IDs
- User and tenant context
- Policy evaluation results
- Performance timings

## Troubleshooting

### Common Issues

**Authentication Failures**
```bash
# Check JWT secret configuration
echo $JWT_SECRET

# Verify token format
jwt decode your-token-here
```

**Policy Violations**
```bash
# Test specific policy
curl -X POST localhost:8080/api/policies/test \
  -d '{"query": "your-query-here"}'
```

**Connection Issues**
```bash
# Health check
curl localhost:8080/health

# Check orchestrator connectivity  
curl localhost:8080/health | jq '.orchestrator_status'
```

## Contributing

1. Follow Go coding standards and conventions
2. Add tests for all new policy rules
3. Update documentation for API changes  
4. Ensure security implications are reviewed
5. Test with multiple tenant configurations

## Security Considerations

- Never log sensitive data (passwords, tokens, PII)
- Validate all inputs before processing
- Use secure defaults for all configurations
- Regularly update dependencies for security patches
- Monitor for unusual access patterns

---

**Part of AxonFlow Enterprise AI Governance Platform**
- 🔒 **Agent**: Authentication & Static Policies (this component)
- 🧠 **Orchestrator**: LLM Routing & Dynamic Policies  
- 📊 **Clients**: Industry-specific applications
- 🏢 **Admin Portal**: Policy management and tenant configuration