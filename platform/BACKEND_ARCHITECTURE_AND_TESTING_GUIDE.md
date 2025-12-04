# AxonFlow Backend Services - Architecture Analysis & Unit Testing Guide

**Document Version**: 1.0  
**Date**: October 28, 2025  
**Status**: Complete  

---

## Executive Summary

AxonFlow is a **Go-based AI Agent Platform** consisting of three core services:

1. **Agent Service** - Authentication, authorization, static policy enforcement gateway
2. **Orchestrator Service** - Dynamic policy evaluation, LLM routing, workflow orchestration
3. **Shared Libraries** - Common utilities, structured logging, shared data models

**Key Finding**: There are **NO existing unit tests** across any service. This document provides a comprehensive architecture analysis and test structure recommendations.

---

## I. AGENT SERVICE (`/platform/agent/`)

### A. Service Overview

**Purpose**: Authentication, authorization & static policy enforcement gateway  
**Language**: Go 1.21  
**Framework**: Gorilla Mux HTTP router  
**Port**: 8080 (default)

**Architecture Pattern**: Request validation layer before routing to orchestrator

```
Client Request 
    ↓
[Client Authentication & License Validation]
    ↓
[User Token Validation]
    ↓
[Tenant Isolation Check]
    ↓
[Static Policy Enforcement]
    ↓
[Rate Limiting (Redis/In-Memory)]
    ↓
Forward to Orchestrator → Get Response → Return to Client
```

### B. Main Entry Point

**File**: `/Users/saurabhjain/Development/axonflow/platform/agent/main.go` (926 lines)

**Key Initialization**:
- License validation (AXONFLOW_LICENSE_KEY)
- Database policy engine (DATABASE_URL) or static policy fallback
- JWT secret loading (JWT_SECRET)
- Redis rate limiting initialization (REDIS_URL)
- MCP connector registry setup
- HTTP router with CORS

**HTTP Routes**:
```
GET  /health                          - Service health check
GET  /metrics                         - JSON performance metrics
GET  /prometheus                      - Prometheus exposition format
POST /api/request                     - Main client request handler
GET  /api/clients                     - List registered clients
POST /api/clients                     - Create new client
POST /api/policies/test               - Policy testing endpoint
GET  /mcp/connectors                  - List MCP connectors
GET  /mcp/connectors/{name}/health    - Connector health check
```

### C. Core Business Logic Files

#### 1. **Static Policy Engine** (`static_policies.go` - 213 lines)

**Responsibility**: Fast, rule-based policy enforcement

**Key Classes/Types**:
- `StaticPolicyEngine` - Main enforcement engine
- `PolicyPattern` - Single policy rule with regex
- `StaticPolicyResult` - Result of policy evaluation

**Core Methods**:
```go
func NewStaticPolicyEngine() *StaticPolicyEngine
func (spe *StaticPolicyEngine) EvaluateStaticPolicies(user *User, query string, requestType string) *StaticPolicyResult
```

**Policy Categories**:
1. SQL Injection Detection (critical)
2. Dangerous Query Detection (critical)
3. Admin Access Control (high)
4. Request Type Validation
5. PII Detection (low-medium)

**Testing Need**: Critical
- Regex pattern matching for each policy type
- User permission checking
- Request type validation
- Integration of multiple policies

#### 2. **Database Policy Engine** (`db_policies.go` - 500+ lines)

**Responsibility**: Load and cache policies from database

**Key Classes/Types**:
- `DatabasePolicyEngine` - Database-backed policy engine
- `PolicyRecord` - Policy data model from DB
- `AuditQueue` - Async audit logging with fallback

**Core Features**:
- Policy caching with TTL (time-based refresh)
- Performance mode (async writes) vs Compliance mode (sync writes)
- Exponential backoff retry for DB operations
- Multi-tenant policy isolation

**Key Methods**:
```go
func NewDatabasePolicyEngine() (*DatabasePolicyEngine, error)
func (dpe *DatabasePolicyEngine) EvaluateStaticPolicies(user *User, query string, requestType string) *StaticPolicyResult
func (dpe *DatabasePolicyEngine) loadPoliciesFromDB() error
func (dpe *DatabasePolicyEngine) refreshPoliciesRoutine()
```

**Testing Need**: High
- Database connection handling
- Policy caching and refresh
- Retry logic with exponential backoff
- Performance vs compliance mode behavior
- Multi-tenant isolation

#### 3. **Authentication & Authorization** (`auth.go` - 200+ lines)

**Responsibility**: Client and user authentication

**Key Classes/Types**:
- `ClientAuth` - Client authentication config
- `RateLimitEntry` - Rate limit tracking
- User credentials validation

**Authentication Methods**:
- Option 2: Whitelist + License key validation
- Option 3: Database-backed authentication with Redis rate limiting

**Key Functions**:
```go
func validateClientLicense(ctx context.Context, clientID, licenseKey string) (*Client, error)
func validateUserToken(tokenString string) (*User, error)
func checkRateLimit(clientID string, client *Client) error
```

**Key Hardcoded Clients** (whitelist):
- healthcare-demo (PLUS tier)
- ecommerce-demo (PLUS tier)
- client_1, client_2 (ENT tier)
- loadtest (HIGH tier)

**Testing Need**: Critical
- License key validation
- JWT token parsing
- Tenant isolation enforcement
- Rate limiting (in-memory and Redis)
- Client permission verification

#### 4. **Database Authentication** (`db_auth.go` - 340+ lines)

**Responsibility**: Option 3 - Database-backed authentication with usage tracking

**Key Classes/Types**:
- Database client and user lookup
- API key management
- Usage tracking for billing

**Core Methods**:
```go
func validateClientLicenseDB(ctx context.Context, db *sql.DB, clientID, licenseKey string) (*Client, error)
func trackAPIUsage(db *sql.DB, apiKeyID, clientID string) error
```

**Testing Need**: High
- Database query execution and error handling
- Concurrent access to DB
- API key validation
- Usage tracking

#### 5. **Rate Limiting** (`redis_rate_limit.go` - 155+ lines)

**Responsibility**: Distributed rate limiting via Redis

**Key Classes/Types**:
- Redis client management
- Rate limit bucket tracking

**Core Methods**:
```go
func initRedis(redisURL string) error
func checkRedisRateLimit(clientID string, limit int) (bool, error)
func closeRedis()
```

**Testing Need**: High
- Redis connection handling
- Rate limit calculation
- Token bucket algorithm
- Error handling for Redis failures

#### 6. **Audit Queue** (`audit_queue.go` - 260+ lines)

**Responsibility**: Async audit logging with persistent fallback

**Key Classes/Types**:
- `AuditQueue` - Async queue with file fallback
- `AuditMode` - COMPLIANCE vs PERFORMANCE modes
- Audit event tracking

**Core Methods**:
```go
func NewAuditQueue(dbURL string, auditMode AuditMode) *AuditQueue
func (aq *AuditQueue) QueueAuditEvent(event *AuditEvent) error
func (aq *AuditQueue) flushAuditQueue()
```

**Testing Need**: High
- Async queue behavior
- File fallback mechanism
- Database persistence
- Event serialization

#### 7. **License Validation** (`license/validation.go` - 320+ lines)

**Responsibility**: License key validation with HMAC

**Key Classes/Types**:
- `LicenseValidationResult` - Result of validation
- License tier information

**Core Methods**:
```go
func ValidateWithRetry(ctx context.Context, licenseKey string, maxRetries int) (*LicenseValidationResult, error)
func ValidateLicense(licenseKey string) (*LicenseValidationResult, error)
```

**Testing Need**: Critical
- License key format validation
- HMAC signature verification
- License expiry checking
- Tier extraction and validation

#### 8. **MCP Handler** (`mcp_handler.go` - 350+ lines)

**Responsibility**: Model Context Protocol (MCP) connector management

**Key Classes/Types**:
- Connector registry integration
- PostgreSQL and Cassandra connector registration

**Core Methods**:
```go
func InitializeMCPRegistry() error
func registerPostgresConnector() error
func registerCassandraConnector() error
func RegisterMCPHandlers(r *mux.Router)
```

**Testing Need**: Medium
- Connector registry initialization
- Connector health checks
- Error handling for connector failures

### D. Key Data Structures

```go
// Client represents registered client application
type Client struct {
    ID            string    
    Name          string    
    TenantID      string    
    Permissions   []string  
    RateLimit     int       
    Enabled       bool      
    LicenseTier   string    
    LicenseExpiry time.Time 
    APIKeyID      string    
}

// User represents authenticated user information
type User struct {
    ID          int      
    Email       string   
    Name        string   
    Department  string   
    Role        string   
    Region      string   
    Permissions []string 
    TenantID    string   
}

// ClientRequest - incoming request from client
type ClientRequest struct {
    Query       string                 
    UserToken   string                 
    ClientID    string                 
    RequestType string                 // "sql", "llm_chat", "rag_search"
    SkipLLM     bool                   
    Context     map[string]interface{} 
}

// ClientResponse - response to client
type ClientResponse struct {
    Success      bool                  
    Data         interface{}           
    Result       interface{}           // Multi-agent planning
    PlanID       string                // Multi-agent planning
    Metadata     interface{}           // Multi-agent planning
    Error        string                
    Blocked      bool                  
    BlockReason  string                
    PolicyInfo   *PolicyEvaluationInfo 
}
```

### E. Database Dependencies

**Required Tables** (Agent service):
- `clients` - Client authentication records
- `users` - User information
- `api_keys` - API key management
- `policies` - Static policy rules
- `audit_logs` - Audit trail

**Connection**: Via `DATABASE_URL` environment variable (PostgreSQL)

### F. External Dependencies

```
Go Packages:
- github.com/dgrijalva/jwt-go v3.2.0+incompatible - JWT token parsing
- github.com/gorilla/mux v1.8.1 - HTTP routing
- github.com/lib/pq v1.10.9 - PostgreSQL driver
- github.com/go-redis/redis/v8 v8.11.5 - Redis client
- github.com/prometheus/client_golang v1.17.0 - Prometheus metrics
- github.com/rs/cors v1.10.1 - CORS middleware

External Services:
- PostgreSQL (DATABASE_URL) - Policy and auth storage
- Redis (REDIS_URL) - Distributed rate limiting
- AxonFlow Orchestrator (ORCHESTRATOR_URL) - Request forwarding
- License Server - License validation via API
```

### G. Metrics & Monitoring

**Prometheus Metrics**:
- `axonflow_agent_requests_total` (counter) - Total requests by status
- `axonflow_agent_request_duration_milliseconds` (histogram) - Request latency
- `axonflow_agent_policy_evaluations_total` (counter) - Policy evaluation count
- `axonflow_agent_blocked_requests_total` (counter) - Blocked requests

**Custom Metrics** (in-memory):
- Per-request latencies (last 1000)
- Auth timing breakdown
- Static policy timing
- Network timing to orchestrator

---

## II. ORCHESTRATOR SERVICE (`/platform/orchestrator/`)

### A. Service Overview

**Purpose**: Dynamic policy enforcement, LLM routing, workflow orchestration  
**Language**: Go 1.21  
**Framework**: Gorilla Mux HTTP router  
**Port**: 8081 (default)

**Architecture Pattern**: Multi-stage request processing

```
Agent Request
    ↓
[Dynamic Policy Evaluation]
    ↓
[LLM Router - Provider Selection]
    ↓
[LLM Inference]
    ↓
[Response Processing - PII Detection/Redaction]
    ↓
[Audit Logging]
    ↓
[Metrics Collection]
    ↓
Return Response
```

### B. Main Entry Point

**File**: `/Users/saurabhjain/Development/axonflow/platform/orchestrator/main.go` (1028 lines)

**Key Initialization**:
- Dynamic policy engine (database-backed or in-memory)
- LLM router with multi-provider support
- Amadeus API client
- Response processor with PII detection
- Audit logger with database persistence
- Metrics collector
- Workflow engine for task orchestration
- Planning engine for multi-agent decomposition
- Result aggregator for synthesis
- MCP connector registry

**HTTP Routes**:
```
GET  /health                                      - Service health check
GET  /metrics                                     - JSON metrics
GET  /prometheus                                  - Prometheus format
POST /api/v1/process                             - Main request processing
GET  /api/v1/providers/status                    - LLM provider status
PUT  /api/v1/providers/weights                   - Update provider weights
GET  /api/v1/policies/dynamic                    - List active policies
POST /api/v1/policies/test                       - Test policy
GET  /api/v1/metrics                             - Metrics endpoint
POST /api/v1/audit/search                        - Search audit logs
GET  /api/v1/audit/tenant/{tenant_id}           - Get tenant audit logs
POST /api/v1/workflows/execute                   - Execute workflow
GET  /api/v1/workflows/executions/{id}           - Get execution
GET  /api/v1/workflows/executions                - List executions
GET  /api/v1/workflows/executions/tenant/{id}    - Get tenant executions
POST /api/v1/plan                                - Multi-agent planning
GET  /api/v1/connectors                          - List connectors
GET  /api/v1/connectors/{id}                     - Get connector details
POST /api/v1/connectors/{id}/install             - Install connector
DELETE /api/v1/connectors/{id}/uninstall         - Uninstall connector
GET  /api/v1/connectors/{id}/health              - Connector health
```

### C. Core Business Logic Files

#### 1. **Dynamic Policy Engine** (`dynamic_policy_engine.go` - 400+ lines)

**Responsibility**: Runtime policy evaluation based on request context

**Key Classes/Types**:
- `DynamicPolicyEngine` - Policy evaluation engine
- `DynamicPolicy` - Runtime policy definition
- `PolicyCondition` - Policy trigger condition
- `PolicyAction` - Policy action on trigger
- `RiskCalculator` - Risk score calculation
- `PolicyCache` - Result caching

**Core Methods**:
```go
func NewDynamicPolicyEngine() *DynamicPolicyEngine
func (dpe *DynamicPolicyEngine) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult
func (dpe *DynamicPolicyEngine) ListActivePolicies() []DynamicPolicy
func (dpe *DynamicPolicyEngine) loadPoliciesFromDB() error
func (dpe *DynamicPolicyEngine) reloadPoliciesRoutine()
func (dpe *DynamicPolicyEngine) IsHealthy() bool
```

**Policy Types**:
- `content` - Content-based rules
- `user` - User role/attribute based
- `risk` - Risk score based
- `cost` - Cost/token based

**Testing Need**: Critical
- Policy evaluation logic
- Condition matching (contains, equals, greater_than)
- Risk score calculation
- Cache TTL and refresh
- Database loading and refresh
- Multi-tenant isolation

#### 2. **LLM Router** (`llm_router.go` - 280+ lines)

**Responsibility**: Intelligent routing to multiple LLM providers

**Key Classes/Types**:
- `LLMRouter` - Main routing engine
- `LLMProvider` - Provider interface
- `LLMRouterConfig` - Router configuration
- `QueryOptions` - Query parameters
- `LLMResponse` - Provider response
- `ProviderStatus` - Provider health/metrics
- `HealthChecker` - Provider health monitoring
- `LoadBalancer` - Request distribution
- `ProviderMetricsTracker` - Provider statistics

**Supported Providers**:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Local LLM endpoint

**Core Methods**:
```go
func NewLLMRouter(config LLMRouterConfig) *LLMRouter
func (lr *LLMRouter) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error)
func (lr *LLMRouter) GetProviderStatus() []ProviderStatus
func (lr *LLMRouter) UpdateProviderWeights(weights map[string]float64) error
func (lr *LLMRouter) IsHealthy() bool
```

**Testing Need**: Critical
- Provider selection algorithm
- Weight-based routing
- Fallback logic when provider fails
- Cost calculation
- Health checking mechanism
- Timeout handling

#### 3. **Planning Engine** (`planning_engine.go` - 400+ lines)

**Responsibility**: Generate multi-step execution plans from natural language

**Key Classes/Types**:
- `PlanningEngine` - Plan generation engine
- `DomainTemplate` - Domain-specific hints
- `QueryAnalysis` - Query analysis result
- `PlanGenerationRequest` - Planning request
- Workflow generation logic

**Supported Domains**:
- `travel` - Flight, hotel, activities, restaurant, transportation
- `healthcare` - Symptom checking, provider search, appointment scheduling
- `finance` - Market analysis, portfolio review, transaction analysis
- `generic` - General purpose planning

**Core Methods**:
```go
func NewPlanningEngine(router *LLMRouter) *PlanningEngine
func (e *PlanningEngine) GeneratePlan(ctx context.Context, req PlanGenerationRequest) (*Workflow, error)
func (e *PlanningEngine) AnalyzeQuery(ctx context.Context, query string, domain string) (*QueryAnalysis, error)
func (e *PlanningEngine) IsHealthy() bool
```

**Testing Need**: High
- Query analysis and domain detection
- Task decomposition logic
- Template-based plan generation
- LLM-based plan synthesis
- Parallel vs sequential execution decision

#### 4. **Workflow Engine** (`workflow_engine.go` - 600+ lines)

**Responsibility**: Execute multi-step workflows with step orchestration

**Key Classes/Types**:
- `WorkflowEngine` - Main execution engine
- `Workflow` - Workflow definition (Kubernetes-like)
- `WorkflowMetadata` - Workflow metadata
- `WorkflowSpec` - Workflow specification
- `WorkflowStep` - Single step definition
- `WorkflowExecution` - Execution instance
- `StepExecution` - Step execution result
- `StepProcessor` - Step type handler interface
- `WorkflowStorage` - Persistence interface

**Step Types**:
- `llm-call` - Call LLM provider
- `connector-call` - Call MCP connector
- `conditional` - Conditional logic
- (extensible)

**Core Methods**:
```go
func NewWorkflowEngine() *WorkflowEngine
func (we *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error)
func (we *WorkflowEngine) ExecuteWorkflowWithParallelSupport(ctx context.Context, workflow Workflow, context map[string]interface{}, user UserContext, enableParallel bool) (*WorkflowExecution, error)
func (we *WorkflowEngine) GetExecution(executionID string) (*WorkflowExecution, error)
func (we *WorkflowEngine) ListRecentExecutions(limit int) ([]WorkflowExecution, error)
func (we *WorkflowEngine) GetExecutionsByTenant(tenantID string) ([]WorkflowExecution, error)
func (we *WorkflowEngine) IsHealthy() bool
```

**Testing Need**: Critical
- Workflow definition parsing
- Step execution sequencing
- Parallel step execution
- Conditional branching
- Error handling and retries
- Timeout handling
- Storage persistence
- Multi-tenant isolation

#### 5. **Result Aggregator** (`result_aggregator.go` - 236 lines)

**Responsibility**: Synthesize outputs from multiple tasks into coherent result

**Key Classes/Types**:
- `ResultAggregator` - Synthesis engine
- `AggregationStats` - Aggregation statistics

**Core Methods**:
```go
func NewResultAggregator(router *LLMRouter) *ResultAggregator
func (a *ResultAggregator) AggregateResults(ctx context.Context, taskResults []StepExecution, originalQuery string, user UserContext) (string, error)
func (a *ResultAggregator) AggregateWithCustomPrompt(ctx context.Context, taskResults []StepExecution, customPrompt string, user UserContext) (string, error)
func (a *ResultAggregator) GetAggregationStats(results []StepExecution) AggregationStats
func (a *ResultAggregator) IsHealthy() bool
```

**Features**:
- LLM-based result synthesis
- Fallback to simple concatenation
- Custom prompt support
- Error handling

**Testing Need**: Medium
- Result filtering
- Prompt construction
- LLM synthesis
- Fallback behavior
- Statistics calculation

#### 6. **Response Processor** (`response_processor.go` - 270+ lines)

**Responsibility**: PII detection, redaction, and response processing

**Key Classes/Types**:
- `ResponseProcessor` - Main processor
- PII detection patterns
- Redaction rules

**Core Methods**:
```go
func NewResponseProcessor() *ResponseProcessor
func (rp *ResponseProcessor) ProcessResponse(ctx context.Context, user UserContext, response *LLMResponse) (interface{}, *RedactionInfo)
func (rp *ResponseProcessor) IsHealthy() bool
```

**PII Detection**:
- Credit card numbers
- Social security numbers
- Phone numbers
- Email addresses
- API keys
- Sensitive data patterns

**Testing Need**: High
- PII pattern detection
- False positive/negative handling
- Redaction accuracy
- Performance with large responses

#### 7. **Audit Logger** (`audit_logger.go` - 320+ lines)

**Responsibility**: Comprehensive audit trail logging

**Key Classes/Types**:
- `AuditLogger` - Logging system
- `AuditEvent` - Audit event record
- Database persistence

**Core Methods**:
```go
func NewAuditLogger(dbURL string) *AuditLogger
func (al *AuditLogger) LogSuccessfulRequest(ctx context.Context, req OrchestratorRequest, response interface{}, policyResult *PolicyEvaluationResult, providerInfo *ProviderInfo) error
func (al *AuditLogger) LogBlockedRequest(ctx context.Context, req OrchestratorRequest, policyResult *PolicyEvaluationResult)
func (al *AuditLogger) LogFailedRequest(ctx context.Context, req OrchestratorRequest, err error)
func (al *AuditLogger) SearchAuditLogs(searchReq interface{}) (interface{}, error)
func (al *AuditLogger) IsHealthy() bool
```

**Logged Information**:
- Request ID, timestamp, user, client
- Request type and content
- Policy evaluation results
- LLM provider used
- Response redaction status
- Any errors or violations

**Testing Need**: Medium
- Event marshaling
- Database persistence
- Search functionality
- Tenant isolation in searches

#### 8. **Metrics Collector** (`metrics_collector.go` - 280+ lines)

**Responsibility**: Collect and aggregate performance metrics

**Key Classes/Types**:
- `MetricsCollector` - Main collector
- `RequestTypeMetrics` - Per-request-type metrics
- `PolicyMetrics` - Policy evaluation metrics
- `ProviderMetrics` - LLM provider metrics

**Core Methods**:
```go
func NewMetricsCollector() *MetricsCollector
func (mc *MetricsCollector) RecordRequest(requestType string, provider string, duration time.Duration)
func (mc *MetricsCollector) GetMetrics() *CollectedMetrics
func (mc *MetricsCollector) IsHealthy() bool
```

**Metrics Tracked**:
- Total requests by type
- Success/blocked/error counts
- P99 response times
- Average response times
- Provider-specific metrics
- Policy evaluation timing

**Testing Need**: Medium
- Metric recording
- Percentile calculation (P99, P95)
- Average calculation
- Provider aggregation

#### 9. **Amadeus Client** (`amadeus_client.go` - 235+ lines)

**Responsibility**: Integration with Amadeus travel API

**Key Classes/Types**:
- `AmadeusClient` - API client
- Amadeus authentication
- Flight/hotel search

**Core Methods**:
```go
func NewAmadeusClient() *AmadeusClient
func (ac *AmadeusClient) SearchFlights(origin, destination string, departDate, returnDate string) (interface{}, error)
func (ac *AmadeusClient) SearchHotels(cityCode, checkInDate, checkOutDate string) (interface{}, error)
func (ac *AmadeusClient) IsConfigured() bool
```

**Testing Need**: High
- API authentication
- Request/response parsing
- Error handling
- Mock data fallback

#### 10. **Connector Marketplace** (`connector_marketplace_handlers.go` - 350+ lines)

**Responsibility**: MCP connector installation and management

**Core Methods**:
- List available connectors
- Get connector details
- Install/uninstall connectors
- Health checks

**Testing Need**: Medium
- Connector registry operations
- Installation verification
- Health check accuracy

### D. Key Data Structures

```go
// OrchestratorRequest - incoming request from Agent
type OrchestratorRequest struct {
    RequestID   string                 
    Query       string                 
    RequestType string                 
    SkipLLM     bool                   
    User        UserContext            
    Client      ClientContext          
    Context     map[string]interface{} 
    Timestamp   time.Time              
}

// OrchestratorResponse - response to Agent/Client
type OrchestratorResponse struct {
    RequestID       string                  
    Success         bool                    
    Data            interface{}             
    Error           string                  
    Redacted        bool                    
    RedactedFields  []string                
    PolicyInfo      *PolicyEvaluationResult 
    ProviderInfo    *ProviderInfo           
    ProcessingTime  string                  
}

// PolicyEvaluationResult - policy decision
type PolicyEvaluationResult struct {
    Allowed          bool     
    AppliedPolicies  []string 
    RiskScore        float64  
    RequiredActions  []string 
    ProcessingTimeMs int64    
    DatabaseAccessed bool     
}

// Workflow - Kubernetes-like workflow definition
type Workflow struct {
    APIVersion string            
    Kind       string            
    Metadata   WorkflowMetadata  
    Spec       WorkflowSpec      
}

// WorkflowExecution - runtime execution instance
type WorkflowExecution struct {
    ID           string                 
    WorkflowName string                 
    Status       string                 // pending, running, completed, failed
    Input        map[string]interface{} 
    Output       map[string]interface{} 
    Steps        []StepExecution        
    StartTime    time.Time              
    EndTime      *time.Time             
    UserContext  UserContext            
    Error        string                 
}
```

### E. Database Dependencies

**Required Tables** (Orchestrator service):
- `policies_dynamic` - Dynamic policy definitions
- `policies_conditions` - Policy conditions
- `policies_actions` - Policy actions
- `audit_logs` - Audit trail
- `workflow_executions` - Workflow execution records
- `workflow_steps` - Step execution records
- `workflow_definitions` - Workflow templates (optional)

**Connection**: Via `DATABASE_URL` environment variable (PostgreSQL)

### F. External Dependencies

```
Go Packages:
- All from Agent + additional:
- github.com/gocql/gocql v1.7.0 - Cassandra driver
- Additional packages for connectors

External Services:
- OpenAI API (OPENAI_API_KEY) - LLM inference
- Anthropic API (ANTHROPIC_API_KEY) - LLM inference
- Local LLM (LOCAL_LLM_ENDPOINT) - Alternative LLM
- Amadeus Travel API - Flight/hotel searches
- PostgreSQL (DATABASE_URL) - Policy and audit storage
- MCP Connectors (PostgreSQL, Cassandra, HTTP)
```

### G. Metrics & Monitoring

**Prometheus Metrics**:
- `axonflow_orchestrator_requests_total` (counter)
- `axonflow_orchestrator_request_duration_milliseconds` (histogram)
- `axonflow_orchestrator_policy_evaluations_total` (counter)
- `axonflow_orchestrator_blocked_requests_total` (counter)
- `axonflow_orchestrator_llm_calls_total` (counter) - By provider and status

---

## III. SHARED LIBRARIES (`/platform/shared/`)

### A. Shared Package Overview

**Purpose**: Common utilities, data models, and infrastructure code  
**Current Content**: Minimal (logger package only)

### B. Logger Package (`/platform/shared/logger/logger.go` - 126 lines)

**Responsibility**: Structured JSON logging for multi-tenant systems

**Key Classes/Types**:
```go
type Logger struct {
    Component  string
    InstanceID string
    Container  string
}

type LogEntry struct {
    Timestamp  string                 
    Level      LogLevel               
    Component  string                 
    InstanceID string                 
    Container  string                 
    ClientID   string                 
    RequestID  string                 
    Message    string                 
    Fields     map[string]interface{} 
}
```

**Log Levels**: DEBUG, INFO, WARN, ERROR

**Core Methods**:
```go
func New(component string) *Logger
func (l *Logger) Log(level LogLevel, clientID, requestID, message string, fields map[string]interface{})
func (l *Logger) Info(clientID, requestID, message string, fields map[string]interface{})
func (l *Logger) Error(clientID, requestID, message string, fields map[string]interface{})
func (l *Logger) Warn(clientID, requestID, message string, fields map[string]interface{})
func (l *Logger) Debug(clientID, requestID, message string, fields map[string]interface{})
func (l *Logger) InfoWithDuration(clientID, requestID, message string, durationMS float64, fields map[string]interface{})
func (l *Logger) ErrorWithCode(clientID, requestID, message string, statusCode int, err error, fields map[string]interface{})
```

**Features**:
- Multi-tenant logging (clientID, requestID)
- Instance tracking (instance_id, container name)
- Structured JSON output
- CloudWatch compatible

**Testing Need**: High
- JSON serialization
- Field assignment
- Log level filtering
- Error handling

---

## IV. CURRENT TEST INFRASTRUCTURE

### Existing Tests

**Status**: ❌ **NO UNIT TESTS EXIST**

### Test File Patterns

Standard Go testing patterns should be used:
- `*_test.go` files in same package
- Table-driven tests for multiple scenarios
- Mock interfaces using manual or library approaches

---

## V. COMPREHENSIVE UNIT TEST STRUCTURE

### A. Agent Service Tests

#### 1. Test File: `agent/static_policies_test.go`

**Test Coverage Areas**:
```
[Static Policy Engine Tests]
├── TestNewStaticPolicyEngine
│   └── Verify engine initialization with default policies
├── TestEvaluateStaticPolicies - SQL Injection Detection
│   ├── Valid queries (no injection)
│   ├── Union-based injection attempts
│   ├── Boolean-based injection
│   ├── Time-based injection
│   └── Second-order injection
├── TestEvaluateStaticPolicies - Dangerous Queries
│   ├── DROP TABLE attempts
│   ├── DELETE without WHERE clause
│   ├── ALTER TABLE attempts
│   └── TRUNCATE attempts
├── TestEvaluateStaticPolicies - Admin Access
│   ├── Admin user can execute admin queries
│   ├── Non-admin user blocked from admin queries
│   └── Permission verification
├── TestEvaluateStaticPolicies - PII Detection
│   ├── Credit card detection
│   ├── SSN detection
│   ├── Email detection
│   └── API key detection
├── TestEvaluateStaticPolicies - Request Type Validation
│   ├── Valid request types accepted
│   ├── Invalid request types blocked
│   └── Type case handling
└── TestStaticPolicyResult
    ├── Result blocking status
    ├── Reason messages
    ├── Triggered policies list
    └── Processing time tracking
```

**Mock/Setup**:
```go
func setupTestUser(role string, permissions []string) *User
func setupTestQuery(queryType string) string
```

#### 2. Test File: `agent/db_policies_test.go`

**Test Coverage Areas**:
```
[Database Policy Engine Tests]
├── TestNewDatabasePolicyEngine
│   ├── Successful database connection
│   ├── Failed database connection fallback
│   └── Policy cache initialization
├── TestEvaluateStaticPolicies - Database Backed
│   ├── Load policies from database
│   ├── Cache policy results
│   ├── Policy refresh on TTL
│   └── Thread-safe caching
├── TestAuditQueue Integration
│   ├── Async audit logging (PERFORMANCE mode)
│   ├── Sync audit logging (COMPLIANCE mode)
│   ├── Persistent fallback on DB failure
│   └── Batch processing
├── TestRetryLogic
│   ├── Exponential backoff on failure
│   ├── Max retry attempts respected
│   └── Successful retry scenarios
└── TestMultiTenantIsolation
    ├── Policies isolated by tenant
    ├── Cross-tenant access blocked
    └── Tenant-specific caching
```

**Mock/Setup**:
```go
func setupMockDB() (*sql.DB, error)
func setupTestPolicies() []*PolicyRecord
```

#### 3. Test File: `agent/auth_test.go`

**Test Coverage Areas**:
```
[Authentication Tests]
├── TestValidateClientLicense
│   ├── Valid client with valid license key
│   ├── Invalid client ID
│   ├── Invalid license key
│   ├── Expired license
│   ├── Disabled client
│   └── Rate limit enforcement
├── TestValidateUserToken
│   ├── Valid JWT token
│   ├── Expired JWT token
│   ├── Invalid signature
│   ├── Malformed token
│   ├── Missing required claims
│   └── Test mode token acceptance
├── TestTenantIsolation
│   ├── User and client same tenant
│   ├── User and client different tenant (blocked)
│   └── Tenant ID extraction
├── TestRateLimiting
│   ├── Request within limit (allowed)
│   ├── Request at limit boundary
│   ├── Request exceeding limit (blocked)
│   ├── Rate limit reset after window
│   └── Per-client rate limits
└── TestClientWhitelist
    ├── All known clients retrievable
    ├── Correct permissions assigned
    ├── License tiers validated
    └── Tenant assignments correct
```

**Mock/Setup**:
```go
func generateTestJWT(userID int, email string) string
func setupKnownClientsWhitelist() map[string]*ClientAuth
```

#### 4. Test File: `agent/db_auth_test.go`

**Test Coverage Areas**:
```
[Database Authentication Tests]
├── TestValidateClientLicenseDB
│   ├── Database query execution
│   ├── Valid credentials from DB
│   ├── Invalid credentials
│   ├── DB connection failures
│   └── Query timeout handling
├── TestTrackAPIUsage
│   ├── Usage tracking recorded
│   ├── Concurrent tracking
│   └── Database write errors
└── TestUsageBilling
    ├── Usage limits enforced
    └── Billing calculations
```

**Mock/Setup**:
```go
func setupMockAuthDB(t *testing.T) *sql.DB
```

#### 5. Test File: `agent/redis_rate_limit_test.go`

**Test Coverage Areas**:
```
[Redis Rate Limiting Tests]
├── TestInitRedis
│   ├── Successful connection
│   ├── Invalid connection string
│   └── Connection timeout
├── TestCheckRedisRateLimit
│   ├── First request allowed
│   ├── Request within limit
│   ├── Request exceeding limit
│   ├── Rate limit reset
│   └── Concurrent requests
├── TestRedisFailover
│   ├── Fallback to in-memory on Redis failure
│   ├── Reconnection attempts
│   └── Error handling and logging
└── TestTokenBucket
    ├── Token bucket algorithm
    ├── Token refill rate
    └── Burst handling
```

**Mock/Setup**:
```go
func startMockRedisServer() (string, func())
func setupTestRateLimit(clientID string, limit int)
```

#### 6. Test File: `agent/audit_queue_test.go`

**Test Coverage Areas**:
```
[Audit Queue Tests]
├── TestNewAuditQueue
│   ├── COMPLIANCE mode initialization
│   ├── PERFORMANCE mode initialization
│   └── Database connection
├── TestQueueAuditEvent
│   ├── Event queuing (async)
│   ├── Event serialization
│   ├── Event validation
│   └── Concurrent queueing
├── TestAuditFlush
│   ├── Batch database persistence
│   ├── Transaction handling
│   └── Error recovery
├── TestPersistentFallback
│   ├── File-based fallback on DB failure
│   ├── File creation and writing
│   ├── Fallback to fallback when file fails
│   └── Recovery when DB comes back online
└── TestComplianceMode
    ├── Sync writes on violations
    ├── Async writes on normal requests
    └── Mode switching
```

**Mock/Setup**:
```go
func setupAuditQueue(mode AuditMode) *AuditQueue
func setupMockAuditDB(t *testing.T) *sql.DB
```

#### 7. Test File: `agent/license_validation_test.go`

**Test Coverage Areas**:
```
[License Validation Tests]
├── TestValidateLicense
│   ├── Valid license key format
│   ├── Valid HMAC signature
│   ├── Invalid HMAC signature
│   ├── Expired license
│   ├── License tier extraction
│   ├── Max nodes validation
│   └── Days until expiry calculation
├── TestValidateWithRetry
│   ├── Success on first attempt
│   ├── Retry on transient failure
│   ├── Exhausted retries
│   ├── Exponential backoff
│   └── Context timeout respected
└── TestLicenseTiers
    ├── BASIC tier limits
    ├── PLUS tier limits
    ├── ENTERPRISE tier limits
    └── CUSTOM tier support
```

**Mock/Setup**:
```go
func generateTestLicenseKey(tier string, nodes int, expiryDays int) string
func generateValidHMAC(data string, key []byte) string
```

#### 8. Test File: `agent/mcp_handler_test.go`

**Test Coverage Areas**:
```
[MCP Handler Tests]
├── TestInitializeMCPRegistry
│   ├── Registry creation
│   ├── PostgreSQL connector registration
│   ├── Cassandra connector registration
│   └── Error handling
├── TestRegisterPostgresConnector
│   ├── Connector registration
│   ├── Configuration loading
│   └── Connection verification
├── TestRegisterCassandraConnector
│   ├── Optional connector handling
│   ├── Configuration missing gracefully
│   └── Connection verification
└── TestMCPHandlers
    ├── List connectors endpoint
    ├── Connector health check endpoint
    └── Error responses
```

**Mock/Setup**:
```go
func setupMockMCPRegistry() *registry.Registry
func setupTestConnectorConfig() *config.ConnectorConfig
```

#### 9. Test File: `agent/main_test.go` (Integration Tests)

**Test Coverage Areas**:
```
[Integration Tests]
├── TestClientRequestHandler - Happy Path
│   ├── Valid client + valid user + allowed query
│   ├── End-to-end request processing
│   ├── Orchestrator forwarding
│   └── Response structure validation
├── TestClientRequestHandler - Error Cases
│   ├── Missing authentication
│   ├── Invalid license key
│   ├── Policy blocked request
│   ├── Rate limited request
│   ├── Orchestrator failure
│   └── Malformed request body
├── TestHealthCheck
│   ├── Service health status
│   ├── Component health aggregation
│   └── Metrics availability
├── TestMetricsEndpoint
│   ├── Metrics JSON format
│   ├── Metric values accuracy
│   └── Per-stage timing metrics
└── TestPolicyTestEndpoint
    ├── Static policy testing
    ├── Query blocking verification
    └── Policy detail response
```

**Mock/Setup**:
```go
func startTestAgent(t *testing.T) (*http.Server, string)
func createTestClientRequest(query, token string) *ClientRequest
func createMockOrchestratorServer(t *testing.T) (*http.Server, string)
```

---

### B. Orchestrator Service Tests

#### 1. Test File: `orchestrator/dynamic_policy_engine_test.go`

**Test Coverage Areas**:
```
[Dynamic Policy Engine Tests]
├── TestNewDynamicPolicyEngine
│   ├── In-memory initialization
│   ├── Database-backed initialization
│   └── Policy loading from DB
├── TestEvaluateDynamicPolicies
│   ├── Policy conditions matching
│   │   ├── contains operator
│   │   ├── equals operator
│   │   ├── greater_than operator
│   │   └── regex operator
│   ├── Policy action execution
│   │   ├── block action
│   │   ├── redact action
│   │   ├── alert action
│   │   └── log action
│   ├── Risk score calculation
│   ├── Multiple policy evaluation
│   └── Policy priority ordering
├── TestPolicyCache
│   ├── Cache hit on repeated evaluation
│   ├── Cache TTL expiration
│   ├── Cache invalidation
│   └── Thread-safe caching
├── TestListActivePolicies
│   ├── Return all active policies
│   ├── Filter disabled policies
│   └── Correct metadata
├── TestPolicyRefresh
│   ├── Periodic policy refresh
│   ├── Database change detection
│   └── Cache update on refresh
└── TestMultiTenantPolicies
    ├── Tenant-specific policies
    ├── Cross-tenant isolation
    └── Tenant ID filtering
```

**Mock/Setup**:
```go
func setupTestDynamicPolicies() []DynamicPolicy
func setupPolicyCondition(field, operator string, value interface{}) PolicyCondition
func setupPolicyAction(actionType string) PolicyAction
func setupTestRiskCalculator() *RiskCalculator
```

#### 2. Test File: `orchestrator/llm_router_test.go`

**Test Coverage Areas**:
```
[LLM Router Tests]
├── TestNewLLMRouter
│   ├── Multi-provider initialization
│   ├── OpenAI provider setup
│   ├── Anthropic provider setup
│   ├── Local LLM setup
│   └── Weight initialization
├── TestRouteRequest
│   ├── Successful routing to OpenAI
│   ├── Successful routing to Anthropic
│   ├── Successful routing to local LLM
│   ├── Provider selection based on weights
│   ├── Cost-aware routing
│   ├── Capability-based routing
│   └── Fallback when provider fails
├── TestGetProviderStatus
│   ├── Provider health status
│   ├── Request counts
│   ├── Error counts
│   ├── Average latency
│   └── Last used timestamp
├── TestUpdateProviderWeights
│   ├── Weight modification
│   ├── Weight normalization
│   ├── Invalid weights rejection
│   └── Hot reload without downtime
├── TestHealthChecker
│   ├── Provider health monitoring
│   ├── Health check failures
│   ├── Circuit breaker logic
│   └── Recovery detection
├── TestLoadBalancer
│   ├── Weight-based distribution
│   ├── Round-robin selection
│   ├── Stickiness to healthy providers
│   └── Load distribution accuracy
├── TestProviderMetricsTracker
│   ├── Latency tracking
│   ├── Error rate calculation
│   ├── Cost aggregation
│   └── Per-provider statistics
└── TestCostCalculation
    ├── OpenAI token pricing
    ├── Anthropic token pricing
    ├── Local LLM cost (free)
    └── Cost comparison for routing
```

**Mock/Setup**:
```go
func setupMockLLMProviders() map[string]LLMProvider
func createMockOpenAIProvider() LLMProvider
func createMockAnthropicProvider() LLMProvider
func setupTestQueryOptions() QueryOptions
```

#### 3. Test File: `orchestrator/planning_engine_test.go`

**Test Coverage Areas**:
```
[Planning Engine Tests]
├── TestNewPlanningEngine
│   ├── Engine initialization
│   ├── Domain template setup
│   └── LLM router integration
├── TestGeneratePlan
│   ├── Query analysis
│   ├── Task decomposition
│   ├── Travel domain planning
│   ├── Healthcare domain planning
│   ├── Finance domain planning
│   ├── Generic domain planning
│   ├── Execution mode selection (auto/parallel/sequential)
│   └── Workflow generation
├── TestAnalyzeQuery
│   ├── Domain detection
│   ├── Complexity calculation
│   ├── Parallel vs sequential decision
│   └── Suggested tasks
├── TestDomainTemplates
│   ├── Travel template tasks
│   ├── Healthcare template tasks
│   ├── Finance template tasks
│   └── Custom domain hints
├── TestWorkflowGeneration
│   ├── Step generation
│   ├── Parameter passing
│   ├── Branching logic
│   └── Timeout specifications
└── TestErrorHandling
    ├── LLM failure fallback
    ├── Invalid query handling
    └── Context propagation
```

**Mock/Setup**:
```go
func setupTestLLMRouter() *LLMRouter
func setupTestQuery(domain string, complexity string) string
func setupPlanGenerationRequest(query, domain, mode string) PlanGenerationRequest
```

#### 4. Test File: `orchestrator/workflow_engine_test.go`

**Test Coverage Areas**:
```
[Workflow Engine Tests]
├── TestNewWorkflowEngine
│   ├── Engine initialization
│   ├── Step processor registration
│   └── Storage setup
├── TestExecuteWorkflow
│   ├── Sequential step execution
│   ├── Step output chaining
│   ├── Step error handling
│   ├── Timeout handling
│   ├── Retry logic
│   ├── Conditional branching
│   └── Parallel execution
├── TestWorkflowStep Types
│   ├── LLM call step
│   ├── Connector call step
│   ├── Conditional step
│   ├── Branching step
│   └── Custom step processors
├── TestWorkflowExecution
│   ├── Execution state machine
│   ├── Step status tracking
│   ├── Execution persistence
│   ├── Execution retrieval
│   └── Execution history
├── TestParallelExecution
│   ├── Parallel task execution
│   ├── Dependency ordering
│   ├── Error handling in parallel
│   ├── Resource pooling
│   └── Timeout per task
├── TestTenantIsolation
│   ├── Tenant-specific executions
│   ├── Cross-tenant access prevention
│   └── Tenant filtering
├── TestWorkflowStorage
│   ├── Execution persistence
│   ├── Execution retrieval
│   ├── Concurrent writes
│   └── Storage failure handling
└── TestErrorRecovery
    ├── Failed step recovery
    ├── Partial execution resume
    ├── Rollback scenarios
    └── Cleanup on failure
```

**Mock/Setup**:
```go
func setupTestWorkflow() *Workflow
func setupTestWorkflowStep(name, stepType string) WorkflowStep
func setupMockStepProcessor() StepProcessor
func setupTestWorkflowExecution() *WorkflowExecution
```

#### 5. Test File: `orchestrator/result_aggregator_test.go`

**Test Coverage Areas**:
```
[Result Aggregator Tests]
├── TestNewResultAggregator
│   ├── Aggregator initialization
│   └── LLM router integration
├── TestAggregateResults
│   ├── Successful results synthesis
│   ├── Filter successful vs failed
│   ├── LLM-based synthesis
│   ├── Fallback to concatenation
│   ├── Error handling
│   └── Original query preservation
├── TestBuildSynthesisPrompt
│   ├── Prompt construction
│   ├── Task result inclusion
│   ├── Instruction clarity
│   └── Prompt length limits
├── TestSimpleConcatenation
│   ├── Fallback formatting
│   ├── Result ordering
│   └── Status inclusion
├── TestAggregationStats
│   ├── Task count calculation
│   ├── Success rate calculation
│   ├── Total time aggregation
│   └── Failed task counting
└── TestAggregateWithCustomPrompt
    ├── Custom prompt usage
    ├── Custom prompt synthesis
    └── Fallback on failure
```

**Mock/Setup**:
```go
func setupTestResultAggregator() *ResultAggregator
func setupTestStepExecutions(count int, successCount int) []StepExecution
func setupMockLLMResponse(content string) *LLMResponse
```

#### 6. Test File: `orchestrator/response_processor_test.go`

**Test Coverage Areas**:
```
[Response Processor Tests]
├── TestNewResponseProcessor
│   ├── Processor initialization
│   └── PII pattern compilation
├── TestProcessResponse
│   ├── No PII response (no redaction)
│   ├── With PII detection
│   ├── Redaction accuracy
│   └── User role-based filtering
├── TestPIIDetection
│   ├── Credit card detection
│   │   ├── Visa patterns
│   │   ├── Mastercard patterns
│   │   ├── American Express
│   │   └── Discover
│   ├── Social Security Number detection
│   ├── Phone number detection
│   ├── Email address detection
│   ├── API key detection
│   ├── False positive rate
│   └── False negative rate
├── TestRedactionLogic
│   ├── PII replacement (*****)
│   ├── Partial redaction
│   ├── Pattern matching accuracy
│   └── Edge cases
├── TestUserRoleFiltering
│   ├── Admin can see all data
│   ├── Standard user sees redacted
│   ├── Guest user sees minimal data
│   └── Custom role permissions
└── TestPerformance
    ├── Large response processing
    ├── Pattern matching performance
    └── Memory usage
```

**Mock/Setup**:
```go
func setupTestResponseProcessor() *ResponseProcessor
func setupTestLLMResponse(content string) *LLMResponse
func setupTestUserContexts() map[string]UserContext
```

#### 7. Test File: `orchestrator/audit_logger_test.go`

**Test Coverage Areas**:
```
[Audit Logger Tests]
├── TestNewAuditLogger
│   ├── Logger initialization
│   └── Database connection
├── TestLogSuccessfulRequest
│   ├── Event recording
│   ├── Database persistence
│   ├── Required field inclusion
│   └── Metadata accuracy
├── TestLogBlockedRequest
│   ├── Policy block logging
│   ├── Block reason inclusion
│   ├── Severity levels
│   └── Triggering policy tracking
├── TestLogFailedRequest
│   ├── Error logging
│   ├── Exception details
│   ├── Stack trace (if available)
│   └── Request context
├── TestSearchAuditLogs
│   ├── Search by user email
│   ├── Search by client ID
│   ├── Search by time range
│   ├── Search by request type
│   ├── Pagination/limiting
│   └── Result ordering
├── TestMultiTenantAudit
│   ├── Tenant isolation
│   ├── Tenant-specific searches
│   └── Cross-tenant prevention
├── TestAuditEventSerialization
│   ├── JSON encoding
│   ├── Timestamp formatting
│   └── Error handling
└── TestDatabasePersistence
    ├── Insert accuracy
    ├── Concurrent writes
    └── Query performance
```

**Mock/Setup**:
```go
func setupMockAuditDB(t *testing.T) *sql.DB
func setupTestAuditLogger() *AuditLogger
func setupTestAuditEvent() *AuditEvent
func setupMigrations(t *testing.T, db *sql.DB)
```

#### 8. Test File: `orchestrator/metrics_collector_test.go`

**Test Coverage Areas**:
```
[Metrics Collector Tests]
├── TestNewMetricsCollector
│   ├── Collector initialization
│   └── Metric registration
├── TestRecordRequest
│   ├── Request metric recording
│   ├── Per-type aggregation
│   ├── Per-provider aggregation
│   └── Timing accuracy
├── TestGetMetrics
│   ├── Overall metrics aggregation
│   ├── Per-request-type metrics
│   ├── Provider metrics
│   ├── Policy metrics
│   └── Timing statistics
├── TestPercentileCalculation
│   ├── P99 calculation
│   ├── P95 calculation
│   ├── P50 (median) calculation
│   └── Edge cases (low volume)
├── TestAverageCalculation
│   ├── Average response time
│   ├── Average per type
│   ├── Average per provider
│   └── Weighted average
├── TestProviderMetrics
│   ├── Provider request count
│   ├── Provider error count
│   ├── Provider average latency
│   └── Provider cost tracking
└── TestConcurrentMetrics
    ├── Thread-safe recording
    ├── Concurrent retrieval
    └── Race condition prevention
```

**Mock/Setup**:
```go
func setupTestMetricsCollector() *MetricsCollector
func recordTestMetrics(mc *MetricsCollector, count int)
func setupProviderMetrics(provider string) ProviderMetrics
```

#### 9. Test File: `orchestrator/amadeus_client_test.go`

**Test Coverage Areas**:
```
[Amadeus Client Tests]
├── TestNewAmadeusClient
│   ├── Client initialization
│   ├── API key loading
│   └── Configuration validation
├── TestSearchFlights
│   ├── Valid search request
│   ├── Valid response parsing
│   ├── Multiple flight options
│   ├── Price formatting
│   ├── Invalid parameters
│   ├── API error handling
│   └── Timeout handling
├── TestSearchHotels
│   ├── Valid search request
│   ├── Valid response parsing
│   ├── Multiple hotel options
│   ├── Rate formatting
│   ├── Invalid parameters
│   ├── API error handling
│   └── Timeout handling
├── TestIsConfigured
│   ├── With API credentials
│   ├── Without API credentials
│   └── Partial configuration
├── TestMockDataFallback
│   ├── Fallback on API failure
│   ├── Mock data structure
│   └── Realistic mock values
└── TestAuthentication
    ├── OAuth token handling
    ├── Token refresh
    └── Credential security
```

**Mock/Setup**:
```go
func setupMockAmadeusAPI(t *testing.T) (*http.Server, string)
func setupAmadeusFlightResponse() interface{}
func setupAmadeusHotelResponse() interface{}
func setupAmadeusClient(apiKey, apiSecret string) *AmadeusClient
```

#### 10. Test File: `orchestrator/main_test.go` (Integration Tests)

**Test Coverage Areas**:
```
[Integration Tests]
├── TestProcessRequestHandler - Happy Path
│   ├── Policy evaluation → Allow
│   ├── LLM routing → Response
│   ├── PII detection → Redaction
│   ├── Audit logging
│   └── Metrics recording
├── TestProcessRequestHandler - Policy Blocked
│   ├── Policy evaluation → Block
│   ├── Error response structure
│   ├── Audit log for block
│   └── Metrics update
├── TestMultiAgentPlanning
│   ├── Planning request received
│   ├── Plan generation
│   ├── Workflow execution
│   ├── Result aggregation
│   └── Response structure
├── TestWorkflowExecution
│   ├── Workflow definition validation
│   ├── Step execution
│   ├── Execution persistence
│   └── Execution retrieval
├── TestHealthCheck
│   ├── Service health status
│   ├── Component health aggregation
│   ├── Feature availability
│   └── Health transition
├── TestMetricsEndpoints
│   ├── JSON metrics format
│   ├── Prometheus format
│   ├── Metric value accuracy
│   └── Per-stage metrics
├── TestAuditLogging
│   ├── Request audit trail
│   ├── Search functionality
│   ├── Tenant filtering
│   └── Time-range filtering
└── TestConnectorManagement
    ├── List available connectors
    ├── Get connector details
    ├── Install connector
    ├── Uninstall connector
    └── Health checks
```

**Mock/Setup**:
```go
func startTestOrchestrator(t *testing.T) (*http.Server, string)
func createTestOrchestratorRequest(query string, requestType string) OrchestratorRequest
func createMockAgentServer(t *testing.T) (*http.Server, string)
func setupMockDynamicPolicyEngine() DynamicPolicyEngine
func setupMockLLMRouter() *LLMRouter
```

---

### C. Shared Library Tests

#### 1. Test File: `shared/logger/logger_test.go`

**Test Coverage Areas**:
```
[Logger Tests]
├── TestNewLogger
│   ├── Logger initialization
│   ├── Component name assignment
│   ├── Instance ID loading
│   └── Container name detection
├── TestLog - All Levels
│   ├── DEBUG level logging
│   ├── INFO level logging
│   ├── WARN level logging
│   ├── ERROR level logging
│   └── LogLevel constants
├── TestLogEntry - JSON Structure
│   ├── Timestamp RFC3339 format
│   ├── All required fields present
│   ├── Fields map serialization
│   ├── Null field handling
│   └── Special character escaping
├── TestConvenienceMethods
│   ├── Info() method
│   ├── Error() method
│   ├── Warn() method
│   ├── Debug() method
│   ├── InfoWithDuration() method
│   └── ErrorWithCode() method
├── TestMultiTenantFields
│   ├── ClientID inclusion
│   ├── RequestID inclusion
│   ├── Both IDs in same log
│   └── Empty ID handling
├── TestFieldsParameter
│   ├── Nil fields handling
│   ├── Empty map handling
│   ├── Complex field values
│   ├── Type assertions
│   └── Large field counts
├── TestJSONMarshal
│   ├── Valid JSON output
│   ├── Unmarshal accuracy
│   ├── Error handling
│   └── Concurrency safety
└── TestEdgeCases
    ├── Very long messages
    ├── Special characters
    ├── Large field values
    └── Concurrent logging
```

**Mock/Setup**:
```go
func setupTestLogger(component string) *Logger
func captureLogOutput(t *testing.T, fn func()) string
func parseLogJSON(logLine string) *LogEntry
```

---

## VI. TEST INFRASTRUCTURE SETUP

### A. Testing Framework & Tools

**Recommended Stack**:
```
Testing Framework: Go's built-in testing (no external deps)
Mocking: 
  - Manual interfaces (preferred for interfaces in codebase)
  - github.com/golang/mock/gomock (for complex mocking)
  - testify/mock (alternative)
Database Testing:
  - github.com/testcontainers/testcontainers-go
  - Custom Docker containers
  - In-memory SQL databases
HTTP Testing:
  - httptest package (built-in)
  - Custom mock servers
Assertion Library:
  - testify/assert (optional)
  - Built-in comparisons (preferred)
Benchmarking:
  - testing.B (built-in)
  - Custom benchmark harnesses
```

### B. Test Configuration

**Environment Variables for Tests**:
```bash
# Database
TEST_DATABASE_URL=postgres://test:test@localhost:5432/axonflow_test
TEST_REDIS_URL=redis://localhost:6379

# API Keys
TEST_OPENAI_API_KEY=sk-test-xxxxx
TEST_ANTHROPIC_API_KEY=sk-ant-test-xxxxx
TEST_AMADEUS_API_KEY=test-key
TEST_AMADEUS_API_SECRET=test-secret

# Service URLs
TEST_ORCHESTRATOR_URL=http://localhost:8081
TEST_AGENT_URL=http://localhost:8080
TEST_LOCAL_LLM_ENDPOINT=http://localhost:8000

# License
TEST_AXONFLOW_LICENSE_KEY=AXON-TEST-key

# Feature Flags
TEST_SKIP_EXTERNAL_CALLS=true
TEST_USE_MOCK_RESPONSES=true
```

### C. Test Database Setup

**Database Schema for Tests**:
```sql
-- Create test-specific schema
CREATE SCHEMA IF NOT EXISTS test;

-- Client credentials
CREATE TABLE IF NOT EXISTS test.clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    license_key VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    tenant_id VARCHAR(255),
    permissions TEXT[] DEFAULT ARRAY[]::TEXT[],
    rate_limit INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true
);

-- User information
CREATE TABLE IF NOT EXISTS test.users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    department VARCHAR(255),
    role VARCHAR(50),
    region VARCHAR(50),
    permissions TEXT[] DEFAULT ARRAY[]::TEXT[],
    tenant_id VARCHAR(255)
);

-- Static policies
CREATE TABLE IF NOT EXISTS test.policies (
    id SERIAL PRIMARY KEY,
    policy_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    category VARCHAR(50),
    pattern TEXT,
    severity VARCHAR(20),
    description TEXT,
    action VARCHAR(50),
    tenant_id VARCHAR(255),
    enabled BOOLEAN DEFAULT true
);

-- Dynamic policies
CREATE TABLE IF NOT EXISTS test.policies_dynamic (
    id SERIAL PRIMARY KEY,
    policy_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    description TEXT,
    type VARCHAR(50),
    conditions JSONB,
    actions JSONB,
    priority INT,
    enabled BOOLEAN DEFAULT true,
    tenant_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Audit logs
CREATE TABLE IF NOT EXISTS test.audit_logs (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(255),
    user_email VARCHAR(255),
    client_id VARCHAR(255),
    tenant_id VARCHAR(255),
    request_type VARCHAR(50),
    query TEXT,
    status VARCHAR(20),
    blocked BOOLEAN DEFAULT false,
    block_reason TEXT,
    redacted BOOLEAN DEFAULT false,
    response_summary TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_tenant (tenant_id),
    INDEX idx_user (user_email),
    INDEX idx_client (client_id)
);

-- Workflow executions
CREATE TABLE IF NOT EXISTS test.workflow_executions (
    id VARCHAR(255) PRIMARY KEY,
    workflow_name VARCHAR(255),
    tenant_id VARCHAR(255),
    user_email VARCHAR(255),
    status VARCHAR(50),
    input JSONB,
    output JSONB,
    steps JSONB,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    error TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_tenant (tenant_id)
);
```

### D. CI/CD Integration

**GitHub Actions Workflow** (`.github/workflows/test.yml`):
```yaml
name: Go Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: axonflow_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: 1.21
      
      - name: Run tests
        run: |
          cd platform
          go test -v -race -coverprofile=coverage.out ./...
        env:
          TEST_DATABASE_URL: postgres://test:test@localhost:5432/axonflow_test
          TEST_REDIS_URL: redis://localhost:6379
          TEST_SKIP_EXTERNAL_CALLS: "true"
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./platform/coverage.out
```

---

## VII. CRITICAL BUSINESS LOGIC GAPS

### A. Agent Service - Missing Test Coverage

**Priority: CRITICAL**

1. **Policy Enforcement** - Core security feature
   - SQL injection detection regex patterns
   - Dangerous query blocking (DROP, DELETE, ALTER)
   - Admin access control
   - Multi-policy combination logic

2. **Authentication Chain** - Security-critical
   - License key validation with HMAC
   - JWT token parsing and validation
   - Tenant isolation enforcement
   - Concurrent authentication requests

3. **Rate Limiting** - Resource protection
   - Token bucket algorithm
   - Redis distributed rate limiting
   - In-memory fallback behavior
   - Concurrent request handling

4. **Audit Logging** - Compliance requirement
   - Async queue behavior
   - Persistent file fallback
   - Event serialization/deserialization
   - Database persistence under load

### B. Orchestrator Service - Missing Test Coverage

**Priority: CRITICAL**

1. **Dynamic Policies** - Runtime enforcement
   - Policy condition evaluation (all operators)
   - Risk score calculation
   - Policy prioritization
   - Policy cache invalidation

2. **LLM Routing** - Feature core
   - Multi-provider selection
   - Weight-based routing algorithm
   - Cost calculation and comparison
   - Provider health monitoring
   - Circuit breaker logic

3. **Workflow Orchestration** - Feature core
   - Sequential step execution
   - Parallel execution with dependencies
   - Conditional branching
   - Error recovery and retries
   - Timeout enforcement

4. **Planning Engine** - Complex feature
   - Query analysis and decomposition
   - Domain detection
   - Task generation
   - Workflow template application
   - Execution mode selection

5. **Result Aggregation** - Feature quality
   - LLM-based synthesis
   - Fallback concatenation
   - Custom prompt handling
   - Statistics calculation

### C. Shared Libraries - Missing Test Coverage

**Priority: HIGH**

1. **Structured Logger** - Infrastructure
   - JSON serialization
   - Multi-tenant field handling
   - Concurrent logging
   - Error handling

---

## VIII. TESTING BEST PRACTICES FOR AXONFLOW

### A. Test Organization

```
/platform/
├── agent/
│   ├── main.go
│   ├── auth.go
│   ├── static_policies.go
│   ├── ...
│   ├── main_test.go              (integration)
│   ├── auth_test.go              (unit)
│   ├── static_policies_test.go   (unit)
│   └── testdata/                 (test fixtures)
│       ├── valid_queries.json
│       ├── malicious_queries.json
│       └── test_tokens.json
│
├── orchestrator/
│   ├── main.go
│   ├── llm_router.go
│   ├── ...
│   ├── main_test.go              (integration)
│   ├── llm_router_test.go        (unit)
│   └── testdata/
│       ├── test_workflows.json
│       ├── mock_llm_responses.json
│       └── test_policies.json
│
└── shared/
    └── logger/
        ├── logger.go
        ├── logger_test.go
        └── testdata/
            └── sample_logs.json
```

### B. Common Test Patterns

**1. Table-Driven Tests**:
```go
func TestStaticPolicyEvaluation(t *testing.T) {
    tests := []struct {
        name        string
        query       string
        user        *User
        expectBlocked bool
        expectReason string
    }{
        {
            name:        "valid query",
            query:       "SELECT * FROM users WHERE id = 1",
            user:        &User{Role: "user"},
            expectBlocked: false,
        },
        {
            name:        "sql injection",
            query:       "SELECT * FROM users WHERE id = 1 OR '1'='1'",
            user:        &User{Role: "user"},
            expectBlocked: true,
            expectReason: "SQL injection",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            engine := NewStaticPolicyEngine()
            result := engine.EvaluateStaticPolicies(tt.user, tt.query, "sql")
            
            if result.Blocked != tt.expectBlocked {
                t.Errorf("expected blocked=%v, got %v", tt.expectBlocked, result.Blocked)
            }
        })
    }
}
```

**2. Mock Interfaces**:
```go
type MockLLMProvider struct {
    QueryFunc func(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error)
    healthFunc func() bool
}

func (m *MockLLMProvider) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
    return m.QueryFunc(ctx, prompt, options)
}

func (m *MockLLMProvider) IsHealthy() bool {
    return m.healthFunc()
}
```

**3. Setup/Teardown**:
```go
func TestDatabasePolicyEngine(t *testing.T) {
    // Setup
    db := setupTestDB(t)
    defer db.Close()
    
    engine, err := NewDatabasePolicyEngine()
    if err != nil {
        t.Fatalf("failed to create engine: %v", err)
    }
    
    // Test
    result := engine.EvaluateStaticPolicies(testUser, testQuery, "sql")
    
    // Verify
    if !result.Blocked {
        t.Error("expected request to be blocked")
    }
}
```

### C. Testing Multi-Tenant Logic

```go
func TestMultiTenantIsolation(t *testing.T) {
    engine := NewDynamicPolicyEngine()
    
    // Setup tenant-specific policies
    policy1 := DynamicPolicy{ID: "p1", TenantID: "tenant_a", Enabled: true}
    policy2 := DynamicPolicy{ID: "p2", TenantID: "tenant_b", Enabled: true}
    
    // Request from tenant_a
    req := OrchestratorRequest{
        User: UserContext{TenantID: "tenant_a"},
    }
    
    result := engine.EvaluateDynamicPolicies(context.Background(), req)
    
    // Verify only tenant_a policies evaluated
    for _, policy := range result.AppliedPolicies {
        if policy == "p2" {
            t.Error("policy from different tenant evaluated!")
        }
    }
}
```

### D. Testing Concurrency

```go
func TestConcurrentRateLimiting(t *testing.T) {
    done := make(chan bool)
    rateLimiter := NewRedisRateLimiter("client_1", 100)
    
    // Simulate 200 concurrent requests
    for i := 0; i < 200; i++ {
        go func() {
            blocked, err := rateLimiter.Check()
            if err != nil {
                t.Errorf("error: %v", err)
            }
            done <- !blocked
        }()
    }
    
    // Collect results
    allowedCount := 0
    for i := 0; i < 200; i++ {
        if <-done {
            allowedCount++
        }
    }
    
    // Should allow 100, block 100 (rate limit is 100/min)
    if allowedCount != 100 {
        t.Errorf("expected 100 allowed, got %d", allowedCount)
    }
}
```

### E. Testing Error Paths

```go
func TestDatabaseFailoverFallback(t *testing.T) {
    // Create policy engine with bad DB
    dbURL := "postgres://invalid:invalid@invalid:5432/invalid"
    os.Setenv("DATABASE_URL", dbURL)
    
    // Should fall back to in-memory policies
    engine, err := NewDatabasePolicyEngine()
    
    // Verify fallback works
    result := engine.EvaluateStaticPolicies(testUser, "SELECT 1 DROP", "sql")
    
    if !result.Blocked {
        t.Error("fallback policy engine not working")
    }
}
```

---

## IX. RECOMMENDED TEST EXECUTION ORDER

### Phase 1: Unit Tests (Week 1)
1. Shared libraries (logger)
2. Agent auth modules
3. Agent policy modules
4. Orchestrator policy modules

### Phase 2: Unit Tests (Week 2)
5. LLM router tests
6. Workflow engine tests
7. Planning engine tests
8. Response processor tests

### Phase 3: Integration Tests (Week 3)
9. Agent main integration
10. Orchestrator main integration
11. Multi-service integration

### Phase 4: Performance & Load (Week 4)
12. Benchmarks
13. Load testing
14. Chaos engineering

---

## X. COVERAGE TARGETS

### Minimum Coverage by Service
- **Agent Service**: 80% code coverage
- **Orchestrator Service**: 75% code coverage  
- **Shared Libraries**: 90% code coverage

### Critical Paths (Must Be 100% Covered)
- Policy evaluation engines
- Authentication and authorization
- Audit logging
- Error handling in core flows

---

## Summary

This document provides a complete blueprint for unit testing the AxonFlow backend services. Key findings:

1. **No existing tests** - All files are untested
2. **86 critical test files** need to be created
3. **~2000+ test cases** required for comprehensive coverage
4. **Go testing framework** is recommended (built-in, no external deps)
5. **Database mocking** is essential for fast tests
6. **Integration tests** are critical for multi-service flows

**Estimated Effort**: 160-200 hours for comprehensive test coverage

**Next Steps**:
1. Set up test infrastructure (database, mocking framework)
2. Implement Phase 1 tests (shared libraries + auth)
3. Build test fixtures and mock data
4. Integrate with CI/CD pipeline
5. Establish coverage monitoring

