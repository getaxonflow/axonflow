# Comprehensive End-to-End Test Plan: Travel & Core Platform

*Created: Oct 14, 2025*
*Context: Post-MMT Partnership Pack - Validation of Oct 8-12 deployment*

## Overview

This test plan covers comprehensive validation of:
1. **Core orchestration functionality** (multi-agent coordination, routing, policy enforcement)
2. **MCP connector health** (PostgreSQL, Cassandra, permission-aware access)
3. **MAP task decomposition** (parallel execution planning, result synthesis)
4. **Permission enforcement** (RBAC/ABAC, tenant isolation)
5. **Multi-tenant isolation** (data separation, resource limits)
6. **Failover scenarios** (agent failures, API timeouts, degraded mode)
7. **Trip planner edge cases** (invalid inputs, impossible scenarios, concurrent load)

---

## Test Architecture

### Test Environment
- **Target**: `travel-eu.getaxonflow.com` (EU production environment)
- **Backend**: 40 Agent replicas + 20 Orchestrator replicas on Kubernetes
- **Database**: PostgreSQL (tenant data) + Cassandra (booking history)
- **APIs**: Amadeus (flights), Booking.com patterns (hotels), Open Exchange Rates (forex)
- **Observability**: Prometheus + Grafana dashboards

### Test Data Fixtures
```
Valid Destinations: Paris, Tokyo, Barcelona, New York, Dubai, Singapore
Valid Date Ranges: +7 days to +90 days from today
Budget Levels: low (<$1000), moderate ($1000-3000), high (>$3000)
Travelers: 1-10 people
Trip Duration: 1-14 days
```

### Success Criteria
- **P95 Latency**: Agent <10ms, Orchestrator <30ms
- **Availability**: 99.9% uptime during test window
- **Correctness**: 100% valid responses for valid inputs
- **Error Handling**: Graceful degradation for invalid inputs
- **Isolation**: Zero cross-tenant data leakage
- **Failover**: <5s recovery time for agent failures

---

## 1. Core Orchestration Functionality Tests

### Test 1.1: Basic Multi-Agent Coordination
**Objective**: Validate that Orchestrator correctly coordinates multiple agents in parallel

**Test Cases**:
```
TC1.1.1: Single agent request (flight only)
Input: "Find flights from Delhi to Paris for 1 person"
Expected: Flight agent invoked, results returned in <3s

TC1.1.2: Two parallel agents (flights + hotels)
Input: "Plan trip to Paris for 2 days with hotels"
Expected: Flight + Hotel agents run concurrently, results in <5s

TC1.1.3: Three parallel agents (flights + hotels + forex)
Input: "Paris 3 days trip with moderate budget"
Expected: Flight + Hotel + Forex agents run concurrently, results in <20s

TC1.1.4: Four parallel agents (add activities)
Input: "Complete Tokyo trip with activities for 5 days"
Expected: All 4 agents run concurrently, results in <25s
```

**Validation**:
- Check Grafana: Agent invocation timestamps overlap (parallel execution)
- Verify orchestrator latency: <30ms P95
- Confirm result aggregation: All agent responses present in final output
- No serial execution (Total time < sum of individual agent times)

### Test 1.2: Routing Logic
**Objective**: Validate that Orchestrator routes requests to correct agents

**Test Cases**:
```
TC1.2.1: Flight-only query routes to Flight Agent only
TC1.2.2: Hotel-only query routes to Hotel Agent only
TC1.2.3: Forex-only query routes to Forex Agent only
TC1.2.4: Combined query routes to multiple agents
TC1.2.5: Ambiguous query handled gracefully (e.g., "trip to Paris" without details)
```

**Validation**:
- Check Prometheus metrics: Verify only expected agents received requests
- Review audit logs: Confirm routing decisions logged correctly
- Validate response structure matches expected agents

### Test 1.3: Policy Enforcement
**Objective**: Validate that policies are enforced at orchestration layer

**Test Cases**:
```
TC1.3.1: Rate limiting (>100 requests/min from single user)
Expected: 429 Too Many Requests after threshold

TC1.3.2: Tenant quota enforcement (exceed daily request limit)
Expected: 403 Forbidden with quota exceeded message

TC1.3.3: Unauthorized API access (invalid JWT token)
Expected: 401 Unauthorized

TC1.3.4: Forbidden resource access (tenant A tries to access tenant B data)
Expected: 403 Forbidden with tenant isolation message
```

**Validation**:
- Confirm policy engine logs show evaluation steps
- Verify audit trail captures policy violations
- Check that legitimate requests are not blocked

---

## 2. MCP Connector Health Checks

### Test 2.1: PostgreSQL Connector
**Objective**: Validate PostgreSQL MCP connector performance and correctness

**Test Cases**:
```
TC2.1.1: Basic read query (fetch user preferences)
Expected: <12ms P95, correct data returned

TC2.1.2: Complex join query (multi-table booking history)
Expected: <15ms P95, correct aggregated data

TC2.1.3: Write query (save trip preferences)
Expected: <20ms P95, data persisted correctly

TC2.1.4: Connection pool health (200 connections/replica)
Expected: No connection exhaustion under load

TC2.1.5: Permission-aware query (user can only see own data)
Expected: ABAC rules applied, no data leakage
```

**Validation**:
- Monitor Grafana: PostgreSQL query latency metrics
- Check connection pool: No "too many connections" errors
- Verify data correctness: Sample queries match expected results
- Audit logs: Permission checks logged for every query

### Test 2.2: Cassandra Connector
**Objective**: Validate Cassandra MCP connector for booking history access

**Test Cases**:
```
TC2.2.1: Read booking history (single user, last 30 days)
Expected: <11ms P95, correct records returned

TC2.2.2: Read booking history (multiple users, aggregated)
Expected: <15ms P95, correct aggregation

TC2.2.3: Time-range query (last 90 days)
Expected: <20ms P95, correct date filtering

TC2.2.4: Consistency level validation (LOCAL_QUORUM)
Expected: Strong consistency, no stale reads

TC2.2.5: Tenant isolation (partition key enforcement)
Expected: Each tenant sees only own booking history
```

**Validation**:
- Monitor Grafana: Cassandra query latency metrics
- Verify consistency: No stale or duplicate records
- Check partition distribution: Balanced across replicas
- Audit logs: Tenant ID verified in every query

### Test 2.3: Permission Layer
**Objective**: Validate RBAC/ABAC enforcement in MCP layer

**Test Cases**:
```
TC2.3.1: Admin role can access all tenant data
TC2.3.2: User role can only access own data
TC2.3.3: Service account has read-only access
TC2.3.4: Anonymous request blocked
TC2.3.5: Expired token rejected
```

**Validation**:
- Permission checks logged with decision rationale
- Policy evaluation time: <5ms overhead
- Zero false positives (legitimate access denied)
- Zero false negatives (illegitimate access granted)

---

## 3. MAP Task Decomposition Tests

### Test 3.1: Parallel Execution Planning
**Objective**: Validate that MAP framework correctly identifies parallel tasks

**Test Cases**:
```
TC3.1.1: Independent tasks decomposed to parallel (flights + hotels + forex)
Expected: Execution plan shows parallel strategy

TC3.1.2: Dependent tasks serialized (get hotel, THEN get nearby restaurants)
Expected: Execution plan shows sequential strategy

TC3.1.3: Mixed dependencies (parallel flights+hotels, THEN aggregate pricing)
Expected: Execution plan shows hybrid strategy

TC3.1.4: Single task (no decomposition needed)
Expected: Direct agent invocation, no planning overhead
```

**Validation**:
- Review planner logs: Task decomposition reasoning captured
- Check execution traces: Parallel tasks have overlapping timestamps
- Verify speedup: Parallel execution ~40X faster than sequential
- No unnecessary decomposition: Simple queries handled directly

### Test 3.2: Result Synthesis
**Objective**: Validate that MAP correctly aggregates multi-agent results

**Test Cases**:
```
TC3.2.1: Aggregate flight + hotel + forex into coherent trip plan
Expected: Total cost calculated, currency converted, recommendations ranked

TC3.2.2: Handle partial results (flights found, hotels unavailable)
Expected: Show available results + explain missing data

TC3.2.3: Handle conflicting data (hotel price changed during query)
Expected: Use latest data + log inconsistency warning

TC3.2.4: Rank results by user preference (budget constraint)
Expected: Show options sorted by fit score
```

**Validation**:
- Final output contains all expected fields
- Calculations correct (total cost = flights + hotels + activities)
- Ranking logic applied consistently
- Missing data handled gracefully (no errors)

### Test 3.3: Planner Performance
**Objective**: Validate that MAP adds minimal overhead

**Test Cases**:
```
TC3.3.1: Simple query (1 agent) - planning overhead <500ms
TC3.3.2: Moderate query (2-3 agents) - planning overhead <1500ms
TC3.3.3: Complex query (4+ agents) - planning overhead <2500ms
TC3.3.4: Cached plan reuse (same query repeated)
Expected: Planning overhead <100ms on cache hit
```

**Validation**:
- Measure planning time separately from agent execution time
- Check cache hit rate: >80% for repeated queries
- Verify LLM token usage: <1000 tokens per planning request
- No planning failures: 100% success rate for valid inputs

---

## 4. Permission Enforcement Tests

### Test 4.1: RBAC (Role-Based Access Control)
**Objective**: Validate role-based permissions work correctly

**Test Cases**:
```
TC4.1.1: Admin user can access trip plans for all tenants
TC4.1.2: Regular user can only access own trip plans
TC4.1.3: Guest user can browse but not save trips
TC4.1.4: Service account can read metrics but not user data
TC4.1.5: Role change takes effect immediately (no stale permissions)
```

**Validation**:
- Policy engine evaluates role correctly
- Permission denied returns 403 with clear message
- Audit trail captures role in every decision
- Role cache invalidated on change

### Test 4.2: ABAC (Attribute-Based Access Control)
**Objective**: Validate attribute-based policies work correctly

**Test Cases**:
```
TC4.2.1: User can access trip plans created by self
TC4.2.2: User cannot access trip plans created by others
TC4.2.3: Shared trip plan accessible to all collaborators
TC4.2.4: Time-based policy (business hours only)
TC4.2.5: Location-based policy (EU users can access EU data only)
```

**Validation**:
- Attribute extraction from context (user, tenant, time, location)
- Policy evaluation considers all relevant attributes
- Policy decisions logged with attribute values
- Policy updates take effect within 5s

---

## 5. Multi-Tenant Isolation Tests

### Test 5.1: Data Isolation
**Objective**: Validate that tenants cannot access each other's data

**Test Cases**:
```
TC5.1.1: Tenant A cannot read Tenant B trip plans (direct ID guess)
TC5.1.2: Tenant A cannot read Tenant B booking history (database query)
TC5.1.3: Tenant A cannot write to Tenant B namespace (malicious update)
TC5.1.4: Cross-tenant query returns 403 (database enforces tenant_id filter)
TC5.1.5: Admin can access all tenants (superuser exception)
```

**Validation**:
- Database queries always include tenant_id filter
- Application layer validates tenant_id in JWT matches resource
- Audit logs capture cross-tenant access attempts
- Zero data leakage in 1000+ randomized tests

### Test 5.2: Resource Isolation
**Objective**: Validate that tenants have fair resource allocation

**Test Cases**:
```
TC5.2.1: Tenant A heavy load does not impact Tenant B latency
TC5.2.2: Tenant quota enforcement (Tenant A exceeds limit, gets throttled)
TC5.2.3: Agent replica distribution (each tenant gets fair share)
TC5.2.4: Database connection limits (per-tenant connection pool)
TC5.2.5: Rate limiting per tenant (not global)
```

**Validation**:
- Monitor per-tenant latency metrics during load test
- Verify quota counters tracked independently per tenant
- Check connection pool: No single tenant monopolizes connections
- Rate limits applied per tenant, not globally

### Test 5.3: Configuration Isolation
**Objective**: Validate that tenant configurations are isolated

**Test Cases**:
```
TC5.3.1: Tenant A custom policy does not affect Tenant B
TC5.3.2: Tenant A API key does not work for Tenant B resources
TC5.3.3: Tenant A feature flags do not leak to Tenant B
TC5.3.4: Tenant configuration change (Tenant A) does not impact Tenant B
TC5.3.5: Tenant deletion removes all data for that tenant only
```

**Validation**:
- Policy engine loads tenant-specific policies
- API keys scoped to tenant_id
- Feature flag evaluation includes tenant context
- Configuration changes logged per tenant

---

## 6. Failover Scenario Tests

### Test 6.1: Agent Failures
**Objective**: Validate graceful degradation when agents fail

**Test Cases**:
```
TC6.1.1: Flight Agent down - return partial results (hotels + forex only)
Expected: User sees hotels + forex, message "Flights temporarily unavailable"

TC6.1.2: Hotel Agent slow (>30s timeout) - return partial results
Expected: User sees flights + forex, message "Hotels loading slowly, check back"

TC6.1.3: Forex Agent unavailable - use cached exchange rates
Expected: User sees flights + hotels, note "Exchange rates as of [timestamp]"

TC6.1.4: All agents down - return error with clear message
Expected: 503 Service Unavailable, "Try again in a few minutes"

TC6.1.5: Agent recovery - resume normal operation
Expected: Next request succeeds, no manual intervention needed
```

**Validation**:
- Check health checks: Failed agents marked unhealthy within 10s
- Orchestrator routing: Skips unhealthy agents automatically
- Partial results: User sees what's available + clear explanation
- Recovery time: <5s from agent restart to traffic resumption

### Test 6.2: API Timeouts
**Objective**: Validate handling of external API timeouts

**Test Cases**:
```
TC6.2.1: Amadeus API timeout (>10s) - return error, don't block other agents
TC6.2.2: Booking.com API timeout - use cached data if available
TC6.2.3: Forex API timeout - use stale exchange rates + warning
TC6.2.4: Multiple API timeouts - degrade gracefully, show what's available
TC6.2.5: API recovery - clear error state, resume normal operation
```

**Validation**:
- Timeout configuration: Each API has appropriate timeout (5-15s)
- Circuit breaker: After 5 consecutive failures, stop trying for 60s
- Fallback data: Cache used when external API unavailable
- User feedback: Clear message about what's cached vs live

### Test 6.3: Database Failures
**Objective**: Validate handling of database connection failures

**Test Cases**:
```
TC6.3.1: PostgreSQL primary down - fail over to read replica
Expected: Read queries succeed, write queries return 503

TC6.3.2: Cassandra node down - query remaining replicas
Expected: No user-visible impact, latency <20ms P95

TC6.3.3: Database connection pool exhausted - queue requests
Expected: Requests wait up to 5s, then 503 if pool still full

TC6.3.4: Database slow query (>1s) - return cached data
Expected: User sees stale data + "Refreshing..." indicator

TC6.3.5: Database recovery - resume write operations
Expected: Writes succeed, audit log shows recovery event
```

**Validation**:
- Connection pool: Health checks detect failures within 5s
- Read replica: Automatic failover for read queries
- Write degradation: Writes queued during primary outage
- Recovery: Write operations resume automatically

### Test 6.4: Orchestrator Failures
**Objective**: Validate Kubernetes automatically recovers orchestrator pods

**Test Cases**:
```
TC6.4.1: Kill 1 orchestrator pod - requests route to healthy pods
Expected: No user-visible impact, new pod starts within 30s

TC6.4.2: Kill 5 orchestrator pods simultaneously - remaining pods handle load
Expected: Latency spike <100ms, no request failures

TC6.4.3: Kill all orchestrator pods - Kubernetes restarts them
Expected: 30-60s downtime, then full recovery

TC6.4.4: Orchestrator OOM (out of memory) - pod restarted automatically
Expected: <10s disruption for requests on that pod

TC6.4.5: Network partition - orchestrator can't reach agents
Expected: Health checks fail, traffic routed to healthy zones
```

**Validation**:
- Kubernetes liveness probes: Detect failures within 10s
- Pod restart: New pod ready within 30s
- Load balancing: Traffic automatically rerouted
- No data loss: Stateless orchestrators, state in database

---

## 7. Travel Edge Case Tests

### Test 7.1: Invalid Destinations
**Objective**: Validate handling of invalid or unsupported destinations

**Test Cases**:
```
TC7.1.1: Non-existent city ("Atlantis")
Expected: "We couldn't find flights to Atlantis. Did you mean Atlanta?"

TC7.1.2: Ambiguous city ("Paris" - France or Texas?)
Expected: "Did you mean Paris, France or Paris, Texas?"

TC7.1.3: City with no airport ("Vatican City")
Expected: "Vatican City has no airport. Try Rome (30 min away)"

TC7.1.4: Unsupported country (travel restrictions)
Expected: "Travel to [country] currently restricted. Check [link] for updates"

TC7.1.5: Typo in city name ("Parus" instead of "Paris")
Expected: "Did you mean Paris?" + suggest corrections
```

**Validation**:
- Fuzzy matching: Suggest corrections for typos (Levenshtein distance <3)
- Disambiguation: Offer choices when multiple matches exist
- Helpful errors: Explain why destination invalid + suggest alternatives
- No crashes: Invalid input returns 400 Bad Request, not 500

### Test 7.2: Impossible Date Ranges
**Objective**: Validate handling of invalid date ranges

**Test Cases**:
```
TC7.2.1: Past date ("Trip to Paris on Jan 1, 2024")
Expected: "That date has passed. Did you mean Jan 1, 2026?"

TC7.2.2: Too far in future (">365 days")
Expected: "Bookings available up to 330 days in advance. Try a closer date."

TC7.2.3: Return before departure ("Return Jan 5, depart Jan 10")
Expected: "Return date must be after departure. Please check your dates."

TC7.2.4: Same-day travel (depart today, return today)
Expected: "Same-day trips not supported. Try at least 1-day stay."

TC7.2.5: Invalid date format ("Trip on 32nd January")
Expected: "Invalid date: January has only 31 days. Please correct."
```

**Validation**:
- Date parsing: Handle multiple formats (MM/DD/YYYY, DD/MM/YYYY, natural language)
- Validation: Check departure < return, both in valid range
- Helpful errors: Suggest corrections, don't just say "invalid"
- No crashes: Malformed dates return 400, not 500

### Test 7.3: API Timeout Handling
**Objective**: Validate graceful handling when external APIs timeout

**Test Cases**:
```
TC7.3.1: Amadeus API times out after 10s
Expected: "Flight search taking longer than usual. Showing hotels while we fetch flights..."

TC7.3.2: All APIs timeout (network issue)
Expected: "We're experiencing connectivity issues. Please try again in a moment."

TC7.3.3: Partial timeout (flights OK, hotels timeout)
Expected: Show flights + "Hotel search timed out. Retry?" button

TC7.3.4: Timeout recovery (retry succeeds)
Expected: Full results shown, "Retrieved [X] flights and [Y] hotels"

TC7.3.5: Repeated timeouts (circuit breaker)
Expected: "Service temporarily unavailable. Estimated recovery: 5 minutes"
```

**Validation**:
- Timeout configuration: 10s for Amadeus, 15s for Booking APIs
- Retry logic: 1 retry with exponential backoff (2s, 4s, 8s)
- Circuit breaker: Open after 5 failures, half-open after 60s
- User feedback: Show what's available + retry option

### Test 7.4: Result Synthesis Failures
**Objective**: Validate handling when result aggregation fails

**Test Cases**:
```
TC7.4.1: Agent returns malformed JSON
Expected: Log error, exclude that agent's results, show others

TC7.4.2: Agent returns HTTP 200 but empty results
Expected: Log warning, show "No [flights/hotels] found for your criteria"

TC7.4.3: Agents return conflicting data (price mismatch)
Expected: Use latest timestamp, log inconsistency for investigation

TC7.4.4: Planner fails to synthesize results (timeout)
Expected: Fall back to raw agent responses (less polished but functional)

TC7.4.5: Budget constraint impossible (no options under $50 for Paris trip)
Expected: "No options found under $50. Here are the cheapest options starting at $[X]"
```

**Validation**:
- JSON schema validation: Reject malformed responses early
- Partial results: Show what's available even if synthesis fails
- Conflict resolution: Timestamp-based, with audit trail
- Graceful degradation: Raw results better than no results

### Test 7.5: Concurrent Request Handling
**Objective**: Validate system handles concurrent requests correctly

**Test Cases**:
```
TC7.5.1: Same user, 2 concurrent requests (Paris + Tokyo)
Expected: Both complete successfully, no interference

TC7.5.2: Same user, 10 concurrent requests (spam/bot)
Expected: Rate limiter kicks in after request #5, return 429

TC7.5.3: Different users, 1000 concurrent requests
Expected: All complete within SLA, no degradation

TC7.5.4: Same destination, 100 concurrent requests (cache effectiveness)
Expected: First request hits API, next 99 hit cache, all <5s

TC7.5.5: Database write contention (2 users save same trip plan ID)
Expected: One succeeds, other gets unique ID assigned automatically
```

**Validation**:
- Load test: 1000 concurrent users, 150K requests over 10 minutes
- Latency: P95 remains <30ms during load test
- Rate limiting: Per-user limits enforced correctly
- Cache hit rate: >85% for repeated queries
- No race conditions: Database constraints prevent conflicts

---

## Test Execution Plan

### Phase 1: Smoke Tests (30 minutes)
- Run TC1.1.1, TC1.1.3, TC2.1.1, TC2.2.1, TC3.1.1, TC7.1.1
- Validate basic functionality end-to-end
- If any failures, STOP and investigate before proceeding

### Phase 2: Core Functionality (2 hours)
- Run all Test 1 (Orchestration), Test 2 (MCP), Test 3 (MAP)
- Monitor Grafana dashboards continuously
- Capture latency metrics for all test cases

### Phase 3: Security & Isolation (1 hour)
- Run all Test 4 (Permissions), Test 5 (Multi-tenant)
- Attempt cross-tenant access 1000+ times
- Validate zero data leakage

### Phase 4: Resilience (1.5 hours)
- Run all Test 6 (Failover scenarios)
- Simulate failures: kill pods, network partitions, API timeouts
- Validate recovery time <5s

### Phase 5: Edge Cases (1.5 hours)
- Run all Test 7 (Trip planner edge cases)
- Test invalid inputs, impossible scenarios, high concurrency
- Validate graceful error handling

### Phase 6: Load & Stress (2 hours)
- Sustained load: 1000 users, 150K requests over 2 hours
- Monitor: Latency (P50/P95/P99), error rate, throughput
- Validate: No degradation under load

**Total Estimated Time**: 8-9 hours (1 full working day)

---

## Success Metrics

### Performance
- ✅ Agent P95 latency: <10ms
- ✅ Orchestrator P95 latency: <30ms
- ✅ Database query P95: <15ms (PostgreSQL), <15ms (Cassandra)
- ✅ End-to-end trip query: <25s (with 3-4 concurrent agent calls)
- ✅ Throughput: 150K+ requests sustained over 2 hours

### Reliability
- ✅ Availability: 99.9% (max 5 minutes downtime in 8-hour test)
- ✅ Error rate: <0.1% for valid requests
- ✅ Recovery time: <5s from agent failure
- ✅ Circuit breaker: Opens after 5 consecutive failures

### Security
- ✅ Zero cross-tenant data leakage (1000+ attempts blocked)
- ✅ Permission enforcement: 100% coverage (every query checked)
- ✅ Audit trail: 100% of access decisions logged
- ✅ Rate limiting: Enforced correctly per tenant

### Correctness
- ✅ Valid inputs: 100% correct responses
- ✅ Invalid inputs: 100% graceful error handling (no 500 errors)
- ✅ Partial results: Shown when agents fail (no all-or-nothing)
- ✅ Data consistency: No conflicting or stale data in final results

---

## Test Automation

### Recommended Tools
- **API Testing**: Postman collections + Newman CLI
- **Load Testing**: k6 (existing load test binary can be extended)
- **Monitoring**: Prometheus queries + Grafana snapshots
- **Assertions**: Jest/Mocha for result validation
- **CI Integration**: GitHub Actions (run on every deploy)

### Test Data Management
- **Fixtures**: JSON files in `/platform/load-testing/fixtures/`
- **Mock APIs**: Wiremock for external API simulation
- **Database state**: Reset between test phases using SQL scripts

### Continuous Testing
- **Smoke tests**: Run every 15 minutes against production
- **Full suite**: Run nightly (automated, 8-hour run)
- **On-demand**: Trigger via GitHub Actions workflow

---

## Appendix: Example Test Commands

### Smoke Test (Single Trip Query)
```bash
curl -X POST https://travel-eu.getaxonflow.com/api/v1/plan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "query": "Paris 3 days trip with moderate budget",
    "travelers": 2,
    "tenant_id": "mmt-demo"
  }'
```

### Load Test (1000 concurrent users)
```bash
AXONFLOW_ENV=eu bash /Users/saurabhjain/Development/axonflow/scripts/multi-tenant/deploy-sustained-load.sh
```

### Permission Test (Cross-tenant access attempt)
```bash
# As Tenant A, try to access Tenant B resource
curl -X GET https://travel-eu.getaxonflow.com/api/v1/trips/tenant-b-trip-id \
  -H "Authorization: Bearer $TENANT_A_TOKEN"

# Expected: 403 Forbidden
```

### Failover Test (Kill Flight Agent)
```bash
kubectl delete pod -n axonflow -l app=flight-agent --force

# Monitor recovery
kubectl get pods -n axonflow -w
```

---

*Next: Execute this test plan in fresh session with full context*
