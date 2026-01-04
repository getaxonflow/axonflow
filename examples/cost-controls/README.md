# Cost Controls Examples

This directory contains comprehensive examples demonstrating ALL AxonFlow Cost Controls SDK methods and HTTP API endpoints.

## Coverage

Each SDK example and the HTTP example tests **all 12 operations**:

| # | Operation | SDK Method | HTTP Endpoint |
|---|-----------|------------|---------------|
| 1 | Create Budget | `createBudget()` | `POST /api/v1/budgets` |
| 2 | Get Budget | `getBudget()` | `GET /api/v1/budgets/{id}` |
| 3 | List Budgets | `listBudgets()` | `GET /api/v1/budgets` |
| 4 | Update Budget | `updateBudget()` | `PUT /api/v1/budgets/{id}` |
| 5 | Get Budget Status | `getBudgetStatus()` | `GET /api/v1/budgets/{id}/status` |
| 6 | Get Budget Alerts | `getBudgetAlerts()` | `GET /api/v1/budgets/{id}/alerts` |
| 7 | Check Budget | `checkBudget()` | `POST /api/v1/budgets/check` |
| 8 | Get Usage Summary | `getUsageSummary()` | `GET /api/v1/usage` |
| 9 | Get Usage Breakdown | `getUsageBreakdown()` | `GET /api/v1/usage/breakdown` |
| 10 | List Usage Records | `listUsageRecords()` | `GET /api/v1/usage/records` |
| 11 | Get Pricing | `getPricing()` | `GET /api/v1/pricing` |
| 12 | Delete Budget | `deleteBudget()` | `DELETE /api/v1/budgets/{id}` |

## Prerequisites

1. AxonFlow Agent running at `http://localhost:8080`
2. AxonFlow Orchestrator running at `http://localhost:8081`
3. The orchestrator must have Cost Controls enabled

## Running Examples

### Go (SDK)

```bash
cd go
go mod download
go run main.go
```

For local SDK development:
```bash
# Uncomment the replace directive in go.mod
go run main.go
```

### Python (SDK)

```bash
cd python
pip install -r requirements.txt
python main.py
```

For local SDK development:
```bash
pip install -e /path/to/axonflow-sdk-python
python main.py
```

### TypeScript (SDK)

```bash
cd typescript
npm install
npm start
```

For local SDK development:
```bash
# In SDK repo: npm link
# In example: npm link @axonflow/sdk
npm start
```

### Java (SDK)

```bash
cd java
mvn compile exec:java
```

For local SDK development:
```bash
# In SDK repo: mvn install -DskipTests
mvn compile exec:java
```

### HTTP (curl)

```bash
cd http
chmod +x cost-controls.sh
./cost-controls.sh
```

## SDK Versions

| SDK | Version | Package |
|-----|---------|---------|
| Go | v1.15.0+ | `github.com/getaxonflow/axonflow-sdk-go` |
| Python | 0.11.0+ | `axonflow` |
| TypeScript | 1.11.1+ | `@axonflow/sdk` |
| Java | 1.10.0+ | `com.getaxonflow:axonflow-sdk` |

## Budget Configuration

Budgets can be configured with:

- **Scope**: `organization`, `team`, `agent`, `workflow`, or `user`
- **Period**: `daily`, `weekly`, `monthly`, `quarterly`, or `yearly`
- **On Exceed**: `warn`, `block`, or `downgrade`
- **Alert Thresholds**: Array of percentages (e.g., `[50, 80, 100]`)

## Example Output

```
AxonFlow Cost Controls - Go SDK (Comprehensive)
================================================

1. createBudget - Creating a monthly budget...
   Created: demo-budget-go-1735900000 (limit: $100.00/month)

2. getBudget - Retrieving budget by ID...
   Retrieved: demo-budget-go-1735900000 (scope: organization, period: monthly)

3. listBudgets - Listing all budgets...
   Found 1 budgets (total: 1)
   - demo-budget-go-1735900000: $100.00/monthly

4. updateBudget - Updating budget limit...
   Updated: demo-budget-go-1735900000 (new limit: $150.00)

5. getBudgetStatus - Checking current budget status...
   Used: $0.00 / $150.00 (0.0%)
   Remaining: $150.00
   Exceeded: false, Blocked: false

...

================================================
All 12 Cost Control methods tested!
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | Agent URL |
| `AXONFLOW_ORCHESTRATOR_URL` | `http://localhost:8081` | Orchestrator URL |

## Related Documentation

- [Cost Controls Guide](https://docs.getaxonflow.com/governance/cost-controls)
- [API Reference](https://docs.getaxonflow.com/api/orchestrator-api)
