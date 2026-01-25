# Budget Enforcement Examples

These examples test that budget limits **actually block requests**, not just track usage.

## The Problem (Issue #1082)

Previous cost-controls examples only tested that:
- Budget API returns 200 OK
- Budget fields are present in responses

They did **NOT** verify:
- Requests are actually blocked when budget is exceeded
- HTTP 402 Payment Required is returned
- BudgetInfo is included in blocked responses

## What These Examples Test

1. Create a budget with `on_exceed: "block"` and a low limit ($0.01)
2. Make LLM requests using `ProxyLLMCall` (not deprecated `executeQuery`)
3. Verify that when budget is exceeded:
   - Request returns HTTP 402 Payment Required
   - Response includes `budget_info` with:
     - `exceeded: true`
     - `percentage >= 100`
     - `action: "block"`
4. Verify `GetBudgetStatus` confirms `is_blocked: true`

## Prerequisites

- AxonFlow Agent running on localhost:8080
- OpenAI or Anthropic API key configured in AxonFlow

## Running the Examples

### Go

```bash
cd go
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

### HTTP (curl)

```bash
cd http
chmod +x test-enforcement.sh
./test-enforcement.sh
```

## Expected Output

```
AxonFlow Budget Enforcement Test (Issue #1082)
====================================================

Step 1: Create a budget with on_exceed=block
--------------------------------------------
   Created budget: enforcement-test-xxx (limit: $0.01, action: block)

Step 2: Make LLM requests until blocked
----------------------------------------
   Request 1: OK (tokens used)
   Request 2: BLOCKED (budget exceeded) ✓

Step 3: Verify enforcement
---------------------------
   [PASS] Request was blocked when budget exceeded
   [PASS] BudgetInfo is included in blocked response
   [PASS] BudgetInfo.exceeded is true
   [PASS] BudgetInfo.percentage is 150.0% (>= 100%)
   [PASS] BudgetInfo.action is 'block'
   [PASS] GetBudgetStatus confirms is_blocked=true

====================================================
Results: 6 PASS, 0 FAIL
Budget enforcement is working correctly!
```

## What Happens If Enforcement Fails

If budget enforcement is not properly wired:

```
Step 2: Make LLM requests until blocked
----------------------------------------
   Request 1: OK (tokens used)
   Request 2: OK (tokens used)
   ... (requests continue without blocking)
   Request 10: OK (tokens used)

Step 3: Verify enforcement
---------------------------
   [FAIL] Request was NOT blocked - budget enforcement not working!
```

This indicates a wiring gap - the `CheckBudget()` function exists but is not being called in the request path.

## Implementation Notes

- These examples use `ProxyLLMCall` (not deprecated `executeQuery`)
- Budget enforcement was wired in Issue #1082
- The Agent calls `CheckBudget()` in `handlePolicyPreCheck` before processing requests
- When `on_exceed: "block"` and budget is exceeded, returns HTTP 402 with `BudgetInfo`
