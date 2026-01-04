# Parameterized Query Examples - Deterministic Parameter Ordering

These examples verify that parameterized queries with multiple parameters produce
deterministic results. This tests the fix for [issue #281](https://github.com/getaxonflow/axonflow-enterprise/issues/281).

## The Problem

Go map iteration order is non-deterministic. The Postgres connector's `buildArgs()`
function was iterating over a parameter map to build positional SQL arguments
(`$1`, `$2`, `$3`...), which could cause parameter mismatch bugs:

```go
// BEFORE (non-deterministic)
for _, v := range params {
    args = append(args, v)  // Order varies between runs!
}
```

## The Fix

Parameters are now sorted alphabetically by key before building the args slice:

```go
// AFTER (deterministic)
keys := make([]string, 0, len(params))
for k := range params {
    keys = append(keys, k)
}
sort.Strings(keys)  // Alphabetical order

for _, k := range keys {
    args = append(args, params[k])
}
```

## How It Works

Given parameters:
```json
{
  "zebra": "Z",
  "alpha": "A",
  "middle": "M"
}
```

After sorting keys alphabetically: `alpha`, `middle`, `zebra`

The SQL `SELECT $1, $2, $3` receives:
- `$1` = "A" (alpha)
- `$2` = "M" (middle)
- `$3` = "Z" (zebra)

## Prerequisites

Start AxonFlow:

```bash
docker compose up -d
```

## Running the Examples

### Go

```bash
cd go
go run main.go
```

### Python

```bash
cd python
pip install requests
python main.py
```

## Test Cases

| Test | Description |
|------|-------------|
| **Parameterized Query** | 3 parameters with non-alphabetical keys, verifies correct ordering |
| **Determinism** | 10 iterations with 5 parameters, ensures consistent results |
| **Single Parameter** | Edge case with one parameter |
| **Empty Parameters** | Edge case with no parameters |

## Expected Output

```
============================================================
Parameterized Query Example - Deterministic Parameter Ordering
============================================================
Agent URL: http://localhost:8080

This example verifies fix for issue #281:
  - Go map iteration is non-deterministic
  - buildArgs() now sorts keys alphabetically
  - Parameters are assigned to $1, $2, $3... in sorted order

Test 1: Parameterized query with multiple parameters...
  Keys provided: zebra, alpha, middle (non-alphabetical)
  Expected order after sorting: alpha, middle, zebra
  Result: first_param=A, second_param=M, third_param=Z
  SUCCESS: Parameters in correct alphabetical key order!

Test 2: Determinism test (10 iterations)...
  SUCCESS: All 10 iterations produced consistent results!

Test 3: Single parameter query...
  SUCCESS: Single parameter worked! value=SINGLE

Test 4: Query with no parameters...
  SUCCESS: Empty params query worked! result=no params

============================================================
All parameterized query tests PASSED!
============================================================
```

## API Endpoint

These examples use the Agent's MCP query endpoint directly:

```
POST http://localhost:8080/mcp/resources/query
Content-Type: application/json
X-Tenant-ID: default

{
  "connector": "axonflow_rds",
  "statement": "SELECT $1::text as value",
  "parameters": {"key": "value"}
}
```

## Troubleshooting

**"Connection refused"**: AxonFlow is not running. Run `docker compose up -d`.

**"Connector not found"**: The postgres connector is not configured. Ensure
`DATABASE_URL` environment variable is set in docker-compose.

**Parameters in wrong order**: The fix for #281 is not applied. Update to latest version.
