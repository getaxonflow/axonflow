# Example 2: Parallel Execution

This example demonstrates AxonFlow's Multi-Agent Planning (MAP) capability to automatically parallelize independent tasks.

## What You'll Learn

- How AxonFlow detects parallelizable tasks
- How MAP executes tasks concurrently
- How to aggregate parallel results

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Planning trip to Paris...
🔄 MAP detected 3 independent tasks - executing in parallel:
   - Search flights
   - Search hotels
   - Find local attractions
⏱️  Parallel execution completed in 2.3s (sequential would take ~6s)
📥 Results aggregated successfully
✅ Workflow completed
```

## How It Works

1. **Submit Complex Query:** "Plan a 3-day trip to Paris with flights, hotels, and attractions"
2. **MAP Planning:** AxonFlow's planning engine breaks down the query into independent sub-tasks
3. **Parallel Execution:** All 3 tasks execute simultaneously
4. **Result Aggregation:** Results are combined into a cohesive response

## Performance Comparison

| Approach | Execution Time |
|----------|----------------|
| Sequential (without MAP) | ~6 seconds |
| Parallel (with MAP) | ~2 seconds |
| **Speedup** | **3x faster** |

## Next Steps

- Try Example 3 to see conditional branching
- Modify the query to test different scenarios
- Check orchestrator logs to see the DAG execution plan
