# Example 3: Conditional Logic

This example demonstrates how to implement conditional branching based on data returned from API calls.

## What You'll Learn

- How to branch workflows based on API responses
- How to handle different scenarios (success/fallback)
- How to validate data before proceeding

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Searching for flights to Paris...
✅ Found 5 flight options
💡 Best option: $450 non-stop flight
📤 Booking flight...
✅ Booking successful!
✅ Workflow completed
```

## How It Works

1. **Query Flight API:** Search for flights from New York to Paris
2. **Check Results:** If flights found → proceed to booking, else → show error
3. **Conditional Branch:**
   - **Success Path:** Book the cheapest flight
   - **Fallback Path:** Suggest alternative dates
4. **Confirmation:** Display booking confirmation or error message

## Key Concepts

**Conditional Execution:**
- Check API response for data availability
- Branch based on conditions (price, availability, etc.)
- Handle both success and error paths

**Data Validation:**
- Verify flight results exist before booking
- Check price thresholds
- Validate booking confirmation

## Next Steps

- Try Example 4 to see fallback mechanisms
- Modify the query to test different scenarios (no flights available)
- Add more conditional branches (budget constraints, preferred airlines)
