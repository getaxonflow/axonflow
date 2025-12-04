# Example 4: Travel Booking with Fallbacks

This example demonstrates robust error handling with multiple fallback mechanisms for real-world travel booking scenarios.

## What You'll Learn

- How to implement multi-level fallback strategies
- How to handle API failures gracefully
- How to provide alternative options when primary choices fail

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Step 1: Searching for direct flights...
⚠️  Direct flights sold out
📤 Step 2: Trying connecting flights...
✅ Found connecting flight option
📤 Step 3: Searching for hotels...
⚠️  Preferred hotel unavailable
📤 Step 4: Trying alternative hotels...
✅ Found alternative hotel
✅ Complete itinerary created with fallbacks
📥 Final Itinerary: [details]
```

## How It Works

1. **Primary Strategy:** Try direct flights + 5-star hotels
2. **Fallback Level 1:** If primary fails → Try connecting flights + 4-star hotels
3. **Fallback Level 2:** If level 1 fails → Try any flights + 3-star hotels
4. **Fallback Level 3:** If all fail → Provide manual booking suggestions

**Fallback Chain:**
```
Direct Flight → Connecting Flight → Multi-Stop Flight → Manual Booking
5-Star Hotel → 4-Star Hotel → 3-Star Hotel → Alternative Dates
```

## Key Concepts

**Resilient Workflows:**
- Always have a backup plan
- Fail gracefully with useful alternatives
- Never leave user with "no results"

**Real-World Scenarios:**
- Sold-out flights during peak season
- Fully booked hotels for events
- Price surges (fallback to budget options)
- API rate limits (fallback to cached data)

## Next Steps

- Try Example 5 to see data pipeline patterns
- Modify fallback priorities (price vs time vs comfort)
- Add timeout handling for slow APIs
