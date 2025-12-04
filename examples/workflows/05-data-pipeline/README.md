# Example 5: Data Pipeline

This example demonstrates building a multi-stage data processing pipeline with AxonFlow.

## What You'll Learn

- How to chain multiple processing steps
- How to transform data between stages
- How to validate data at each pipeline stage

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Stage 1: Extracting data from sources...
✅ Extracted 1,000 records
📤 Stage 2: Cleaning and normalizing data...
✅ Cleaned 995 records (5 invalid removed)
📤 Stage 3: Enriching with external data...
✅ Enriched 995 records
📤 Stage 4: Aggregating and analyzing...
✅ Analysis complete
📥 Pipeline Results: [summary statistics]
```

## How It Works

1. **Extract:** Pull data from multiple sources (APIs, databases, files)
2. **Transform:** Clean, normalize, and standardize data formats
3. **Enrich:** Add external data (geocoding, pricing, categories)
4. **Load:** Aggregate and store results
5. **Analyze:** Generate insights and reports

**Pipeline Stages:**
```
Raw Data → Cleaned Data → Enriched Data → Aggregated Results → Insights
```

## Key Concepts

**Data Processing:**
- Multi-stage transformation
- Error handling at each stage
- Data validation and quality checks
- Progress tracking

**Real-World Use Cases:**
- ETL (Extract, Transform, Load) workflows
- Data warehousing
- Report generation
- Machine learning preprocessing

## Next Steps

- Try Example 6 to see approval workflows
- Add error recovery (retry failed records)
- Implement partial pipeline execution
