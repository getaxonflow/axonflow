# Example 9: Financial Report Generation

This example demonstrates automated financial report generation with data aggregation and analysis.

## What You'll Learn

- How to aggregate financial data from multiple sources
- How to generate formatted reports
- How to calculate financial metrics and trends

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
📤 Fetching Q4 2024 financial data...
✅ Data retrieved from 3 sources
📤 Calculating key metrics...
✅ Metrics calculated: Revenue $2.4M, Expenses $1.8M, Profit $600K
📤 Analyzing trends...
✅ YoY growth: +15%, QoQ growth: +8%
📤 Generating executive report...
✅ Report generated successfully
```

## How It Works

1. **Data Collection:** Fetch from accounting systems, CRM, payment processors
2. **Data Validation:** Check for completeness and accuracy
3. **Metric Calculation:** Revenue, expenses, profit, margins, growth rates
4. **Trend Analysis:** Compare periods, identify patterns
5. **Report Generation:** Format for executives with visualizations
6. **Distribution:** Email to stakeholders with access controls

## Key Concepts

**Financial Analytics:**
- Multi-source data aggregation
- Time-series analysis
- Variance analysis (actual vs budget)
- Key performance indicators (KPIs)

## Next Steps

- Try Example 10 for chatbot workflows
- Add budget vs actual comparisons
- Implement forecast projections
