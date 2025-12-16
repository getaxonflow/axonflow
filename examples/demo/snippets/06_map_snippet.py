# Multi-Agent Planning - Natural language to governed workflow
plan = await ax.generate_plan(query="Book flight and build itinerary")
result = await ax.execute_plan(plan.plan_id)
print(f"Workflow ID: {result.workflow_execution_id}")  # Per-step audit
