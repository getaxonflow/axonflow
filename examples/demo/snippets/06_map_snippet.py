# Multi-Agent Planning - Natural language to governed workflow
plan = await ax.generate_plan(
    query="Research renewable energy and create a summary report",
    domain="generic",
)
result = await ax.execute_plan(plan.plan_id)
print(f"Steps: {len(plan.steps)}")  # Workflow with governance at every step
