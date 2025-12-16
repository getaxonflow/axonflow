# With AxonFlow - Policies, audit, rate limits automatic
response = await ax.execute_query(
    user_token="demo-user",
    query="Explain AI governance in one sentence",
    request_type="chat",
)
print(f"Checks: {response.policy_info['static_checks']}")  # Audit trail
