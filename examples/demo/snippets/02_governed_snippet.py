import os

# With AxonFlow - Policies, audit, rate limits automatic
response = await ax.proxy_llm_call(
    user_token=os.getenv("AXONFLOW_USER_TOKEN", "demo-user"),
    query="Explain AI governance in one sentence",
    request_type="chat",
)
print(f"Checks: {response.policy_info['static_checks']}")  # Audit trail
