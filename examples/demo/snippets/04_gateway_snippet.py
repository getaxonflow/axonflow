# Gateway Mode - Any LLM client, AxonFlow governance
ctx = await ax.get_policy_approved_context(query="Explain AI governance")
response = openai.chat.completions.create(...)  # Your LLM call
audit = await ax.audit_llm_call(context_id=ctx.context_id, ...)
print(f"Audit ID: {audit.audit_id}")  # Logged with tokens & latency
