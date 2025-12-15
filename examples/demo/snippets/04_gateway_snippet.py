# Gateway Mode - Your LLM, AxonFlow governance
ctx = await ax.get_policy_approved_context(query="Explain AI governance in one sentence")
response = openai.chat.completions.create(...)  # Your API key
await ax.audit_llm_call(context_id=ctx.context_id, ...)
