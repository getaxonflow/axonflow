# Gateway Mode - Your LLM, AxonFlow governance
ctx = await ax.get_policy_approved_context(query=user_input)
response = openai.chat.completions.create(...)  # Your API key
await ax.audit_llm_call(context_id=ctx.context_id, ...)
