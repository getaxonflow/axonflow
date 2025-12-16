# Gateway Mode - Any LLM client (LangChain, CrewAI, etc.)
ctx = await ax.get_policy_approved_context(query="Explain AI governance")
response = llm.invoke([HumanMessage(content=query)])  # Your LangChain call
audit = await ax.audit_llm_call(context_id=ctx.context_id, ...)
print(f"Audit ID: {audit.audit_id}")  # Logged with tokens & latency
