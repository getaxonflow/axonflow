# Gateway Mode - LangChain + AxonFlow (works with any LLM client: CrewAI, OpenAI SDK, etc.)
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4")
ctx = await ax.get_policy_approved_context(query="Explain AI governance")
response = llm.invoke([HumanMessage(content=query)])  # Your LangChain call
audit = await ax.audit_llm_call(context_id=ctx.context_id, ...)
print(f"Audit ID: {audit.audit_id}")  # Full audit trail
