# Unprotected - Direct LLM call, no governance
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}]
)
