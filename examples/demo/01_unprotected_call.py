"""
Unprotected AI Call - The Problem

Most AI apps send user input directly to an LLM.
No checks, no rate limits, no audit trail.
"""

import openai

# Direct call to LLM - no governance
user_input = "What's the weather in London?"

response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}]
    # No policy checks
    # No PII detection
    # No audit trail
    # No rate limiting
)

print(response.choices[0].message.content)
