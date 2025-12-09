# Example 10: Chatbot with Conversation Memory

This example demonstrates building a stateful chatbot that maintains conversation context across multiple turns.

## What You'll Learn

- How to maintain conversation state
- How to reference previous messages
- How to build context-aware responses

## Running

```bash
cp .env.example .env
# Add your API key to .env
go run main.go
```

## Expected Output

```
✅ Connected to AxonFlow
💬 Chatbot initialized with memory
👤 User: My name is Alice
🤖 Bot: Nice to meet you, Alice!
👤 User: What's the weather like?
🤖 Bot: I can help you check the weather, Alice. Where are you located?
👤 User: Remember my favorite color is blue
🤖 Bot: Got it, Alice! I'll remember that your favorite color is blue.
👤 User: What did I just tell you?
🤖 Bot: You told me your favorite color is blue, Alice.
```

## How It Works

1. **Initialize Memory:** Create conversation context storage
2. **User Input:** Receive message from user
3. **Context Retrieval:** Load relevant previous messages
4. **Generate Response:** LLM considers full conversation history
5. **Update Memory:** Store new exchange for future turns
6. **Repeat:** Continue conversation loop

**Memory Structure:**
```
{
  "user_id": "alice123",
  "conversation": [
    {"role": "user", "content": "My name is Alice"},
    {"role": "assistant", "content": "Nice to meet you, Alice!"},
    ...
  ],
  "facts": {
    "name": "Alice",
    "favorite_color": "blue"
  }
}
```

## Key Concepts

**Stateful Conversations:**
- Conversation history tracking
- Entity extraction (names, preferences)
- Context window management
- Personalization

**Use Cases:**
- Customer support chatbots
- Personal assistants
- Interactive tutorials
- Conversational forms

## Next Steps

- Add long-term memory (database storage)
- Implement memory summarization (compress old messages)
- Add multi-user support (separate contexts)
