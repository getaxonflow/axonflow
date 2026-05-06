# Interceptors (Invisible Governance) — Rust

Wraps an OpenAI-compatible client with `WrappedOpenAIClient` so AxonFlow runs a policy pre-check before each chat completion, blocks on policy violations, and asynchronously audits the call after the response.

## Run

```bash
cargo run
```

The example uses a mock OpenAI client so no real LLM credentials are needed. In a real app, swap `MockOpenAIClient` for your `async-openai` (or equivalent) client implementation.
