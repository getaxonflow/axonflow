# Multi-Agent Planning (MAP) — Rust

Generates a plan, prints the steps, then executes it through AxonFlow's MAP orchestration.

## Run

```bash
cargo run
```

The community stack will return a plan but may not fully execute it without LLM provider credentials configured on the orchestrator. That's expected — the SDK paths (`generate_plan` → `execute_plan` → `get_plan_status`) are exercised regardless.
