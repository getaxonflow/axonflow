# AxonFlow Rust SDK — Quick Start Guide

**Last Updated:** September 2026

**SDK Status:** Preview (v0.10.0) | **Platform Version:** v10.4.0

> The Rust SDK is in **preview**. v0.10.0 covers a subset of the surface available in the established Go / Python / TypeScript / Java SDKs — see [SDK Feature Coverage](../SDK_FEATURE_COVERAGE.md) for the full matrix. Track upcoming work on the [Rust SDK issues](https://github.com/getaxonflow/axonflow-sdk-rust/issues) page.

---

## Prerequisites

- **Rust 1.78+** (stable toolchain via [rustup](https://rustup.rs/))
- An AxonFlow Agent running (locally via Docker, or a remote deployment)
- Your `client_id` and `client_secret` credentials (for enterprise deployments — community deployments work without)

## 1. Add the SDK to your project

```toml
# Cargo.toml
[dependencies]
axonflow-sdk-rust = "0.10.0"
tokio = { version = "1", features = ["full"] }
```

## 2. Configure the Client

The Rust SDK speaks **HTTP Basic auth**. With no credentials configured, the SDK defaults to `Basic base64("community:")` so it works out-of-the-box against a self-hosted community deployment. With credentials, it sends `Basic base64("client_id:client_secret")`.

```rust
use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AxonFlowConfig::new("http://localhost:8080")
        .with_auth(
            std::env::var("AXONFLOW_CLIENT_ID")?,
            std::env::var("AXONFLOW_CLIENT_SECRET")?,
        );
    let client = AxonFlowClient::new(config)?;

    // ... use the client ...
    Ok(())
}
```

For **community / self-hosted** deployments without credentials:

```rust
let client = AxonFlowClient::new(AxonFlowConfig::new("http://localhost:8080"))?;
```

For **enterprise deployments** with a license key:

```rust
let config = AxonFlowConfig::new("https://your-enterprise-host")
    .with_auth("client-id", "client-secret")
    .with_license_key(std::env::var("AXONFLOW_LICENSE_KEY")?);
```

## 3. Choose an Integration Mode

### Proxy Mode (recommended for new projects)

AxonFlow handles policy enforcement and forwards to the configured LLM provider. Your code only talks to AxonFlow.

```rust
use std::collections::HashMap;

let mut context = HashMap::new();
context.insert("temperature".to_string(), serde_json::json!(0.7));

let response = client
    .proxy_llm_call(
        "user-123",                         // user_token
        "Summarize Q4 revenue",             // query
        "chat",                             // request_type
        context,                            // context
    )
    .await?;

if response.blocked {
    println!("Blocked by policy: {}", response.block_reason.unwrap_or_default());
} else {
    println!("Result: {:?}", response.data);
}
```

### Invisible Governance via the OpenAI Interceptor

If you already have an OpenAI-compatible client, wrap it. AxonFlow runs a policy pre-check before each call, blocks if policy violations are detected, and audits asynchronously after the response.

```rust
use axonflow_sdk_rust::interceptors::openai::{
    ChatCompletionRequest, ChatMessage, OpenAIChatCompleter, WrappedOpenAIClient,
};

// Implement OpenAIChatCompleter for your existing client...
let governed = WrappedOpenAIClient::new(my_openai_client, axonflow_client, "user-123");

let response = governed
    .create_chat_completion(ChatCompletionRequest {
        model: "gpt-4".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Hello".to_string(),
        }],
        ..Default::default()
    })
    .await?;
```

### Gateway Mode (audit-only)

If you call your LLM provider directly and only want to log calls for compliance:

```rust
use axonflow_sdk_rust::{AuditRequest, TokenUsage};

client
    .audit_llm_call(&AuditRequest {
        context_id: "request-id-from-your-llm".to_string(),
        response_summary: "Summary of the response".to_string(),
        provider: "openai".to_string(),
        model: "gpt-4".to_string(),
        token_usage: TokenUsage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        },
        latency_ms: 250,
        metadata: None,
    })
    .await?;
```

## 4. Multi-Agent Planning (MAP)

```rust
let plan = client
    .generate_plan("Plan a 3-day trip to Paris", "travel", None)
    .await?;
println!("Plan {} has {} steps", plan.plan_id, plan.steps.len());

let execution = client.execute_plan(&plan.plan_id, None).await?;
println!("Execution status: {}", execution.status);

let status = client.get_plan_status(&plan.plan_id).await?;
let _ = client.cancel_plan(&plan.plan_id, Some("user_cancelled")).await?;
```

## 5. MCP Connectors

```rust
let connectors = client.list_connectors().await?;
for conn in &connectors {
    println!("{} ({}) — installed: {}", conn.name, conn.r#type, conn.installed);
}
```

## 6. Configuration knobs

```rust
use std::time::Duration;
use axonflow_sdk_rust::{AxonFlowConfig, RetryConfig, CacheConfig, Mode};

let config = AxonFlowConfig::new("http://localhost:8080")
    .with_auth("client-id", "client-secret")
    .with_mode(Mode::Production)                     // Production = fail-open on 5xx; Sandbox = propagate
    .with_timeout(Duration::from_secs(30))           // for non-MAP requests
    .with_map_timeout(Duration::from_secs(120))      // for plan generation/execution
    .with_retry(RetryConfig {
        enabled: true,
        max_attempts: 3,
        initial_delay: Duration::from_secs(1),
    })
    .with_cache(CacheConfig {
        enabled: true,
        ttl: Duration::from_secs(60),
    });
```

## 7. Telemetry opt-out

The SDK sends an anonymous heartbeat at most once per machine every 7 days for licensing compliance and platform health. To disable:

```bash
export AXONFLOW_TELEMETRY=off
```

**Scope:** `AXONFLOW_TELEMETRY=off` disables the heartbeat described above. On self-hosted and in-VPC deployments, that heartbeat is the only data the SDK sends to AxonFlow. On Community SaaS (`try.getaxonflow.com`) the hosted service also processes operational data (registrations, audit logs, policy enforcement records, workflow state, plan data, request-header metadata aggregated for usage analytics) as part of running the platform; that flow is governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by `AXONFLOW_TELEMETRY`.

`DO_NOT_TRACK` is intentionally **not** honored — it's commonly inherited from a parent shell, and we want telemetry opt-out to be an explicit AxonFlow decision.

---

## Error handling

```rust
use axonflow_sdk_rust::AxonFlowError;

match client.list_connectors().await {
    Ok(connectors) => println!("Found {} connectors", connectors.len()),
    Err(AxonFlowError::ApiError { status: 403, message }) => {
        eprintln!("Policy violation: {}", message);
    }
    Err(AxonFlowError::ApiError { status: 429, .. }) => {
        eprintln!("Rate limited; back off and retry");
    }
    Err(AxonFlowError::Unavailable(_)) => {
        eprintln!("Platform unavailable (Production mode would fail-open here)");
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

---

## What's not in v0.10.0 yet

The Rust SDK is being filled out incrementally. v0.10.0 carries the v0.5.0 foundation (auth, proxy, audit, basic MAP, basic MCP, OpenAI + Anthropic interceptors, `X-Client-ID` outbound header, `create_hitl_request`, Indonesia PII category, cross-border audit fields) plus the v0.7.0 Decision Mode PEP (`decide` → `fulfill_request` → forward with engine-only, fail-closed redaction) and the v0.8.x performance/reliability pass (bounded LRU response cache, connection pooling), plus the v0.9.0 AuthZEN-native decide surface (generated wire types, typed refusals with an explicit retryable set) and the v0.10.0 telemetry-parity pass (the heartbeat relays `platform_version`, `license_tier`, `edition` and `platform_deployment_mode` from the platform's own `/health`, and `register_adapter` declares a framework integration). Coming in subsequent releases:

- **Universal surface:** `health_check`, `execute_query`, `get_policy_approved_context`, full MAP (resume / rollback / versions / update), `mcp_check_input` / `mcp_check_output`, `retry_context` / `idempotency_key` wire fields.
- **Interceptors:** Gemini / Bedrock / Ollama (currently OpenAI + Anthropic).
- **Governance:** policies (CRUD + simulation), decisions, HITL queue, audit search, code/media governance.
- **Workflows + executions, cost / budgets / circuit breaker, MASFEAT compliance, webhooks.**

Track upcoming work on the [Rust SDK issues](https://github.com/getaxonflow/axonflow-sdk-rust/issues) page.

---

## Repository

- **GitHub:** https://github.com/getaxonflow/axonflow-sdk-rust
- **crates.io:** `axonflow-sdk-rust`
- **docs.rs:** https://docs.rs/axonflow-sdk-rust
- **License:** MIT
