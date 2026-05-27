# AxonFlow SDK Documentation

**Last Updated:** May 2026

**SDK Versions:** v8.3.0 (Go / Python / TypeScript / Java) — v0.5.0 preview (Rust) | **Platform Version:** v9.0.0

AxonFlow provides official SDKs in five languages for integrating LLM governance into your applications. The four established SDKs (Go / Python / TypeScript / Java) offer identical feature coverage; the Rust SDK is in preview with a Phase-0 baseline (auth + proxy + audit + basic MAP + basic MCP) — see [SDK Feature Coverage](../SDK_FEATURE_COVERAGE.md) for the full matrix.

All SDKs follow the same API design principles: type-safe clients, automatic retries, and structured error handling.

---

## SDK Repositories

| SDK | Repository | Install |
|-----|-----------|---------|
| **Go** | [github.com/getaxonflow/axonflow-sdk-go](https://github.com/getaxonflow/axonflow-sdk-go) | `go get github.com/getaxonflow/axonflow-sdk-go/v8` |
| **Python** | [github.com/getaxonflow/axonflow-sdk-python](https://github.com/getaxonflow/axonflow-sdk-python) | `pip install axonflow` |
| **TypeScript** | [github.com/getaxonflow/axonflow-sdk-typescript](https://github.com/getaxonflow/axonflow-sdk-typescript) | `npm install @axonflow/sdk` |
| **Java** | [github.com/getaxonflow/axonflow-sdk-java](https://github.com/getaxonflow/axonflow-sdk-java) | See [Maven Central](#java) |
| **Rust** _(preview)_ | [github.com/getaxonflow/axonflow-sdk-rust](https://github.com/getaxonflow/axonflow-sdk-rust) | `cargo add axonflow-sdk-rust` |

---

## Quick Start

### Go

```bash
go get github.com/getaxonflow/axonflow-sdk-go/v8
```

```go
package main

import (
    "context"
    "fmt"
    axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
    client := axonflow.NewClient(axonflow.AxonFlowConfig{
        Endpoint:     "http://localhost:8080",
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
    })

    response, err := client.ProxyLLMCall(
        "user-token",
        "Summarize Q4 revenue",
        "chat",
        nil,
    )
    if err != nil {
        panic(err)
    }
    fmt.Println(response)
}
```

### Python

```bash
pip install axonflow
```

```python
from axonflow import AxonFlow

client = AxonFlow(
    endpoint="http://localhost:8080",
    client_id="your-client-id",
    client_secret="your-client-secret",
)

response = client.proxy_llm_call(
    user_token="user-token",
    query="Summarize Q4 revenue",
    request_type="chat",
)
print(response)
```

### TypeScript

```bash
npm install @axonflow/sdk
```

```typescript
import { AxonFlow } from "@axonflow/sdk";

const client = new AxonFlow({
    endpoint: "http://localhost:8080",
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
});

const response = await client.proxyLLMCall({
    userToken: "user-token",
    query: "Summarize Q4 revenue",
    requestType: "chat",
});
console.log(response);
```

### Java

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.getaxonflow</groupId>
    <artifactId>axonflow-sdk</artifactId>
    <version>8.3.0</version>
</dependency>
```

```java
import com.getaxonflow.sdk.AxonFlowClient;

AxonFlowClient client = AxonFlowClient.builder()
    .endpoint("http://localhost:8080")
    .clientId("your-client-id")
    .clientSecret("your-client-secret")
    .build();

var response = client.proxyLlmCall(
    "user-token",
    "Summarize Q4 revenue",
    "chat",
    null
);
System.out.println(response);
```

### Rust _(preview, v0.5.0)_

```toml
# Cargo.toml
[dependencies]
axonflow-sdk-rust = "0.5"
tokio = { version = "1", features = ["full"] }
```

```rust
use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AxonFlowConfig::new("http://localhost:8080")
        .with_auth("your-client-id", "your-client-secret");
    let client = AxonFlowClient::new(config)?;

    let response = client
        .proxy_llm_call("user-token", "Summarize Q4 revenue", "chat", HashMap::new())
        .await?;
    println!("{:?}", response);
    Ok(())
}
```

---

## SDK Documentation

| Document | Description |
|----------|-------------|
| [TypeScript Architecture](./typescript-architecture.md) | TypeScript SDK architecture and design |
| [TypeScript Specification](./typescript-specification.md) | TypeScript SDK technical specification |
| [TypeScript Quick Start](./typescript-quickstart.md) | Quick start guide for TypeScript SDK |
| [Rust Quick Start](./rust-quickstart.md) | Quick start guide for the (preview) Rust SDK |
| [LLM SDK Guide](./llm-sdk-guide.md) | Using LLM providers with the SDK |
| [SDK Feature Coverage](../SDK_FEATURE_COVERAGE.md) | Full method coverage matrix across all SDKs |

## Related Documentation

- [SDK Feature Coverage](../SDK_FEATURE_COVERAGE.md) -- Method coverage and feature matrix
- [Gateway Mode Migration](../guides/gateway-mode.md) -- Migrating to Gateway Mode SDK
- [Cost Controls](../governance/cost-controls.md) -- Budget management via SDK and HTTP API
