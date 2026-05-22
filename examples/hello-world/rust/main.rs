use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent_url =
        std::env::var("AXONFLOW_AGENT_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Community deployments work without credentials — the SDK defaults to
    // Basic auth with the community tenant. For enterprise, set
    // AXONFLOW_CLIENT_ID + AXONFLOW_CLIENT_SECRET.
    let mut config = AxonFlowConfig::new(agent_url);
    if let (Ok(id), Ok(secret)) = (
        std::env::var("AXONFLOW_CLIENT_ID"),
        std::env::var("AXONFLOW_CLIENT_SECRET"),
    ) {
        config = config.with_auth(id, secret);
    }
    let client = AxonFlowClient::new(config)?;

    // First positional arg to proxy_llm_call is the user token. In enterprise
    // mode the platform validates it as a JWT (see ee/platform/agent auth path).
    // In community / community-saas mode any string works. Read from env to
    // match the convention used by the Go/Python/TS/Java hello-world examples.
    let user_token =
        std::env::var("AXONFLOW_USER_TOKEN").unwrap_or_else(|_| "hello-world-user".to_string());

    println!("Sending governed query…");
    let resp = client
        .proxy_llm_call(
            &user_token,
            "What is the capital of France?",
            "chat",
            HashMap::new(),
        )
        .await?;

    if resp.blocked {
        println!(
            "Blocked by governance: {}",
            resp.block_reason.unwrap_or_default()
        );
    } else if resp.success {
        println!("Result: {:?}", resp.data);
    } else {
        println!("Error: {}", resp.error.unwrap_or_default());
    }

    Ok(())
}
