use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent_url =
        std::env::var("AXONFLOW_AGENT_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let mut config = AxonFlowConfig::new(agent_url);
    if let (Ok(id), Ok(secret)) = (
        std::env::var("AXONFLOW_CLIENT_ID"),
        std::env::var("AXONFLOW_CLIENT_SECRET"),
    ) {
        config = config.with_auth(id, secret);
    }
    let client = AxonFlowClient::new(config)?;

    println!("=== List available connectors ===");
    let connectors = client.list_connectors().await?;
    for (i, conn) in connectors.iter().enumerate() {
        println!(
            "{}. {} ({}) — installed: {}",
            i + 1,
            conn.name,
            conn.r#type,
            conn.installed
        );
    }

    println!("\n=== Query a connector (mcp-query through proxy) ===");
    // The community stack ships a Postgres connector; queries are dispatched
    // through the proxy with request_type="mcp-query" so the agent enforces
    // policy before reaching the connector.
    let mut params = HashMap::new();
    params.insert("statement".to_string(), serde_json::json!("SELECT 1"));

    match client
        .query_connector("user-123", "postgres", "List one row", params)
        .await
    {
        Ok(resp) => {
            if resp.success {
                println!("Connector data: {:?}", resp.data);
            } else {
                println!(
                    "Connector returned error: {}",
                    resp.error.unwrap_or_default()
                );
            }
        }
        Err(e) => println!("Query failed: {}", e),
    }

    Ok(())
}
