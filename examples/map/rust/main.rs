use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};

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

    println!("=== Generate a multi-agent plan ===");
    let plan = client
        .generate_plan(
            "Plan a 3-day business trip to Paris with two meetings at La Défense",
            "travel",
            None,
        )
        .await?;

    println!(
        "Plan {} ({} steps, complexity {})",
        plan.plan_id,
        plan.steps.len(),
        plan.complexity
    );
    for step in &plan.steps {
        println!("  - {} ({})", step.name, step.r#type);
    }

    println!("\n=== Execute the plan ===");
    let exec = client.execute_plan(&plan.plan_id, None).await?;
    println!("Status: {} (took {})", exec.status, exec.duration);
    if let Some(err) = exec.error {
        println!("Execution error: {}", err);
    }

    Ok(())
}
