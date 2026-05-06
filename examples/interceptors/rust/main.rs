use async_trait::async_trait;
use axonflow_sdk_rust::interceptors::openai::{
    ChatCompletionRequest, ChatCompletionResponse, ChatMessage, OpenAIChatCompleter, Usage,
    WrappedOpenAIClient,
};
use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};

// Minimal stand-in for an OpenAI-compatible client. In a real app this would
// wrap async-openai or your in-house OpenAI HTTP client.
struct MockOpenAIClient;

#[async_trait]
impl OpenAIChatCompleter for MockOpenAIClient {
    async fn create_chat_completion(
        &self,
        req: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, Box<dyn std::error::Error + Send + Sync>> {
        println!("  [Underlying OpenAI client] would call model={}", req.model);
        Ok(ChatCompletionResponse {
            id: "chatcmpl-stub".to_string(),
            object: "chat.completion".to_string(),
            created: 0,
            model: req.model,
            choices: vec![],
            usage: Usage {
                prompt_tokens: 5,
                completion_tokens: 7,
                total_tokens: 12,
            },
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let agent_url =
        std::env::var("AXONFLOW_AGENT_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let mut config = AxonFlowConfig::new(agent_url);
    if let (Ok(id), Ok(secret)) = (
        std::env::var("AXONFLOW_CLIENT_ID"),
        std::env::var("AXONFLOW_CLIENT_SECRET"),
    ) {
        config = config.with_auth(id, secret);
    }
    let axonflow = AxonFlowClient::new(config)?;

    // Wrap your existing OpenAI-compatible client. Each chat completion now:
    //   1. Hits AxonFlow first for a policy pre-check (blocks on PII/SQLi/etc.)
    //   2. Forwards to the underlying client only if approved
    //   3. Asynchronously audits the call after the response
    let governed = WrappedOpenAIClient::new(MockOpenAIClient, axonflow, "user-456");

    let resp = governed
        .create_chat_completion(ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: "Hello from the Rust interceptor".to_string(),
            }],
            temperature: Some(0.7),
            max_tokens: Some(50),
        })
        .await?;

    println!("Governed response id: {}", resp.id);
    Ok(())
}
