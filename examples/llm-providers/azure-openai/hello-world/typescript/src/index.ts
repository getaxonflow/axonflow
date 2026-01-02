/**
 * Azure OpenAI Integration Example - TypeScript
 * Demonstrates Gateway Mode and Proxy Mode with AxonFlow
 */

const AXONFLOW_URL = process.env.AXONFLOW_URL || "http://localhost:8080";
const TIMEOUT = 30000;

interface PreCheckResponse {
  approved: boolean;
  context_id: string;
  policies?: string[];
  expires_at?: string;
}

interface AzureOpenAIResponse {
  choices: Array<{
    message: {
      content: string;
    };
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
  };
}

interface ProxyResponse {
  success: boolean;
  data: {
    data: string;
    metadata?: {
      processed_at?: string;
    };
  };
  blocked: boolean;
  policy_info?: {
    processing_time?: string;
  };
}

async function main() {
  // Get Azure OpenAI credentials from environment
  const endpoint = process.env.AZURE_OPENAI_ENDPOINT?.replace(/\/$/, "") || "";
  const apiKey = process.env.AZURE_OPENAI_API_KEY || "";
  const deploymentName = process.env.AZURE_OPENAI_DEPLOYMENT_NAME || "";
  const apiVersion = process.env.AZURE_OPENAI_API_VERSION || "2024-08-01-preview";

  if (!endpoint || !apiKey || !deploymentName) {
    console.error("Error: Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT_NAME");
    process.exit(1);
  }

  console.log("=== Azure OpenAI with AxonFlow ===");
  console.log(`Endpoint: ${endpoint}`);
  console.log(`Deployment: ${deploymentName}`);
  console.log(`Auth: ${detectAuthType(endpoint)}`);
  console.log();

  // Example 1: Gateway Mode (recommended)
  console.log("--- Example 1: Gateway Mode ---");
  try {
    await gatewayModeExample(endpoint, apiKey, deploymentName, apiVersion);
  } catch (error) {
    console.error(`Gateway mode error: ${error}`);
  }
  console.log();

  // Example 2: Proxy Mode
  console.log("--- Example 2: Proxy Mode ---");
  try {
    await proxyModeExample();
  } catch (error) {
    console.error(`Proxy mode error: ${error}`);
  }
}

function detectAuthType(endpoint: string): string {
  if (endpoint.toLowerCase().includes("cognitiveservices.azure.com")) {
    return "Bearer token (Foundry)";
  }
  return "api-key (Classic)";
}

async function gatewayModeExample(
  endpoint: string,
  apiKey: string,
  deploymentName: string,
  apiVersion: string
): Promise<void> {
  const userPrompt = "What are the key benefits of using Azure OpenAI over standard OpenAI API?";

  // Step 1: Pre-check with AxonFlow
  console.log("Step 1: Pre-checking with AxonFlow...");
  const preCheckResp = await preCheck(userPrompt, "azure-openai", deploymentName);

  if (!preCheckResp.approved) {
    console.log("Request blocked by policy");
    return;
  }
  console.log(`Pre-check passed (context: ${preCheckResp.context_id})`);

  // Step 2: Call Azure OpenAI directly
  console.log("Step 2: Calling Azure OpenAI...");
  const startTime = Date.now();

  const azureUrl = `${endpoint}/openai/deployments/${deploymentName}/chat/completions?api-version=${apiVersion}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Set auth header based on endpoint type
  if (endpoint.toLowerCase().includes("cognitiveservices.azure.com")) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  } else {
    headers["api-key"] = apiKey;
  }

  const response = await fetch(azureUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({
      messages: [{ role: "user", content: userPrompt }],
      max_tokens: 500,
      temperature: 0.7,
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Azure OpenAI error (status ${response.status}): ${text}`);
  }

  const data: AzureOpenAIResponse = await response.json();
  const latency = Date.now() - startTime;

  const content = data.choices?.[0]?.message?.content || "";
  const { prompt_tokens, completion_tokens } = data.usage;

  console.log(`Response received (latency: ${latency}ms)`);
  console.log(`Response: ${truncate(content, 200)}`);

  // Step 3: Audit the response
  console.log("Step 3: Auditing with AxonFlow...");
  try {
    await auditLLMCall(
      preCheckResp.context_id,
      content,
      "azure-openai",
      deploymentName,
      latency,
      prompt_tokens,
      completion_tokens
    );
    console.log("Audit logged successfully");
  } catch (error) {
    console.log(`Audit warning: ${error}`);
  }
}

async function proxyModeExample(): Promise<void> {
  console.log("Sending request through AxonFlow proxy...");

  const startTime = Date.now();

  const response = await fetch(`${AXONFLOW_URL}/api/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: "Explain the difference between Azure OpenAI Classic and Foundry patterns in 2 sentences.",
      context: {
        provider: "azure-openai",
      },
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`AxonFlow error (status ${response.status}): ${text}`);
  }

  const data: ProxyResponse = await response.json();
  const latency = Date.now() - startTime;

  console.log(`Response received (latency: ${latency}ms)`);
  console.log(`Blocked: ${data.blocked}`);
  console.log(`Response: ${truncate(data.data?.data || "", 300)}`);
}

async function preCheck(prompt: string, provider: string, model: string): Promise<PreCheckResponse> {
  const response = await fetch(`${AXONFLOW_URL}/api/policy/pre-check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: "azure-openai-example",
      query: prompt,
      context: {
        provider,
        model,
      },
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Pre-check failed (status ${response.status}): ${text}`);
  }

  return response.json();
}

async function auditLLMCall(
  contextId: string,
  responseText: string,
  provider: string,
  model: string,
  latencyMs: number,
  promptTokens: number,
  completionTokens: number
): Promise<void> {
  const response = await fetch(`${AXONFLOW_URL}/api/audit/llm-call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: "azure-openai-example",
      context_id: contextId,
      response_summary: truncate(responseText, 500),
      provider,
      model,
      latency_ms: latencyMs,
      token_usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: promptTokens + completionTokens,
      },
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });

  if (!response.ok && response.status !== 202 && response.status !== 204) {
    const text = await response.text();
    throw new Error(`Audit failed (status ${response.status}): ${text}`);
  }
}

function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.substring(0, maxLen) + "...";
}

main().catch(console.error);
