package com.axonflow.examples;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Azure OpenAI Integration Example - Java
 * Demonstrates Gateway Mode and Proxy Mode with AxonFlow
 */
public class AzureOpenAIExample {

    private static final String AXONFLOW_URL = System.getenv().getOrDefault("AXONFLOW_URL", "http://localhost:8080");
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .build();

    public static void main(String[] args) {
        // Get Azure OpenAI credentials from environment
        String endpoint = System.getenv("AZURE_OPENAI_ENDPOINT");
        String apiKey = System.getenv("AZURE_OPENAI_API_KEY");
        String deploymentName = System.getenv("AZURE_OPENAI_DEPLOYMENT_NAME");
        String apiVersion = System.getenv().getOrDefault("AZURE_OPENAI_API_VERSION", "2024-08-01-preview");

        if (endpoint == null || apiKey == null || deploymentName == null) {
            System.err.println("Error: Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT_NAME");
            System.exit(1);
        }

        endpoint = endpoint.replaceAll("/$", ""); // Remove trailing slash

        System.out.println("=== Azure OpenAI with AxonFlow ===");
        System.out.println("Endpoint: " + endpoint);
        System.out.println("Deployment: " + deploymentName);
        System.out.println("Auth: " + detectAuthType(endpoint));
        System.out.println();

        // Example 1: Gateway Mode (recommended)
        System.out.println("--- Example 1: Gateway Mode ---");
        try {
            gatewayModeExample(endpoint, apiKey, deploymentName, apiVersion);
        } catch (Exception e) {
            System.err.println("Gateway mode error: " + e.getMessage());
        }
        System.out.println();

        // Example 2: Proxy Mode
        System.out.println("--- Example 2: Proxy Mode ---");
        try {
            proxyModeExample();
        } catch (Exception e) {
            System.err.println("Proxy mode error: " + e.getMessage());
        }
    }

    private static String detectAuthType(String endpoint) {
        if (endpoint.toLowerCase().contains("cognitiveservices.azure.com")) {
            return "Bearer token (Foundry)";
        }
        return "api-key (Classic)";
    }

    private static void gatewayModeExample(String endpoint, String apiKey,
                                           String deploymentName, String apiVersion)
            throws IOException, InterruptedException {

        String userPrompt = "What are the key benefits of using Azure OpenAI over standard OpenAI API?";

        // Step 1: Pre-check with AxonFlow
        System.out.println("Step 1: Pre-checking with AxonFlow...");
        String preCheckBody = String.format("""
            {
                "client_id": "azure-openai-example",
                "query": "%s",
                "context": {
                    "provider": "azure-openai",
                    "model": "%s"
                }
            }
            """, escapeJson(userPrompt), deploymentName);

        HttpRequest preCheckReq = HttpRequest.newBuilder()
                .uri(URI.create(AXONFLOW_URL + "/api/policy/pre-check"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(preCheckBody))
                .timeout(TIMEOUT)
                .build();

        HttpResponse<String> preCheckResp = httpClient.send(preCheckReq, HttpResponse.BodyHandlers.ofString());

        if (preCheckResp.statusCode() != 200) {
            throw new RuntimeException("Pre-check failed: " + preCheckResp.body());
        }

        // Simple JSON parsing (in production, use a proper JSON library)
        String contextId = extractJsonValue(preCheckResp.body(), "context_id");
        String approved = extractJsonValue(preCheckResp.body(), "approved");

        if (!"true".equals(approved)) {
            System.out.println("Request blocked by policy");
            return;
        }
        System.out.println("Pre-check passed (context: " + contextId + ")");

        // Step 2: Call Azure OpenAI directly
        System.out.println("Step 2: Calling Azure OpenAI...");
        long startTime = System.currentTimeMillis();

        String azureUrl = String.format("%s/openai/deployments/%s/chat/completions?api-version=%s",
                endpoint, deploymentName, apiVersion);

        String azureBody = String.format("""
            {
                "messages": [{"role": "user", "content": "%s"}],
                "max_tokens": 500,
                "temperature": 0.7
            }
            """, escapeJson(userPrompt));

        HttpRequest.Builder azureReqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(azureUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(azureBody))
                .timeout(TIMEOUT);

        // Set auth header based on endpoint type
        if (endpoint.toLowerCase().contains("cognitiveservices.azure.com")) {
            azureReqBuilder.header("Authorization", "Bearer " + apiKey);
        } else {
            azureReqBuilder.header("api-key", apiKey);
        }

        HttpResponse<String> azureResp = httpClient.send(azureReqBuilder.build(),
                                                         HttpResponse.BodyHandlers.ofString());

        if (azureResp.statusCode() != 200) {
            throw new RuntimeException("Azure OpenAI error: " + azureResp.body());
        }

        long latency = System.currentTimeMillis() - startTime;
        String content = extractAzureContent(azureResp.body());

        System.out.println("Response received (latency: " + latency + "ms)");
        System.out.println("Response: " + truncate(content, 200));

        // Step 3: Audit the response
        System.out.println("Step 3: Auditing with AxonFlow...");
        try {
            String auditBody = String.format("""
                {
                    "client_id": "azure-openai-example",
                    "context_id": "%s",
                    "response_summary": "%s",
                    "provider": "azure-openai",
                    "model": "%s",
                    "latency_ms": %d,
                    "token_usage": {
                        "prompt_tokens": 50,
                        "completion_tokens": 100,
                        "total_tokens": 150
                    }
                }
                """, contextId, escapeJson(truncate(content, 500)), deploymentName, latency);

            HttpRequest auditReq = HttpRequest.newBuilder()
                    .uri(URI.create(AXONFLOW_URL + "/api/audit/llm-call"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(auditBody))
                    .timeout(TIMEOUT)
                    .build();

            HttpResponse<String> auditResp = httpClient.send(auditReq, HttpResponse.BodyHandlers.ofString());

            if (auditResp.statusCode() == 200 || auditResp.statusCode() == 202 || auditResp.statusCode() == 204) {
                System.out.println("Audit logged successfully");
            } else {
                System.out.println("Audit warning: " + auditResp.body());
            }
        } catch (Exception e) {
            System.out.println("Audit warning: " + e.getMessage());
        }
    }

    private static void proxyModeExample() throws IOException, InterruptedException {
        System.out.println("Sending request through AxonFlow proxy...");

        long startTime = System.currentTimeMillis();

        String body = """
            {
                "query": "Explain the difference between Azure OpenAI Classic and Foundry patterns in 2 sentences.",
                "context": {
                    "provider": "azure-openai"
                }
            }
            """;

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(AXONFLOW_URL + "/api/request"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(TIMEOUT)
                .build();

        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new RuntimeException("AxonFlow error: " + resp.body());
        }

        long latency = System.currentTimeMillis() - startTime;

        // Parse the actual AxonFlow response structure: {"success": true, "data": {"data": "..."}, "blocked": false}
        String blocked = extractJsonValue(resp.body(), "blocked");
        // Need to extract nested data.data - find the inner data object
        String responseText = extractNestedDataValue(resp.body());

        System.out.println("Response received (latency: " + latency + "ms)");
        System.out.println("Blocked: " + blocked);
        System.out.println("Response: " + truncate(responseText, 300));
    }

    private static String extractNestedDataValue(String json) {
        // Find "data":{"data":" pattern and extract the inner data value
        int dataIdx = json.indexOf("\"data\":{\"data\":");
        if (dataIdx == -1) {
            // Try alternative format
            dataIdx = json.indexOf("\"data\": {\"data\":");
        }
        if (dataIdx == -1) return "";

        int start = json.indexOf("\"data\":", dataIdx + 7) + 8;
        if (start < 8) return "";

        // Skip whitespace and opening quote
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '"')) {
            start++;
        }
        start--; // Back to the quote
        if (json.charAt(start) == '"') start++;

        int end = start;
        while (end < json.length() && json.charAt(end) != '"') {
            if (json.charAt(end) == '\\') end++;
            end++;
        }
        return json.substring(start, end);
    }

    // Simple JSON helpers (in production, use Jackson or Gson)
    private static String extractJsonValue(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return "";
        int start = json.indexOf(":", idx) + 1;
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '"')) {
            start++;
        }
        int end = start;
        boolean inString = json.charAt(start - 1) == '"';
        if (inString) {
            while (end < json.length() && json.charAt(end) != '"') {
                if (json.charAt(end) == '\\') end++;
                end++;
            }
        } else {
            while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') {
                end++;
            }
        }
        return json.substring(start, end).trim();
    }

    private static String extractNestedJsonValue(String json, String... keys) {
        String current = json;
        for (int i = 0; i < keys.length; i++) {
            current = extractJsonValue(current, keys[i]);
        }
        return current;
    }

    // Extract content from Azure OpenAI response: {"choices":[{"message":{"content":"..."}}]}
    private static String extractAzureContent(String json) {
        // Find "content":" pattern within the choices array
        int contentIdx = json.indexOf("\"content\":");
        if (contentIdx == -1) return "";

        int start = contentIdx + 10; // skip "content":
        // Skip whitespace and opening quote
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '"')) {
            start++;
        }

        int end = start;
        while (end < json.length() && json.charAt(end) != '"') {
            if (json.charAt(end) == '\\') end++; // Skip escaped chars
            end++;
        }
        return json.substring(start, end)
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"");
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String truncate(String s, int maxLen) {
        if (s == null || s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...";
    }
}
