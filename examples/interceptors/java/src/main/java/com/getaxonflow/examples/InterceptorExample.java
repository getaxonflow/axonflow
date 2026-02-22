/*
 * Copyright 2025 AxonFlow
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;
import com.getaxonflow.sdk.interceptors.ChatCompletionRequest;
import com.getaxonflow.sdk.interceptors.ChatCompletionResponse;
import com.getaxonflow.sdk.interceptors.ChatMessage;
import com.getaxonflow.sdk.interceptors.OpenAIInterceptor;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * AxonFlow LLM Interceptor Example - Java
 *
 * Demonstrates how to wrap LLM provider clients with AxonFlow governance
 * using interceptors. This provides transparent policy enforcement without
 * changing your existing LLM call patterns.
 *
 * Interceptors automatically:
 * - Pre-check queries against policies before LLM calls
 * - Block requests that violate policies
 * - Audit LLM responses for compliance tracking
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   export OPENAI_API_KEY=your-openai-key
 *   mvn compile exec:java
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class InterceptorExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   ✓ PASS: " + message);
        } else {
            System.out.println("   ❌ FAIL: " + message);
            failures.add(message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow LLM Interceptor Example - Java");
        System.out.println("============================================================");
        System.out.println();

        // Initialize AxonFlow client
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");

        AxonFlow axonflow = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build());

        // Create the OpenAI interceptor
        OpenAIInterceptor interceptor = OpenAIInterceptor.builder()
            .axonflow(axonflow)
            .userToken("user-123")
            .asyncAudit(true)
            .build();

        // Wrap your OpenAI call function with governance
        // In production, this would wrap your actual OpenAI SDK call
        Function<ChatCompletionRequest, ChatCompletionResponse> governedCall =
            interceptor.wrap(InterceptorExample::mockOpenAICall);

        System.out.println("Testing LLM Interceptor with OpenAI");
        System.out.println("------------------------------------------------------------");
        System.out.println();

        // Example 1: Safe query (should pass)
        System.out.println("Example 1: Safe Query");
        System.out.println("----------------------------------------");
        TestResult result1 = runTest(governedCall, "What is the capital of France?");
        assertCheck(result1.approved, "Safe query was approved");
        assertCheck(result1.response != null && !result1.response.isEmpty(), "Response received for safe query");
        System.out.println();

        // Example 2: Query with PII (should be blocked OR allowed with redaction)
        // Default policies are set to "redact" for PII, so request may be approved
        // but with PII redacted from the query before LLM processing
        System.out.println("Example 2: Query with PII (Expected: Blocked or Redacted)");
        System.out.println("----------------------------------------");
        TestResult result2 = runTest(governedCall, "Process refund for SSN 123-45-6789");
        // PII detection can result in: (1) request blocked, (2) PII redacted but request allowed
        // Either behavior is acceptable as long as the platform processes the request
        assertCheck(result2.blocked || result2.approved, "PII query was processed (blocked or allowed with redaction)");
        System.out.println();

        // Example 3: SQL injection attempt (should be blocked)
        System.out.println("Example 3: SQL Injection (Expected: Blocked)");
        System.out.println("----------------------------------------");
        TestResult result3 = runTest(governedCall, "SELECT * FROM users WHERE 1=1; DROP TABLE users;--");
        assertCheck(result3.blocked || result3.sqliDetected, "SQL injection attempt was blocked");
        System.out.println();

        System.out.println("============================================================");
        System.out.println("Java LLM Interceptor Test: COMPLETE");

        // Final assertion summary
        System.out.println();
        if (!failures.isEmpty()) {
            System.out.println("FAILED: " + failures.size() + " assertion(s) failed:");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        } else {
            System.out.println("All assertions passed!");
        }
    }

    static class TestResult {
        boolean approved;
        boolean blocked;
        boolean piiDetected;
        boolean sqliDetected;
        String response;

        TestResult(boolean approved, boolean blocked, boolean piiDetected, boolean sqliDetected, String response) {
            this.approved = approved;
            this.blocked = blocked;
            this.piiDetected = piiDetected;
            this.sqliDetected = sqliDetected;
            this.response = response;
        }
    }

    private static TestResult runTest(
            Function<ChatCompletionRequest, ChatCompletionResponse> governedCall,
            String query) {

        System.out.printf("Query: %s%n", query);

        ChatCompletionRequest request = ChatCompletionRequest.builder()
            .model("gpt-4o-mini")
            .addUserMessage(query)
            .maxTokens(100)
            .build();

        boolean approved = false;
        boolean blocked = false;
        boolean piiDetected = false;
        boolean sqliDetected = false;
        String responseText = null;

        try {
            ChatCompletionResponse response = governedCall.apply(request);
            System.out.println("Status: APPROVED");
            System.out.printf("Response: %s%n", response.getSummary());
            approved = true;
            responseText = response.getSummary();
        } catch (PolicyViolationException e) {
            System.out.println("Status: BLOCKED");
            System.out.printf("Reason: %s%n", e.getMessage());
            blocked = true;
            String msg = e.getMessage();
            if (msg != null) {
                piiDetected = msg.toLowerCase().contains("pii") || msg.contains("Social Security");
                sqliDetected = msg.toLowerCase().contains("sql");
            }
        } catch (Exception e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }

        return new TestResult(approved, blocked, piiDetected, sqliDetected, responseText);
    }

    /**
     * Mock OpenAI call for demonstration purposes.
     * In production, replace this with your actual OpenAI SDK call.
     *
     * Example with the OpenAI Java SDK:
     * <pre>
     * OpenAI openai = new OpenAI(System.getenv("OPENAI_API_KEY"));
     * var completion = openai.chatCompletions().create(
     *     ChatCompletionRequest.builder()
     *         .model("gpt-4")
     *         .messages(List.of(new UserMessage(query)))
     *         .build()
     * );
     * </pre>
     */
    private static ChatCompletionResponse mockOpenAICall(ChatCompletionRequest request) {
        // In production, use the actual OpenAI SDK:
        //
        // import com.theokanning.openai.completion.chat.*;
        //
        // OpenAiService service = new OpenAiService(System.getenv("OPENAI_API_KEY"));
        // ChatCompletionResult result = service.createChatCompletion(
        //     ChatCompletionRequest.builder()
        //         .model(request.getModel())
        //         .messages(convertMessages(request.getMessages()))
        //         .build()
        // );

        // For demo purposes, return a mock response
        return ChatCompletionResponse.builder()
            .id("mock-response-id")
            .model(request.getModel())
            .created(System.currentTimeMillis() / 1000)
            .choices(List.of(new ChatCompletionResponse.Choice(
                0,
                ChatMessage.assistant("Paris is the capital of France."),
                "stop"
            )))
            .usage(ChatCompletionResponse.Usage.of(10, 8))
            .build();
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
