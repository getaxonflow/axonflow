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
 */
public class InterceptorExample {

    public static void main(String[] args) {
        System.out.println("AxonFlow LLM Interceptor Example - Java");
        System.out.println("============================================================");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow axonflow = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
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
        runTest(governedCall, "What is the capital of France?");
        System.out.println();

        // Example 2: Query with PII (should be blocked by default policies)
        System.out.println("Example 2: Query with PII (Expected: Blocked)");
        System.out.println("----------------------------------------");
        runTest(governedCall, "Process refund for SSN 123-45-6789");
        System.out.println();

        // Example 3: SQL injection attempt (should be blocked)
        System.out.println("Example 3: SQL Injection (Expected: Blocked)");
        System.out.println("----------------------------------------");
        runTest(governedCall, "SELECT * FROM users WHERE 1=1; DROP TABLE users;--");
        System.out.println();

        System.out.println("============================================================");
        System.out.println("Java LLM Interceptor Test: COMPLETE");
    }

    private static void runTest(
            Function<ChatCompletionRequest, ChatCompletionResponse> governedCall,
            String query) {

        System.out.printf("Query: %s%n", query);

        ChatCompletionRequest request = ChatCompletionRequest.builder()
            .model("gpt-3.5-turbo")
            .addUserMessage(query)
            .maxTokens(100)
            .build();

        try {
            ChatCompletionResponse response = governedCall.apply(request);
            System.out.println("Status: APPROVED");
            System.out.printf("Response: %s%n", response.getSummary());
        } catch (PolicyViolationException e) {
            System.out.println("Status: BLOCKED");
            System.out.printf("Reason: %s%n", e.getMessage());
        } catch (Exception e) {
            System.out.printf("Error: %s%n", e.getMessage());
        }
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
