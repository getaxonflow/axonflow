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
import com.getaxonflow.sdk.types.*;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.completion.chat.ChatMessageRole;
import com.theokanning.openai.service.OpenAiService;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * AxonFlow Gateway Mode - Java
 *
 * Gateway Mode provides the lowest latency AI governance by separating
 * policy enforcement from LLM calls. The workflow is:
 *
 * 1. Pre-check: Validate request against policies BEFORE calling LLM
 * 2. LLM Call: Make your own call to your preferred provider
 * 3. Audit: Log the interaction for compliance and monitoring
 *
 * This gives you full control over LLM parameters while maintaining
 * complete audit trails with ~3-5ms governance overhead.
 */
public class GatewayModeExample {

    private static final String CLIENT_ID = "gateway-mode-example";

    public static void main(String[] args) {
        System.out.println("AxonFlow Gateway Mode - Java Example");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow axonflow = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // Initialize OpenAI client
        String openaiKey = getEnv("OPENAI_API_KEY", "");
        if (openaiKey.isEmpty()) {
            System.err.println("Error: OPENAI_API_KEY environment variable is required");
            System.exit(1);
        }
        OpenAiService openai = new OpenAiService(openaiKey, Duration.ofSeconds(60));

        // Example request
        String userToken = "user-789";
        String query = "What are best practices for AI model deployment?";
        Map<String, Object> context = new HashMap<>();
        context.put("user_role", "engineer");
        context.put("department", "platform");

        System.out.printf("Query: \"%s\"%n", query);
        System.out.printf("User: %s%n", userToken);
        System.out.printf("Context: %s%n%n", context);

        // =========================================================================
        // STEP 1: Pre-Check - Validate against policies before LLM call
        // =========================================================================
        System.out.println("Step 1: Policy Pre-Check...");
        long preCheckStart = System.currentTimeMillis();

        PolicyApprovalResult preCheck;
        try {
            preCheck = axonflow.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query(query)
                    .userToken(userToken)
                    .clientId(CLIENT_ID)
                    .context(context)
                    .build()
            );

            long preCheckLatency = System.currentTimeMillis() - preCheckStart;
            System.out.printf("   Completed in %dms%n", preCheckLatency);
            System.out.printf("   Context ID: %s%n", preCheck.getContextId());
            System.out.printf("   Approved: %s%n", preCheck.isApproved());

            if (preCheck.getPolicies() != null && !preCheck.getPolicies().isEmpty()) {
                System.out.printf("   Policies: %s%n", String.join(", ", preCheck.getPolicies()));
            }

        } catch (PolicyViolationException e) {
            long preCheckLatency = System.currentTimeMillis() - preCheckStart;
            System.out.printf("   Completed in %dms%n", preCheckLatency);
            System.out.println("   BLOCKED");
            System.out.printf("   Policy: %s%n", e.getPolicyName());
            System.out.printf("   Reason: %s%n", e.getMessage());
            return;
        } catch (AxonFlowException e) {
            System.err.printf("Pre-check failed: %s%n", e.getMessage());
            return;
        }

        long preCheckLatency = System.currentTimeMillis() - preCheckStart;
        System.out.println();

        // =========================================================================
        // STEP 2: LLM Call - Make your own call to OpenAI
        // =========================================================================
        System.out.println("Step 2: LLM Call (OpenAI)...");
        long llmStart = System.currentTimeMillis();

        ChatCompletionRequest chatRequest = ChatCompletionRequest.builder()
            .model("gpt-3.5-turbo")
            .messages(Arrays.asList(
                new ChatMessage(ChatMessageRole.SYSTEM.value(),
                    "You are a helpful AI expert. Be concise."),
                new ChatMessage(ChatMessageRole.USER.value(), query)
            ))
            .maxTokens(200)
            .build();

        ChatCompletionResult completion;
        try {
            completion = openai.createChatCompletion(chatRequest);
        } catch (Exception e) {
            System.err.printf("OpenAI call failed: %s%n", e.getMessage());
            return;
        }

        long llmLatency = System.currentTimeMillis() - llmStart;
        String response = completion.getChoices().get(0).getMessage().getContent();
        int promptTokens = (int) completion.getUsage().getPromptTokens();
        int completionTokens = (int) completion.getUsage().getCompletionTokens();

        System.out.printf("   Response received in %dms%n", llmLatency);
        System.out.printf("   Tokens: %d prompt, %d completion%n", promptTokens, completionTokens);
        System.out.println();

        // =========================================================================
        // STEP 3: Audit - Log the interaction for compliance
        // =========================================================================
        System.out.println("Step 3: Audit Logging...");
        long auditStart = System.currentTimeMillis();

        // Truncate response for summary
        String responseSummary = response.length() > 100
            ? response.substring(0, 100)
            : response;

        try {
            AuditResult auditResult = axonflow.auditLLMCall(
                AuditOptions.builder()
                    .contextId(preCheck.getContextId())
                    .clientId(CLIENT_ID)
                    .responseSummary(responseSummary)
                    .provider("openai")
                    .model("gpt-3.5-turbo")
                    .tokenUsage(TokenUsage.of(promptTokens, completionTokens))
                    .latencyMs(llmLatency)
                    .build()
            );

            long auditLatency = System.currentTimeMillis() - auditStart;
            System.out.printf("   Audit logged in %dms%n", auditLatency);

            // =========================================================================
            // Results
            // =========================================================================
            long governanceOverhead = preCheckLatency + auditLatency;
            long totalLatency = preCheckLatency + llmLatency + auditLatency;

            System.out.println();
            System.out.println("============================================================");
            System.out.println("Results");
            System.out.println("============================================================");
            System.out.printf("%nResponse:%n%s%n%n", response);
            System.out.println("Latency Breakdown:");
            System.out.printf("   Pre-check:  %dms%n", preCheckLatency);
            System.out.printf("   LLM call:   %dms%n", llmLatency);
            System.out.printf("   Audit:      %dms%n", auditLatency);
            System.out.println("   -----------------");
            System.out.printf("   Governance: %dms (overhead)%n", governanceOverhead);
            System.out.printf("   Total:      %dms%n", totalLatency);

        } catch (AxonFlowException e) {
            System.err.printf("Warning: Audit failed (non-fatal): %s%n", e.getMessage());
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
