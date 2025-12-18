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
package com.getaxonflow.examples.springboot.service;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.types.*;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatCompletionResult;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.completion.chat.ChatMessageRole;
import com.theokanning.openai.service.OpenAiService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * AI Assistant Service implementing Gateway Mode pattern.
 *
 * Demonstrates production-grade AxonFlow integration with:
 * - Pre-check policy validation
 * - External LLM calls (OpenAI)
 * - Audit logging
 * - Error handling
 */
@Service
public class AIAssistantService {

    private static final Logger log = LoggerFactory.getLogger(AIAssistantService.class);
    private static final String CLIENT_ID = "spring-boot-assistant";

    private final AxonFlow axonFlow;
    private final OpenAiService openAi;

    public AIAssistantService(AxonFlow axonFlow, OpenAiService openAi) {
        this.axonFlow = axonFlow;
        this.openAi = openAi;
    }

    /**
     * Process a user query through the governed AI pipeline.
     *
     * @param userId User identifier for tracking
     * @param query User's question or request
     * @param context Additional context metadata
     * @return AI response with governance metadata
     */
    public AIResponse processQuery(String userId, String query, Map<String, Object> context) {
        long startTime = System.currentTimeMillis();

        // Merge default context
        Map<String, Object> fullContext = new HashMap<>();
        fullContext.put("service", "ai-assistant");
        fullContext.put("version", "1.0.0");
        if (context != null) {
            fullContext.putAll(context);
        }

        // Step 1: Pre-check
        log.info("Pre-checking query for user: {}", userId);
        PolicyApprovalResult preCheck;
        long preCheckStart = System.currentTimeMillis();
        long preCheckLatency;

        try {
            preCheck = axonFlow.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .query(query)
                    .userToken(userId)
                    .clientId(CLIENT_ID)
                    .context(fullContext)
                    .build()
            );
            preCheckLatency = System.currentTimeMillis() - preCheckStart;
            log.debug("Pre-check completed in {}ms, approved: {}", preCheckLatency, preCheck.isApproved());

        } catch (PolicyViolationException e) {
            preCheckLatency = System.currentTimeMillis() - preCheckStart;
            log.warn("Query blocked for user {}: {}", userId, e.getMessage());
            return AIResponse.blocked(
                e.getMessage(),
                e.getPoliciesEvaluated(),
                preCheckLatency
            );
        } catch (AxonFlowException e) {
            log.error("Pre-check failed for user {}: {}", userId, e.getMessage());
            return AIResponse.error("Governance service unavailable", e.getMessage());
        }

        // Step 2: LLM Call
        log.info("Calling LLM for user: {}", userId);
        long llmStart = System.currentTimeMillis();
        ChatCompletionResult completion;

        try {
            ChatCompletionRequest request = ChatCompletionRequest.builder()
                .model("gpt-3.5-turbo")
                .messages(Arrays.asList(
                    new ChatMessage(ChatMessageRole.SYSTEM.value(),
                        "You are a helpful assistant. Be concise and accurate."),
                    new ChatMessage(ChatMessageRole.USER.value(), query)
                ))
                .maxTokens(500)
                .build();

            completion = openAi.createChatCompletion(request);
        } catch (Exception e) {
            log.error("LLM call failed for user {}: {}", userId, e.getMessage());
            return AIResponse.error("AI service unavailable", e.getMessage());
        }

        long llmLatency = System.currentTimeMillis() - llmStart;
        String response = completion.getChoices().get(0).getMessage().getContent();
        int promptTokens = (int) completion.getUsage().getPromptTokens();
        int completionTokens = (int) completion.getUsage().getCompletionTokens();

        log.debug("LLM response received in {}ms, tokens: {}/{}", llmLatency, promptTokens, completionTokens);

        // Step 3: Audit
        log.info("Auditing interaction for user: {}", userId);
        long auditStart = System.currentTimeMillis();

        try {
            axonFlow.auditLLMCall(
                AuditOptions.builder()
                    .contextId(preCheck.getContextId())
                    .clientId(CLIENT_ID)
                    .responseSummary(truncate(response, 500))
                    .provider("openai")
                    .model("gpt-3.5-turbo")
                    .tokenUsage(TokenUsage.of(promptTokens, completionTokens))
                    .latencyMs(llmLatency)
                    .build()
            );
        } catch (AxonFlowException e) {
            // Audit failures are non-fatal
            log.warn("Audit failed for user {} (non-fatal): {}", userId, e.getMessage());
        }

        long auditLatency = System.currentTimeMillis() - auditStart;
        long totalLatency = System.currentTimeMillis() - startTime;

        log.info("Query processed for user {} in {}ms (governance: {}ms)",
            userId, totalLatency, preCheckLatency + auditLatency);

        return AIResponse.success(
            response,
            preCheck.getContextId(),
            promptTokens,
            completionTokens,
            preCheckLatency,
            llmLatency,
            auditLatency
        );
    }

    private String truncate(String str, int maxLen) {
        if (str == null || str.length() <= maxLen) {
            return str;
        }
        return str.substring(0, maxLen);
    }

    /**
     * Response wrapper with governance metadata.
     */
    public static class AIResponse {
        private final boolean success;
        private final boolean blocked;
        private final String response;
        private final String error;
        private final String errorDetails;
        private final String requestId;
        private final String blockedReason;
        private final java.util.List<String> matchedPolicies;
        private final Integer promptTokens;
        private final Integer completionTokens;
        private final Long preCheckLatencyMs;
        private final Long llmLatencyMs;
        private final Long auditLatencyMs;
        private final Long governanceOverheadMs;

        private AIResponse(Builder builder) {
            this.success = builder.success;
            this.blocked = builder.blocked;
            this.response = builder.response;
            this.error = builder.error;
            this.errorDetails = builder.errorDetails;
            this.requestId = builder.requestId;
            this.blockedReason = builder.blockedReason;
            this.matchedPolicies = builder.matchedPolicies;
            this.promptTokens = builder.promptTokens;
            this.completionTokens = builder.completionTokens;
            this.preCheckLatencyMs = builder.preCheckLatencyMs;
            this.llmLatencyMs = builder.llmLatencyMs;
            this.auditLatencyMs = builder.auditLatencyMs;
            this.governanceOverheadMs = builder.governanceOverheadMs;
        }

        public static AIResponse success(String response, String requestId,
                                         int promptTokens, int completionTokens,
                                         long preCheckMs, long llmMs, long auditMs) {
            return new Builder()
                .success(true)
                .blocked(false)
                .response(response)
                .requestId(requestId)
                .promptTokens(promptTokens)
                .completionTokens(completionTokens)
                .preCheckLatencyMs(preCheckMs)
                .llmLatencyMs(llmMs)
                .auditLatencyMs(auditMs)
                .governanceOverheadMs(preCheckMs + auditMs)
                .build();
        }

        public static AIResponse blocked(String reason, java.util.List<String> policies, long preCheckMs) {
            return new Builder()
                .success(false)
                .blocked(true)
                .blockedReason(reason)
                .matchedPolicies(policies)
                .preCheckLatencyMs(preCheckMs)
                .governanceOverheadMs(preCheckMs)
                .build();
        }

        public static AIResponse error(String error, String details) {
            return new Builder()
                .success(false)
                .blocked(false)
                .error(error)
                .errorDetails(details)
                .build();
        }

        // Getters
        public boolean isSuccess() { return success; }
        public boolean isBlocked() { return blocked; }
        public String getResponse() { return response; }
        public String getError() { return error; }
        public String getErrorDetails() { return errorDetails; }
        public String getRequestId() { return requestId; }
        public String getBlockedReason() { return blockedReason; }
        public java.util.List<String> getMatchedPolicies() { return matchedPolicies; }
        public Integer getPromptTokens() { return promptTokens; }
        public Integer getCompletionTokens() { return completionTokens; }
        public Long getPreCheckLatencyMs() { return preCheckLatencyMs; }
        public Long getLlmLatencyMs() { return llmLatencyMs; }
        public Long getAuditLatencyMs() { return auditLatencyMs; }
        public Long getGovernanceOverheadMs() { return governanceOverheadMs; }

        private static class Builder {
            private boolean success;
            private boolean blocked;
            private String response;
            private String error;
            private String errorDetails;
            private String requestId;
            private String blockedReason;
            private java.util.List<String> matchedPolicies;
            private Integer promptTokens;
            private Integer completionTokens;
            private Long preCheckLatencyMs;
            private Long llmLatencyMs;
            private Long auditLatencyMs;
            private Long governanceOverheadMs;

            Builder success(boolean v) { this.success = v; return this; }
            Builder blocked(boolean v) { this.blocked = v; return this; }
            Builder response(String v) { this.response = v; return this; }
            Builder error(String v) { this.error = v; return this; }
            Builder errorDetails(String v) { this.errorDetails = v; return this; }
            Builder requestId(String v) { this.requestId = v; return this; }
            Builder blockedReason(String v) { this.blockedReason = v; return this; }
            Builder matchedPolicies(java.util.List<String> v) { this.matchedPolicies = v; return this; }
            Builder promptTokens(Integer v) { this.promptTokens = v; return this; }
            Builder completionTokens(Integer v) { this.completionTokens = v; return this; }
            Builder preCheckLatencyMs(Long v) { this.preCheckLatencyMs = v; return this; }
            Builder llmLatencyMs(Long v) { this.llmLatencyMs = v; return this; }
            Builder auditLatencyMs(Long v) { this.auditLatencyMs = v; return this; }
            Builder governanceOverheadMs(Long v) { this.governanceOverheadMs = v; return this; }
            AIResponse build() { return new AIResponse(this); }
        }
    }
}
