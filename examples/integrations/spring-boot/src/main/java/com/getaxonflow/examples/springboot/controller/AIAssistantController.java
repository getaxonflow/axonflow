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
package com.getaxonflow.examples.springboot.controller;

import com.getaxonflow.examples.springboot.service.AIAssistantService;
import com.getaxonflow.examples.springboot.service.AIAssistantService.AIResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST API for the AI Assistant.
 *
 * All requests are governed by AxonFlow policies.
 */
@RestController
@RequestMapping("/api/v1/assistant")
public class AIAssistantController {

    private final AIAssistantService assistantService;

    public AIAssistantController(AIAssistantService assistantService) {
        this.assistantService = assistantService;
    }

    /**
     * Process a user query through governed AI.
     *
     * @param request Query request with user ID and prompt
     * @return AI response with governance metadata
     */
    @PostMapping("/query")
    public ResponseEntity<AIResponse> query(@RequestBody QueryRequest request) {
        if (request.getUserId() == null || request.getUserId().isEmpty()) {
            return ResponseEntity.badRequest().body(
                AIResponse.error("Validation error", "userId is required")
            );
        }
        if (request.getQuery() == null || request.getQuery().isEmpty()) {
            return ResponseEntity.badRequest().body(
                AIResponse.error("Validation error", "query is required")
            );
        }

        AIResponse response = assistantService.processQuery(
            request.getUserId(),
            request.getQuery(),
            request.getContext()
        );

        if (response.isBlocked()) {
            return ResponseEntity.status(403).body(response);
        }
        if (!response.isSuccess()) {
            return ResponseEntity.status(503).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Simple health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "healthy",
            "service", "ai-assistant"
        ));
    }

    /**
     * Query request DTO.
     */
    public static class QueryRequest {
        private String userId;
        private String query;
        private Map<String, Object> context;

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getQuery() { return query; }
        public void setQuery(String query) { this.query = query; }
        public Map<String, Object> getContext() { return context; }
        public void setContext(Map<String, Object> context) { this.context = context; }
    }
}
