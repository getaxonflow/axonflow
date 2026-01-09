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
package com.getaxonflow.examples.springboot.config;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.theokanning.openai.service.OpenAiService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Configuration for AxonFlow and OpenAI clients.
 */
@Configuration
public class AxonFlowConfiguration {

    @Value("${axonflow.agent-url:http://localhost:8080}")
    private String agentUrl;

    @Value("${axonflow.client-id:}")
    private String clientId;

    @Value("${axonflow.client-secret:}")
    private String clientSecret;

    @Value("${axonflow.timeout-seconds:60}")
    private int timeoutSeconds;

    @Value("${axonflow.debug:false}")
    private boolean debug;

    @Value("${openai.api-key:}")
    private String openaiApiKey;

    /**
     * Creates a singleton AxonFlow client bean.
     * The client is thread-safe and should be reused across the application.
     */
    @Bean
    public AxonFlow axonFlowClient() {
        return AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(agentUrl)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .debug(debug)
            .build());
    }

    /**
     * Creates an OpenAI service client.
     */
    @Bean
    public OpenAiService openAiService() {
        String apiKey = openaiApiKey;
        if (apiKey == null || apiKey.isEmpty()) {
            apiKey = System.getenv("OPENAI_API_KEY");
        }
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException(
                "OPENAI_API_KEY environment variable or openai.api-key property must be set"
            );
        }
        return new OpenAiService(apiKey, Duration.ofSeconds(timeoutSeconds));
    }
}
