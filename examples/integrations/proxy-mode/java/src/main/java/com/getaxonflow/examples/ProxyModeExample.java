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
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.Map;

/**
 * AxonFlow Proxy Mode - Java
 *
 * Proxy Mode provides the simplest integration path. AxonFlow handles:
 * - Policy enforcement (pre and post)
 * - LLM routing and failover
 * - Response auditing
 *
 * You simply send a request and receive a governed response.
 *
 * Use Proxy Mode when:
 * - You want the simplest possible integration
 * - You're OK with AxonFlow managing LLM calls
 * - You want automatic provider failover
 */
public class ProxyModeExample {

    private static final String CLIENT_ID = "proxy-mode-example";

    public static void main(String[] args) {
        System.out.println("AxonFlow Proxy Mode - Java Example");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // Example 1: Safe query
        System.out.println("Example 1: Safe Query");
        System.out.println("=".repeat(60));
        runQuery(client, "What are the key principles of clean code?", "user-123");

        // Example 2: Query with PII (should be blocked)
        System.out.println();
        System.out.println("Example 2: Query with PII (Expected: Blocked)");
        System.out.println("=".repeat(60));
        runQuery(client, "Process refund for customer with SSN 123-45-6789", "user-456");

        // Example 3: SQL Injection attempt (should be blocked)
        System.out.println();
        System.out.println("Example 3: SQL Injection (Expected: Blocked)");
        System.out.println("=".repeat(60));
        runQuery(client, "Show me users WHERE 1=1; DROP TABLE users;--", "user-789");

        System.out.println();
        System.out.println("Proxy Mode Demo Complete!");
    }

    private static void runQuery(AxonFlow client, String query, String userToken) {
        System.out.printf("Query: \"%s\"%n", query);
        System.out.printf("User: %s%n%n", userToken);

        long startTime = System.currentTimeMillis();

        try {
            ClientResponse response = client.executeQuery(
                ClientRequest.builder()
                    .query(query)
                    .userToken(userToken)
                    .clientId(CLIENT_ID)
                    .model("gpt-3.5-turbo")
                    .llmProvider("openai")
                    .context(Map.of("source", "proxy-mode-example"))
                    .build()
            );

            long latency = System.currentTimeMillis() - startTime;

            if (response.isSuccess() && !response.isBlocked()) {
                System.out.println("Status: APPROVED");

                // Response data can be Object or String depending on endpoint
                Object data = response.getData();
                if (data != null) {
                    System.out.printf("Response:%n%s%n", data);
                } else if (response.getResult() != null) {
                    System.out.printf("Response:%n%s%n", response.getResult());
                }

                if (response.getPolicyInfo() != null) {
                    System.out.printf("%nPolicies evaluated: %s%n",
                        response.getPolicyInfo().getPoliciesEvaluated());
                }
            } else if (response.isBlocked()) {
                System.out.println("Status: BLOCKED");
                System.out.printf("Blocked by: %s%n", response.getBlockingPolicyName());
                System.out.printf("Reason: %s%n", response.getBlockReason());
            } else {
                System.out.println("Status: ERROR");
                System.out.printf("Error: %s%n", response.getError());
            }

            System.out.printf("%nLatency: %dms%n", latency);

        } catch (PolicyViolationException e) {
            long latency = System.currentTimeMillis() - startTime;
            System.out.println("Status: BLOCKED");
            System.out.printf("Policy: %s%n", e.getPolicyName());
            System.out.printf("Reason: %s%n", e.getMessage());
            System.out.printf("%nLatency: %dms%n", latency);

        } catch (AxonFlowException e) {
            System.out.println("Status: ERROR");
            System.out.printf("Error: %s%n", e.getMessage());
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
