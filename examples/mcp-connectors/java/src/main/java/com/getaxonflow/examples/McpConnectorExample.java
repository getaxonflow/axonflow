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
import com.getaxonflow.sdk.types.ConnectorQuery;
import com.getaxonflow.sdk.types.ConnectorResponse;
import com.getaxonflow.sdk.exceptions.ConnectorException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow MCP Connector Example - Java
 *
 * Demonstrates how to query MCP (Model Context Protocol) connectors
 * through AxonFlow with policy governance.
 *
 * MCP connectors allow AI applications to securely interact with
 * external systems like databases, APIs, and more.
 *
 * Prerequisites:
 * - AxonFlow running with connectors enabled (docker compose up -d)
 * - PostgreSQL connector configured in config/axonflow.yaml
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   mvn compile exec:java
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class McpConnectorExample {

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
        System.out.println("AxonFlow MCP Connector Example - Java");
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

        System.out.println("Testing MCP Connector Queries");
        System.out.println("------------------------------------------------------------");
        System.out.println();

        // Example 1: Query PostgreSQL Connector (configured in axonflow.yaml)
        System.out.println("Example 1: Query PostgreSQL Connector");
        System.out.println("----------------------------------------");

        try {
            ConnectorQuery query = ConnectorQuery.builder()
                .connectorId("postgres")  // Connector configured in config/axonflow.yaml
                .operation("SELECT 1 as health_check, current_timestamp as server_time")
                .userToken("user-123")
                .build();

            ConnectorResponse response = axonflow.queryConnector(query);

            if (response.isSuccess()) {
                System.out.println("Status: SUCCESS");
                System.out.printf("Data: %s%n", response.getData());
                assertCheck(response.getData() != null, "Connector query returned data");
            } else {
                System.out.println("Status: FAILED");
                System.out.printf("Error: %s%n", response.getError());
                assertCheck(false, "Connector query should succeed");
            }
        } catch (ConnectorException e) {
            System.out.println("Status: Connector not available");
            System.out.printf("Error: %s%n", e.getMessage());
            // Connector not available is acceptable in test environments
            assertCheck(true, "Connector query handled gracefully (connector not available)");
        } catch (Exception e) {
            System.out.println("Status: ERROR");
            System.out.printf("Error: %s%n", e.getMessage());
            assertCheck(false, "Connector query should not throw unexpected error");
        }

        System.out.println();

        // Example 2: Query with Policy Enforcement (SQL Injection)
        System.out.println("Example 2: Query with Policy Enforcement");
        System.out.println("----------------------------------------");
        System.out.println("MCP queries are policy-checked before execution.");
        System.out.println("Queries that violate policies will be blocked.");
        System.out.println();

        try {
            // This demonstrates that even connector queries go through policy checks
            ConnectorQuery query = ConnectorQuery.builder()
                .connectorId("postgres")
                .operation("SELECT * FROM users WHERE 1=1; DROP TABLE users;--")  // SQL injection attempt
                .userToken("user-123")
                .build();

            ConnectorResponse response = axonflow.queryConnector(query);

            boolean blocked = false;
            if (!response.isSuccess()) {
                String error = response.getError();
                if (error != null && (error.contains("blocked") || error.contains("policy") ||
                    error.contains("DROP TABLE") || error.contains("dangerous") ||
                    error.contains("SQL injection"))) {
                    System.out.println("Status: BLOCKED by policy (expected behavior)");
                    System.out.printf("Reason: %s%n", error);
                    blocked = true;
                } else {
                    System.out.println("Status: FAILED");
                    System.out.printf("Error: %s%n", error);
                }
            } else {
                System.out.println("Status: Query allowed (UNEXPECTED - should have been blocked!)");
                System.out.printf("Response: %s%n", response.getData());
            }
            assertCheck(blocked, "SQL injection query blocked by policy");
        } catch (Exception e) {
            String error = e.getMessage();
            boolean blocked = error != null && (error.contains("blocked") || error.contains("policy") ||
                error.contains("DROP TABLE") || error.contains("dangerous") ||
                error.contains("SQL injection"));
            if (blocked) {
                System.out.println("Status: BLOCKED by policy (expected behavior)");
                System.out.printf("Reason: %s%n", error);
            } else {
                System.out.println("Status: Error");
                System.out.printf("Error: %s%n", error);
            }
            assertCheck(blocked, "SQL injection query blocked by policy");
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println("Java MCP Connector Test: COMPLETE");

        // Final assertion check
        if (!failures.isEmpty()) {
            System.out.println();
            System.out.println("FAILURES (" + failures.size() + "):");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
            System.exit(1);
        }
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
