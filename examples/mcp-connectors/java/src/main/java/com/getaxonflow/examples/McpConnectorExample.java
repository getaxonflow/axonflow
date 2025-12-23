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

import java.util.Map;

/**
 * AxonFlow MCP Connector Example - Java
 *
 * Demonstrates how to query MCP (Model Context Protocol) connectors
 * through AxonFlow with policy governance.
 *
 * MCP connectors allow AI applications to securely interact with
 * external systems like GitHub, Salesforce, Jira, and more.
 *
 * Prerequisites:
 * - AxonFlow running with connectors enabled
 * - Connector installed and configured (e.g., GitHub connector)
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   mvn compile exec:java
 */
public class McpConnectorExample {

    public static void main(String[] args) {
        System.out.println("AxonFlow MCP Connector Example - Java");
        System.out.println("============================================================");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow axonflow = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        System.out.println("Testing MCP Connector Queries");
        System.out.println("------------------------------------------------------------");
        System.out.println();

        // Example 1: Query GitHub Connector
        System.out.println("Example 1: Query GitHub Connector");
        System.out.println("----------------------------------------");

        try {
            ConnectorQuery query = ConnectorQuery.builder()
                .connectorId("github")
                .operation("list_issues")
                .userToken("user-123")
                .addParameter("repo", "getaxonflow/axonflow")
                .addParameter("state", "open")
                .addParameter("limit", 5)
                .build();

            ConnectorResponse response = axonflow.queryConnector(query);

            if (response.isSuccess()) {
                System.out.println("Status: SUCCESS");
                System.out.printf("Data: %s%n", response.getData());
            } else {
                System.out.println("Status: FAILED");
                System.out.printf("Error: %s%n", response.getError());
            }
        } catch (ConnectorException e) {
            // Connector not installed - expected for demo
            System.out.println("Status: Connector not available (expected if not installed)");
            System.out.printf("Error: %s%n", e.getMessage());
        } catch (Exception e) {
            System.out.println("Status: ERROR");
            System.out.printf("Error: %s%n", e.getMessage());
        }

        System.out.println();

        // Example 2: Query with Policy Enforcement
        System.out.println("Example 2: Query with Policy Enforcement");
        System.out.println("----------------------------------------");
        System.out.println("MCP queries are policy-checked before execution.");
        System.out.println("Queries that violate policies will be blocked.");

        try {
            // This demonstrates that even connector queries go through policy checks
            ConnectorQuery query = ConnectorQuery.builder()
                .connectorId("database")
                .operation("SELECT * FROM users WHERE 1=1; DROP TABLE users;--")
                .userToken("user-123")
                .build();

            ConnectorResponse response = axonflow.queryConnector(query);

            if (!response.isSuccess()) {
                String error = response.getError();
                if (error != null && (error.contains("blocked") || error.contains("policy") ||
                    error.contains("DROP TABLE") || error.contains("dangerous"))) {
                    System.out.println("Status: BLOCKED by policy (expected behavior)");
                    System.out.printf("Reason: %s%n", error);
                } else {
                    System.out.println("Status: FAILED");
                    System.out.printf("Error: %s%n", error);
                }
            } else {
                System.out.println("Status: Query allowed");
                System.out.printf("Response: %s%n", response.getData());
            }
        } catch (Exception e) {
            String error = e.getMessage();
            if (error != null && (error.contains("blocked") || error.contains("policy") ||
                error.contains("DROP TABLE") || error.contains("dangerous"))) {
                System.out.println("Status: BLOCKED by policy (expected behavior)");
                System.out.printf("Reason: %s%n", error);
            } else {
                System.out.println("Status: Connector not available");
                System.out.printf("Error: %s%n", error);
            }
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println("Java MCP Connector Test: COMPLETE");
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
