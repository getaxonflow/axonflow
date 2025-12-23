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
import com.getaxonflow.sdk.types.RequestType;
import com.getaxonflow.sdk.exceptions.AxonFlowException;

import java.util.Map;

/**
 * AxonFlow MAP (Multi-Agent Planning) Example - Java SDK
 *
 * Multi-Agent Planning allows you to orchestrate complex AI workflows
 * by having AxonFlow break down a goal into multiple steps and execute them.
 */
public class MapExample {

    public static void main(String[] args) {
        System.out.println("AxonFlow MAP Example - Java");
        System.out.println("==================================================");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // Simple query for testing
        String query = "Create a brief plan to greet a new user and ask how to help them";
        String domain = "generic";

        System.out.println("Query: " + query);
        System.out.println("Domain: " + domain);
        System.out.println("--------------------------------------------------");
        System.out.println();

        long startTime = System.currentTimeMillis();

        try {
            // Generate a plan using executeQuery with multi-agent-plan request type
            ClientRequest request = ClientRequest.builder()
                .query(query)
                .userToken("user-123")
                .clientId("map-example")
                .requestType(RequestType.MULTI_AGENT_PLAN)
                .context(Map.of("domain", domain))
                .build();

            ClientResponse response = client.executeQuery(request);
            long duration = System.currentTimeMillis() - startTime;

            if (response.isSuccess() && !response.isBlocked()) {
                System.out.println("✅ Plan Generated Successfully");
                System.out.println("Duration: " + duration + "ms");

                Object data = response.getData();
                if (data != null) {
                    String dataStr = data.toString();
                    System.out.println();
                    System.out.println("Response:");
                    // Print first 500 chars
                    if (dataStr.length() > 500) {
                        System.out.println(dataStr.substring(0, 500) + "...");
                    } else {
                        System.out.println(dataStr);
                    }
                } else if (response.getResult() != null) {
                    System.out.println();
                    System.out.println("Response:");
                    System.out.println(response.getResult());
                }

                System.out.println();
                System.out.println("==================================================");
                System.out.println("✅ Java MAP Test: PASS");
            } else if (response.isBlocked()) {
                System.out.println("❌ Request blocked: " + response.getBlockReason());
                System.out.println();
                System.out.println("==================================================");
                System.out.println("❌ Java MAP Test: FAIL (blocked)");
                System.exit(1);
            } else {
                System.out.println("❌ Request failed: " + response.getError());
                System.out.println();
                System.out.println("==================================================");
                System.out.println("❌ Java MAP Test: FAIL");
                System.exit(1);
            }

        } catch (AxonFlowException e) {
            System.err.println("❌ AxonFlow Error: " + e.getMessage());
            System.out.println();
            System.out.println("==================================================");
            System.out.println("❌ Java MAP Test: FAIL");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
            System.out.println();
            System.out.println("==================================================");
            System.out.println("❌ Java MAP Test: FAIL");
            System.exit(1);
        }
    }

    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
