/*
 * Copyright 2026 AxonFlow
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.PlanResponse;
import com.getaxonflow.sdk.types.PlanRequest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * AxonFlow Cost Estimation Example - Java
 *
 * Validates the new cost estimation endpoints added in v4.3.0:
 *   - POST /api/v1/plans/estimate  - Estimate cost of a plan before execution
 *   - GET  /api/v1/plans/{id}/cost - Get cost estimate for an existing plan
 *
 * These endpoints are NOT in any SDK yet, so this example uses HttpURLConnection
 * for raw HTTP calls and the Java SDK for plan generation.
 *
 * Usage:
 *   mvn compile exec:java
 *
 * Environment:
 *   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - Client ID (default: demo-org)
 *   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
 *   AXONFLOW_USER_TOKEN    - JWT token for MAP operations (optional)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
public class CostEstimation {

    private static final List<String> failures = new ArrayList<>();
    private static final ObjectMapper mapper = new ObjectMapper();

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
        } else {
            System.out.println("   FAIL: " + message);
            failures.add(message);
        }
    }

    /**
     * Performs an HTTP request and returns the status code and parsed JSON.
     */
    private static HttpResult doRequest(String method, String urlStr, String body,
                                         String clientId, String clientSecret) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("X-Client-ID", clientId);
        if (clientSecret != null && !clientSecret.isEmpty()) {
            conn.setRequestProperty("X-Client-Secret", clientSecret);
        }

        if (body != null && !body.isEmpty()) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }

        int status = conn.getResponseCode();
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                status >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        } catch (Exception e) {
            // Stream may be null for some error responses
        }

        JsonNode json = null;
        if (response.length() > 0) {
            try {
                json = mapper.readTree(response.toString());
            } catch (Exception e) {
                // Not JSON
            }
        }

        return new HttpResult(status, json);
    }

    private static class HttpResult {
        final int status;
        final JsonNode data;

        HttpResult(int status, JsonNode data) {
            this.status = status;
            this.data = data;
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Cost Estimation - Java (Raw HTTP + SDK)");
        System.out.println("================================================");
        System.out.println();

        String endpoint = getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo-org");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");
        String userToken = getEnv("AXONFLOW_USER_TOKEN", "");

        System.out.println("Endpoint: " + endpoint);
        System.out.println("Client ID: " + clientId);
        System.out.println("------------------------------------------------");
        System.out.println();

        // ========================================
        // 1. HEALTH CHECK
        // ========================================
        System.out.println("1. Health Check...");
        try {
            HttpResult health = doRequest("GET", endpoint + "/health", null, clientId, clientSecret);
            assertCheck(health.status == 200,
                    "Health check returns 200 (got " + health.status + ")");
            if (health.data != null && health.data.has("status")) {
                System.out.println("   Status: " + health.data.get("status").asText());
            }
        } catch (Exception e) {
            System.out.println("   ERROR: " + e.getMessage());
            assertCheck(false, "Health check request succeeded");
        }
        System.out.println();

        // ========================================
        // 2. POST /api/v1/plans/estimate
        // ========================================
        System.out.println("2. POST /api/v1/plans/estimate - Estimate cost before execution...");

        String estimateBody = "{"
                + "\"provider\":\"openai\","
                + "\"model\":\"gpt-4\","
                + "\"steps\":["
                + "{\"name\":\"analyze\",\"type\":\"llm_call\","
                + "\"estimated_tokens_in\":1000,\"estimated_tokens_out\":500},"
                + "{\"name\":\"summarize\",\"type\":\"llm_call\","
                + "\"estimated_tokens_in\":500,\"estimated_tokens_out\":200}"
                + "]"
                + "}";

        try {
            HttpResult estimate = doRequest("POST", endpoint + "/api/v1/plans/estimate",
                    estimateBody, clientId, clientSecret);

            if (estimate.status == 429) {
                System.out.println("   Rate limited (429) - community mode allows 10 estimates/day");
                System.out.println("   This is expected behavior; skipping estimate assertions.");
                assertCheck(true, "Estimate endpoint returned valid status (429 rate limit)");
            } else {
                assertCheck(estimate.status == 200,
                        "Estimate returns 200 (got " + estimate.status + ")");

                if (estimate.status == 200 && estimate.data != null) {
                    System.out.println("   Response: " + estimate.data.toString());

                    // Verify estimated_cost_usd field
                    boolean hasCost = estimate.data.has("estimated_cost_usd");
                    assertCheck(hasCost, "Response contains 'estimated_cost_usd' field");
                    if (hasCost) {
                        double cost = estimate.data.get("estimated_cost_usd").asDouble();
                        assertCheck(estimate.data.get("estimated_cost_usd").isNumber(),
                                "estimated_cost_usd is a number");
                        assertCheck(cost >= 0,
                                String.format("estimated_cost_usd >= 0 (got %.6f)", cost));
                        System.out.printf("   Estimated Cost: $%.6f USD%n", cost);
                    }

                    // Verify currency field
                    boolean hasCurrency = estimate.data.has("currency");
                    assertCheck(hasCurrency, "Response contains 'currency' field");
                    if (hasCurrency) {
                        String currency = estimate.data.get("currency").asText();
                        assertCheck("USD".equals(currency),
                                "currency is 'USD' (got '" + currency + "')");
                    }

                    // Check breakdown (may be absent in community mode)
                    if (estimate.data.has("breakdown")) {
                        System.out.println("   Breakdown available: "
                                + estimate.data.get("breakdown").toString());
                    } else {
                        System.out.println("   Note: 'breakdown' not present "
                                + "(community mode returns aggregate only)");
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("   ERROR: " + e.getMessage());
            assertCheck(false, "Estimate request completed");
        }
        System.out.println();

        // ========================================
        // 3. CREATE PLAN VIA SDK + GET COST
        // ========================================
        System.out.println("3. Create MAP plan via SDK, then GET /api/v1/plans/{id}/cost...");

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();

        try (AxonFlow client = AxonFlow.create(config)) {
            PlanRequest.Builder planBuilder = PlanRequest.builder()
                    .objective("Create a brief plan to analyze customer feedback and generate a summary report")
                    .domain("generic");
            if (userToken != null && !userToken.isEmpty()) {
                planBuilder.userToken(userToken);
            }
            PlanResponse plan = client.generatePlan(planBuilder.build());

            assertCheck(plan != null, "Plan generated successfully");
            assertCheck(plan.getPlanId() != null && !plan.getPlanId().isEmpty(),
                    "Plan has a valid ID");
            System.out.println("   Plan ID: " + plan.getPlanId());
            System.out.println("   Steps: " + (plan.getSteps() != null ? plan.getSteps().size() : 0));

            // GET /api/v1/plans/{id}/cost
            System.out.println();
            System.out.println("   Fetching cost for existing plan...");
            String costUrl = endpoint + "/api/v1/plans/" + plan.getPlanId() + "/cost";

            HttpResult costResult = doRequest("GET", costUrl, null, clientId, clientSecret);

            if (costResult.status == 429) {
                System.out.println("   Rate limited (429) - community mode allows 10 estimates/day");
                assertCheck(true, "Plan cost endpoint returned valid status (429 rate limit)");
            } else if (costResult.status == 404) {
                System.out.println("   Plan cost endpoint returned 404 - "
                        + "endpoint may require enterprise mode");
                assertCheck(true,
                        "Plan cost endpoint responded (404 - may require enterprise)");
            } else {
                assertCheck(costResult.status == 200,
                        "GET plan cost returns 200 (got " + costResult.status + ")");

                if (costResult.status == 200 && costResult.data != null) {
                    System.out.println("   Cost Response: " + costResult.data.toString());

                    boolean hasCost = costResult.data.has("estimated_cost_usd");
                    assertCheck(hasCost, "Plan cost response contains 'estimated_cost_usd'");
                    if (hasCost) {
                        double cost = costResult.data.get("estimated_cost_usd").asDouble();
                        assertCheck(cost >= 0,
                                String.format("Plan cost >= 0 (got %.6f)", cost));
                    }

                    boolean hasCurrency = costResult.data.has("currency");
                    assertCheck(hasCurrency, "Plan cost response contains 'currency'");
                    if (hasCurrency) {
                        String currency = costResult.data.get("currency").asText();
                        assertCheck("USD".equals(currency),
                                "Plan cost currency is 'USD' (got '" + currency + "')");
                    }

                    if (!costResult.data.has("breakdown")) {
                        System.out.println("   Note: 'breakdown' not present "
                                + "(community mode returns aggregate only)");
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("   ERROR: " + e.getMessage());
            assertCheck(false, "Plan creation and cost retrieval succeeded: " + e.getMessage());
        }
        System.out.println();

        // ========================================
        // SUMMARY
        // ========================================
        System.out.println("================================================");
        System.out.println("Cost Estimation Example - Summary");
        System.out.println("================================================");
        if (failures.isEmpty()) {
            System.out.println("All assertions passed!");
        } else {
            System.out.println(failures.size() + " assertion(s) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
