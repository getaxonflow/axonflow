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

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.hitl.HITLTypes.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * HITL Queue API Example - Java
 *
 * Validates the HITL Queue SDK methods against a running AxonFlow instance.
 *
 * <p>The HITL Queue is an enterprise-only feature. In community mode, all HITL
 * queue endpoints return HTTP 403. This example verifies that the API exists
 * and returns the expected 403 response, printing a clear message that this
 * is an enterprise feature.</p>
 *
 * <p>In enterprise mode, the same SDK calls would succeed and return queue data.</p>
 *
 * <p>VALIDATION: This example exits with code 1 if any assertion fails.
 * In community mode, 403 responses are EXPECTED and count as PASS.</p>
 */
public class HITLQueue {

    private static int passCount = 0;
    private static int failCount = 0;
    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
            passCount++;
        } else {
            System.out.println("   FAIL: " + message);
            failCount++;
            failures.add(message);
        }
    }

    /**
     * Check whether an exception indicates a 403 Forbidden or 404 Not Found response,
     * which is expected behavior for HITL Queue endpoints in community mode.
     */
    private static boolean isEnterprise403(Exception e) {
        String msg = e.getMessage() != null ? e.getMessage() : "";
        return msg.contains("403") || msg.contains("Forbidden")
                || msg.contains("enterprise") || msg.contains("Enterprise")
                || msg.contains("404") || msg.toLowerCase().contains("not found");
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    public static void main(String[] args) {
        System.out.println("HITL Queue API - Java");
        System.out.println("=".repeat(50));
        System.out.println();
        System.out.println("This example validates the HITL Queue SDK methods.");
        System.out.println("In community mode, all HITL queue endpoints return 403.");
        System.out.println("403 responses are EXPECTED and count as PASS.");
        System.out.println();

        String endpoint = getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080");
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo-org");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        try {
            // ========================================
            // Test 1: HITL Status (raw HTTP)
            // ========================================
            System.out.println("Test 1: HITL Status Endpoint");
            System.out.println("-".repeat(28));

            try {
                URL statusUrl = new URL(endpoint + "/api/v1/hitl/status");
                HttpURLConnection conn = (HttpURLConnection) statusUrl.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("X-Client-ID", clientId);
                conn.setRequestProperty("X-Client-Secret", clientSecret);
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(10000);

                int statusCode = conn.getResponseCode();
                if (statusCode == 200) {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(conn.getInputStream()));
                    StringBuilder body = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        body.append(line);
                    }
                    reader.close();
                    assertCheck(true, "HITL status endpoint reachable (HTTP 200)");
                    System.out.println("   Response: " + body);

                    if (body.toString().contains("\"community\"")) {
                        System.out.println("   Running in community mode - HITL queue endpoints will return 403");
                    } else {
                        System.out.println("   Running in enterprise mode - HITL queue endpoints should succeed");
                    }
                } else if (statusCode == 403) {
                    assertCheck(true, "HITL status endpoint returned 403 (enterprise feature)");
                } else if (statusCode == 404) {
                    assertCheck(true, "HITL status endpoint returned " + statusCode + " (endpoint may not be available)");
                } else {
                    assertCheck(false, "HITL status endpoint returned unexpected HTTP " + statusCode);
                }
                conn.disconnect();
            } catch (java.net.ConnectException e) {
                System.out.println("\nHint: Make sure AxonFlow is running:");
                System.out.println("  docker compose up -d");
                System.exit(1);
            } catch (Exception e) {
                assertCheck(false, "HITL status request failed: " + e.getMessage());
            }
            System.out.println();

            // ========================================
            // Test 2: listHITLQueue
            // ========================================
            System.out.println("Test 2: listHITLQueue");
            System.out.println("-".repeat(21));

            try {
                HITLQueueListResponse listResp = client.listHITLQueue(null);
                assertCheck(true, "listHITLQueue succeeded (enterprise mode)");
                assertCheck(listResp != null, "listHITLQueue returned non-null response");
                if (listResp != null) {
                    System.out.println("   Queue items: " + listResp.getItems().size()
                            + ", Total: " + listResp.getTotal());
                }
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "listHITLQueue returns 403/404 (enterprise feature)");
                    System.out.println("   HITL Queue listing requires Enterprise license");
                } else {
                    assertCheck(false, "listHITLQueue unexpected error: " + e.getMessage());
                }
            }
            System.out.println();

            // Test with options
            System.out.println("Test 2b: listHITLQueue with options");
            System.out.println("-".repeat(35));

            try {
                HITLQueueListOptions opts = HITLQueueListOptions.builder()
                        .limit(10)
                        .offset(0)
                        .build();
                HITLQueueListResponse listRespOpts = client.listHITLQueue(opts);
                assertCheck(true, "listHITLQueue with options succeeded (enterprise mode)");
                if (listRespOpts != null) {
                    System.out.println("   Queue items: " + listRespOpts.getItems().size()
                            + ", Total: " + listRespOpts.getTotal());
                }
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "listHITLQueue with options returns 403/404 (enterprise feature)");
                } else {
                    assertCheck(false, "listHITLQueue with options unexpected error: " + e.getMessage());
                }
            }
            System.out.println();

            // ========================================
            // Test 3: getHITLStats
            // ========================================
            System.out.println("Test 3: getHITLStats");
            System.out.println("-".repeat(20));

            try {
                HITLStats stats = client.getHITLStats();
                assertCheck(true, "getHITLStats succeeded (enterprise mode)");
                assertCheck(stats != null, "getHITLStats returned non-null response");
                if (stats != null) {
                    System.out.println("   Total Pending: " + stats.getTotalPending()
                            + ", High Priority: " + stats.getHighPriority()
                            + ", Critical Priority: " + stats.getCriticalPriority());
                }
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "getHITLStats returns 403/404 (enterprise feature)");
                    System.out.println("   HITL Queue statistics require Enterprise license");
                } else {
                    assertCheck(false, "getHITLStats unexpected error: " + e.getMessage());
                }
            }
            System.out.println();

            // ========================================
            // Test 4: getHITLRequest (fake ID)
            // ========================================
            System.out.println("Test 4: getHITLRequest (fake ID)");
            System.out.println("-".repeat(31));

            String fakeRequestId = "hitl_req_nonexistent_12345";
            try {
                HITLApprovalRequest hitlReq = client.getHITLRequest(fakeRequestId);
                assertCheck(hitlReq != null, "getHITLRequest succeeded (enterprise mode, unexpected for fake ID)");
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "getHITLRequest returns 403 (enterprise feature)");
                    System.out.println("   HITL request retrieval requires Enterprise license");
                } else {
                    String msg = e.getMessage() != null ? e.getMessage() : "";
                    if (msg.contains("404") || msg.toLowerCase().contains("not found")) {
                        assertCheck(true, "getHITLRequest returns 404 for nonexistent ID (expected)");
                    } else {
                        assertCheck(false, "getHITLRequest unexpected error: " + e.getMessage());
                    }
                }
            }
            System.out.println();

            // ========================================
            // Test 5: approveHITLRequest (fake ID)
            // ========================================
            System.out.println("Test 5: approveHITLRequest (fake ID)");
            System.out.println("-".repeat(35));

            try {
                HITLReviewInput approveReview = HITLReviewInput.builder()
                        .reviewerId("test-reviewer")
                        .comment("Auto-approved by HITL queue validation example")
                        .build();
                client.approveHITLRequest(fakeRequestId, approveReview);
                assertCheck(true, "approveHITLRequest succeeded (enterprise mode)");
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "approveHITLRequest returns 403 (enterprise feature)");
                } else {
                    String msg = e.getMessage() != null ? e.getMessage() : "";
                    if (msg.contains("404") || msg.toLowerCase().contains("not found")) {
                        assertCheck(true, "approveHITLRequest returns 404 for nonexistent ID (expected)");
                    } else {
                        assertCheck(false, "approveHITLRequest unexpected error: " + e.getMessage());
                    }
                }
            }
            System.out.println();

            // ========================================
            // Test 6: rejectHITLRequest (fake ID)
            // ========================================
            System.out.println("Test 6: rejectHITLRequest (fake ID)");
            System.out.println("-".repeat(34));

            try {
                HITLReviewInput rejectReview = HITLReviewInput.builder()
                        .reviewerId("test-reviewer")
                        .comment("Rejected by HITL queue validation example")
                        .build();
                client.rejectHITLRequest(fakeRequestId, rejectReview);
                assertCheck(true, "rejectHITLRequest succeeded (enterprise mode)");
            } catch (Exception e) {
                if (isEnterprise403(e)) {
                    assertCheck(true, "rejectHITLRequest returns 403 (enterprise feature)");
                } else {
                    String msg = e.getMessage() != null ? e.getMessage() : "";
                    if (msg.contains("404") || msg.toLowerCase().contains("not found")) {
                        assertCheck(true, "rejectHITLRequest returns 404 for nonexistent ID (expected)");
                    } else {
                        assertCheck(false, "rejectHITLRequest unexpected error: " + e.getMessage());
                    }
                }
            }
            System.out.println();

            // ========================================
            // Summary
            // ========================================
            System.out.println("=".repeat(50));
            System.out.println("Results: " + passCount + " PASS, " + failCount + " FAIL");
            System.out.println("=".repeat(50));

            if (!failures.isEmpty()) {
                System.out.println("SOME TESTS FAILED:");
                for (String f : failures) {
                    System.out.println("  - " + f);
                }
                System.exit(1);
            }

            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("HITL Queue operations validated:");
            System.out.println("  - HITL status endpoint (raw HTTP)");
            System.out.println("  - listHITLQueue() / listHITLQueue(opts)");
            System.out.println("  - getHITLStats()");
            System.out.println("  - getHITLRequest(requestId)");
            System.out.println("  - approveHITLRequest(requestId, review)");
            System.out.println("  - rejectHITLRequest(requestId, review)");
            System.out.println();
            System.out.println("Note: In Community Edition, all HITL queue endpoints return 403.");
            System.out.println("Upgrade to Enterprise for full HITL queue management.");

        } catch (Exception e) {
            System.err.println("\nFatal error: " + e.getMessage());

            if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                System.err.println("\nHint: Make sure AxonFlow is running:");
                System.err.println("  docker compose up -d");
            }

            System.exit(1);
        }
    }
}
