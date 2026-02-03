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
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.types.RequestType;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.ArrayList;
import java.util.List;

/**
 * AxonFlow Gateway Policy Configuration - Java SDK
 *
 * This example demonstrates and VALIDATES per-mode Gateway policy configuration.
 * AxonFlow's static policies can be configured per-mode using environment variables.
 * This example validates the CURRENT configuration by sending test queries through
 * the Gateway mode API (getPolicyApprovedContext + proxyLLMCall) and checking that
 * the Agent responds according to the configured policy actions.
 *
 * Environment variables (must match Agent-side config):
 *   GATEWAY_PII_ACTION   = block | redact | log  (default: redact)
 *   GATEWAY_SQLI_ACTION  = block | warn | log    (default: block)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class GatewayPolicyConfigExample {

    private static final List<String> failures = new ArrayList<>();

    @SuppressWarnings("unchecked")
    private static String extractResponseText(ClientResponse resp) {
        // The API returns data as {"data": "text...", "metadata": {...}}
        // getResult() is for planning; getData() holds the proxy response
        if (resp.getResult() != null && !resp.getResult().isEmpty()) {
            return resp.getResult();
        }
        Object data = resp.getData();
        if (data instanceof java.util.Map) {
            Object inner = ((java.util.Map<String, Object>) data).get("data");
            if (inner instanceof String) {
                return (String) inner;
            }
        }
        if (data instanceof String) {
            return (String) data;
        }
        return data != null ? data.toString() : null;
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static String getEnvWithFallback(String key, String fallbackKey, String defaultValue) {
        String value = System.getenv(key);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        value = System.getenv(fallbackKey);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   \u274C FAIL: " + message);
        } else {
            System.out.println("   \u2713 PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Gateway Policy Configuration - Java SDK");
        System.out.println("=================================================");
        System.out.println();

        // Read expected policy actions (with fallback keys, matching Go version)
        String piiAction = getEnvWithFallback("GATEWAY_PII_ACTION", "PII_ACTION", "redact").toLowerCase();
        String sqliAction = getEnvWithFallback("GATEWAY_SQLI_ACTION", "SQLI_ACTION", "block").toLowerCase();
        String policiesEnabled = getEnv("GATEWAY_STATIC_POLICIES_ENABLED", "true").toLowerCase();

        System.out.printf("Expected PII_ACTION:  %s%n", piiAction);
        System.out.printf("Expected SQLI_ACTION: %s%n", sqliAction);
        System.out.printf("Static policies enabled: %s%n", policiesEnabled);
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        // -----------------------------------------------------------
        // Test 1: Safe query -- always approved
        // -----------------------------------------------------------
        System.out.println("Test 1: Safe Query Pre-Check");
        System.out.println("----------------------------");

        PolicyApprovalResult result;
        try {
            result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .userToken("")
                    .query("What are the best practices for deploying AI models?")
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: getPolicyApprovedContext failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(result.isApproved(), "Safe query is approved");
        assertCheck(result.getContextId() != null && !result.getContextId().isEmpty(), "Context ID returned");
        System.out.println();

        // -----------------------------------------------------------
        // Test 2: PII query (SSN) -- depends on GATEWAY_PII_ACTION
        // -----------------------------------------------------------
        System.out.println("Test 2: PII Query (SSN '123-45-6789')");
        System.out.println("--------------------------------------");
        System.out.printf("  Expected action: %s%n", piiAction);

        boolean piiBlocked = false;
        String piiBlockReason = null;
        try {
            result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .userToken("")
                    .query("Look up the customer with SSN 123-45-6789 and return their balance")
                    .build()
            );
        } catch (PolicyViolationException e) {
            // SDK throws PolicyViolationException when request is blocked
            piiBlocked = true;
            piiBlockReason = e.getMessage();
            result = null;
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: Pre-check failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        if ("false".equals(policiesEnabled)) {
            assertCheck(result != null && result.isApproved(), "PII approved (static policies disabled)");
            assertCheck(
                result == null || result.getPolicies() == null || result.getPolicies().isEmpty(),
                "No policies matched (disabled)"
            );
        } else {
            switch (piiAction) {
                case "block":
                    assertCheck(piiBlocked || (result != null && !result.isApproved()), "PII blocked (GATEWAY_PII_ACTION=block)");
                    assertCheck(
                        piiBlockReason != null || (result != null && result.getBlockReason() != null && !result.getBlockReason().isEmpty()),
                        "Block reason provided"
                    );
                    String reason = piiBlockReason != null ? piiBlockReason : (result != null ? result.getBlockReason() : "");
                    System.out.printf("   Block reason: %s%n", reason);
                    break;
                case "redact":
                    assertCheck(result.isApproved(), "PII approved for redaction (GATEWAY_PII_ACTION=redact)");
                    assertCheck(
                        result.getPolicies() != null && !result.getPolicies().isEmpty(),
                        "PII policies detected"
                    );
                    if (result.getPolicies() != null) {
                        System.out.printf("   Policies: %s%n", result.getPolicies());
                    }
                    break;
                case "warn":
                    assertCheck(result.isApproved(), "PII approved with warning (GATEWAY_PII_ACTION=warn)");
                    assertCheck(
                        result.getPolicies() != null && !result.getPolicies().isEmpty(),
                        "PII policies detected"
                    );
                    break;
                case "log":
                    assertCheck(result.isApproved(), "PII approved (GATEWAY_PII_ACTION=log)");
                    break;
                default:
                    System.out.println("   \u274C Unknown GATEWAY_PII_ACTION: " + piiAction);
                    failures.add("Unknown GATEWAY_PII_ACTION: " + piiAction);
            }
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 3: SQLi query -- depends on GATEWAY_SQLI_ACTION
        // -----------------------------------------------------------
        System.out.println("Test 3: SQLi Query (UNION SELECT)");
        System.out.println("----------------------------------");
        System.out.printf("  Expected action: %s%n", sqliAction);

        boolean sqliBlocked = false;
        String sqliBlockReason = null;
        try {
            result = client.getPolicyApprovedContext(
                PolicyApprovalRequest.builder()
                    .userToken("")
                    .query("Run this: SELECT name FROM users UNION SELECT password FROM admin_users")
                    .build()
            );
        } catch (PolicyViolationException e) {
            sqliBlocked = true;
            sqliBlockReason = e.getMessage();
            result = null;
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: Pre-check failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        if ("false".equals(policiesEnabled)) {
            assertCheck(result != null && result.isApproved(), "SQLi approved (static policies disabled)");
        } else {
            switch (sqliAction) {
                case "block":
                    assertCheck(sqliBlocked || (result != null && !result.isApproved()), "SQLi blocked (GATEWAY_SQLI_ACTION=block)");
                    assertCheck(
                        sqliBlockReason != null || (result != null && result.getBlockReason() != null && !result.getBlockReason().isEmpty()),
                        "Block reason provided"
                    );
                    String sqliReason = sqliBlockReason != null ? sqliBlockReason : (result != null ? result.getBlockReason() : "");
                    System.out.printf("   Block reason: %s%n", sqliReason);
                    break;
                case "warn":
                    assertCheck(result != null && result.isApproved(), "SQLi approved with warning (GATEWAY_SQLI_ACTION=warn)");
                    break;
                case "log":
                    assertCheck(result != null && result.isApproved(), "SQLi approved (GATEWAY_SQLI_ACTION=log)");
                    break;
                default:
                    System.out.println("   \u274C Unknown GATEWAY_SQLI_ACTION: " + sqliAction);
                    failures.add("Unknown GATEWAY_SQLI_ACTION: " + sqliAction);
            }
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 4: ProxyLLMCall -- end-to-end governed LLM call
        // -----------------------------------------------------------
        System.out.println("Test 4: ProxyLLMCall (End-to-End)");
        System.out.println("---------------------------------");

        ClientResponse llmResp;
        try {
            llmResp = client.proxyLLMCall(ClientRequest.builder()
                .userToken("")
                .query("Explain cloud computing in one sentence.")
                .requestType(RequestType.CHAT)
                .build()
            );
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: proxyLLMCall failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(llmResp.isSuccess(), "ProxyLLMCall succeeded");
        assertCheck(!llmResp.isBlocked(), "Safe LLM call was not blocked");
        String responseText = extractResponseText(llmResp);
        assertCheck(
            responseText != null && !responseText.isEmpty(),
            "LLM response is not empty"
        );
        if (responseText != null) {
            String preview = responseText.length() > 80
                ? responseText.substring(0, 80)
                : responseText;
            System.out.printf("   Response: %s...%n", preview);
        }
        System.out.println();

        // -----------------------------------------------------------
        // Summary
        // -----------------------------------------------------------
        System.out.println("=================================================");
        if (failures.isEmpty()) {
            System.out.println("\u2713 ALL TESTS PASSED");
            System.out.println();
            System.out.printf("Gateway policy config validated:%n");
            System.out.printf("  PII_ACTION=%s, SQLI_ACTION=%s, enabled=%s%n",
                piiAction, sqliAction, policiesEnabled);
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
