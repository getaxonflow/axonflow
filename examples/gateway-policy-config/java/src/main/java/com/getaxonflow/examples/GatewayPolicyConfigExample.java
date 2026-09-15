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
 * This example sends test queries through the Gateway mode API
 * (getPolicyApprovedContext + proxyLLMCall) and checks that the Agent responds
 * according to the shipped policy actions.
 *
 * v11: the stored policy action decides. GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION,
 * PII_ACTION and SQLI_ACTION no longer set an action (ignored, with a boot WARN).
 * The shipped request-phase actions exercised here:
 *   sys_pii_ssn = warn (approved, policy id in getPolicies())
 *   sys_sqli_*  = warn (approved, policy id in getPolicies())
 *
 * To change an outcome, record an organization override (customer portal API,
 * Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
 * or change the policy's action. This example validates the shipped actions with
 * no override recorded.
 *
 * Still read from the environment (a non-action knob, must match Agent config):
 *   GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)
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

    private static boolean hasPolicyPrefix(List<String> policies, String prefix) {
        return policies != null && policies.stream().anyMatch(p -> p.startsWith(prefix));
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

        // Detection actions come from the stored policy rows (no org override
        // recorded), not from the environment.
        String policiesEnabled = getEnv("GATEWAY_STATIC_POLICIES_ENABLED", "true").toLowerCase();

        System.out.println("Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)");
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
        // Test 2: PII query (SSN) -- sys_pii_ssn stores warn for the request phase
        // -----------------------------------------------------------
        System.out.println("Test 2: PII Query (SSN '123-45-6789')");
        System.out.println("--------------------------------------");
        System.out.println("  Expected action: warn (stored)");

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
            // warn approves the request and reports the matched policy
            boolean piiApproved = !piiBlocked && result != null && result.isApproved();
            assertCheck(piiApproved, "PII approved with a warning (stored action: warn)");
            assertCheck(
                result != null && hasPolicyPrefix(result.getPolicies(), "sys_pii_"),
                "PII policy detected (sys_pii_* in policies)"
            );
            if (result != null && result.getPolicies() != null) {
                System.out.printf("   Policies: %s%n", result.getPolicies());
            }
            if (!piiApproved) {
                String reason = piiBlockReason != null ? piiBlockReason : (result != null ? result.getBlockReason() : "");
                System.out.printf("   Block reason: %s (an org pii=block override or an edited policy action is in force)%n", reason);
            }
        }
        System.out.println();

        // -----------------------------------------------------------
        // Test 3: SQLi query -- every sys_sqli_* policy stores warn
        // -----------------------------------------------------------
        System.out.println("Test 3: SQLi Query (UNION SELECT)");
        System.out.println("----------------------------------");
        System.out.println("  Expected action: warn (stored)");

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
            // SQL injection warns by default; it is not blocked
            boolean sqliApproved = !sqliBlocked && result != null && result.isApproved();
            assertCheck(sqliApproved, "SQLi approved with a warning (stored action: warn)");
            assertCheck(
                result != null && hasPolicyPrefix(result.getPolicies(), "sys_sqli_"),
                "SQLi policy detected (sys_sqli_* in policies)"
            );
            if (result != null && result.getPolicies() != null) {
                System.out.printf("   Policies: %s%n", result.getPolicies());
            }
            if (!sqliApproved) {
                String sqliReason = sqliBlockReason != null ? sqliBlockReason : (result != null ? result.getBlockReason() : "");
                System.out.printf("   Block reason: %s (an org sqli=block override or an edited policy action is in force)%n", sqliReason);
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
            System.out.printf("  shipped stored actions (PII warn, SQLi warn), enabled=%s%n",
                policiesEnabled);
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
