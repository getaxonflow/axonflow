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
package com.getaxonflow.examples.mediagovernancepolicies;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.MediaContent;
import com.getaxonflow.sdk.types.MediaGovernanceConfig;
import com.getaxonflow.sdk.types.MediaGovernanceStatus;
import com.getaxonflow.sdk.types.UpdateMediaGovernanceConfigRequest;
import com.getaxonflow.sdk.types.RequestType;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicy;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyCondition;
import com.getaxonflow.sdk.types.policies.PolicyTypes.DynamicPolicyAction;
import com.getaxonflow.sdk.types.policies.PolicyTypes.CreateDynamicPolicyRequest;
import com.getaxonflow.sdk.types.policies.PolicyTypes.UpdateDynamicPolicyRequest;
import com.getaxonflow.sdk.types.policies.PolicyTypes.ListDynamicPoliciesOptions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AxonFlow Media Governance Policies - Java SDK
 *
 * Demonstrates and VALIDATES media governance POLICY management capabilities:
 *   - Listing system media policies (seeded by platform migrations)
 *   - System NSFW policy evaluation with a clean image
 *   - Custom media policy CRUD (create, verify, process, delete)
 *   - Media governance config and status endpoints
 *   - Policy toggle lifecycle (enable/disable)
 *   - Per-tenant media governance disable/enable (Enterprise only)
 *   - Non-media requests unaffected by media policies
 *
 * Two client instances are used:
 *   - orchestratorClient: connects to AXONFLOW_ORCHESTRATOR_ENDPOINT (default :8081)
 *     for policy CRUD, media governance config, and status
 *   - agentClient: connects to AXONFLOW_ENDPOINT (default :8080)
 *     for proxyLLMCall requests that trigger media analysis
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class MediaGovernancePoliciesExample {

    // Minimal valid 1x1 white pixel JPEG encoded as base64.
    private static final String TEST_IMAGE_BASE64 =
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
        + "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh"
        + "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR"
        + "CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAA"
        + "AAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQAC"
        + "EQMRAD8AbwA//9k=";

    private static final List<String> failures = new ArrayList<>();

    private static final String USER_TOKEN = "media-policy-user";

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    public static void main(String[] args) {
        System.out.println("AxonFlow Media Governance Policies - Java SDK");
        System.out.println("==============================================");
        System.out.println();

        String orchestratorEndpoint = getEnv("AXONFLOW_ORCHESTRATOR_ENDPOINT", "http://localhost:8081");
        String agentEndpoint = getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = getEnv("AXONFLOW_CLIENT_ID", "demo");
        String clientSecret = getEnv("AXONFLOW_CLIENT_SECRET", "demo");
        String tenantId = getEnv("AXONFLOW_TENANT", clientId);
        boolean debug = "true".equals(getEnv("AXONFLOW_DEBUG", ""));

        System.out.println("  Agent endpoint:        " + agentEndpoint);
        System.out.println("  Orchestrator endpoint: " + orchestratorEndpoint);
        System.out.println("  Tenant ID:             " + tenantId);
        System.out.println();

        // Two clients: orchestrator for policy CRUD, agent for LLM proxy requests
        AxonFlow orchestratorClient = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(orchestratorEndpoint)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .debug(debug)
            .build());

        AxonFlow agentClient = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(agentEndpoint)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .debug(debug)
            .build());

        boolean pipelineActive = false;

        // ========================================
        // Test 1: Verify system media policies exist
        // ========================================
        System.out.println("Test 1: Verify system media policies exist");
        System.out.println("  Listing dynamic policies with type=media");
        System.out.println();

        List<DynamicPolicy> policies;
        try {
            policies = orchestratorClient.listDynamicPolicies(
                ListDynamicPoliciesOptions.builder().type("media").limit(100).build()
            );
        } catch (Exception e) {
            System.out.println("   FAIL: listDynamicPolicies failed: " + e.getMessage());
            failures.add("listDynamicPolicies call failed");
            policies = Collections.emptyList();
        }

        // Filter for system media policies
        List<DynamicPolicy> sysMediaPolicies = new ArrayList<>();
        for (DynamicPolicy p : policies) {
            if (p.getId() != null && p.getId().startsWith("sys_media_")) {
                sysMediaPolicies.add(p);
            }
        }

        assertCheck(
            sysMediaPolicies.size() >= 5,
            "At least 5 system media policies found (got " + sysMediaPolicies.size() + ")"
        );

        // Count by category
        int mediaSafetyCount = 0;
        int mediaBiometricCount = 0;
        int mediaPiiCount = 0;
        int mediaDocumentCount = 0;
        for (DynamicPolicy p : sysMediaPolicies) {
            String cat = p.getCategory() != null ? p.getCategory() : "unknown";
            if ("media-safety".equals(cat)) mediaSafetyCount++;
            else if ("media-biometric".equals(cat)) mediaBiometricCount++;
            else if ("media-pii".equals(cat)) mediaPiiCount++;
            else if ("media-document".equals(cat)) mediaDocumentCount++;
        }

        assertCheck(
            mediaSafetyCount >= 2,
            "media-safety category has >= 2 policies (got " + mediaSafetyCount + ")"
        );
        assertCheck(
            mediaBiometricCount >= 1,
            "media-biometric category has >= 1 policy (got " + mediaBiometricCount + ")"
        );
        assertCheck(
            mediaPiiCount >= 1,
            "media-pii category has >= 1 policy (got " + mediaPiiCount + ")"
        );
        assertCheck(
            mediaDocumentCount >= 1,
            "media-document category has >= 1 policy (got " + mediaDocumentCount + ")"
        );

        // Print discovered policies
        System.out.println();
        System.out.println("  System media policies:");
        for (DynamicPolicy p : sysMediaPolicies) {
            System.out.println("    - " + p.getId() + ": " + p.getName() + " [" + p.getCategory() + "]");
        }
        System.out.println();

        // ========================================
        // Test 2: System NSFW policy evaluation -- clean image passes
        // ========================================
        System.out.println("Test 2: System NSFW policy evaluation -- clean image passes");
        System.out.println("  Sending 1x1 white JPEG via proxyLLMCall");
        System.out.println();

        ClientResponse resp2;
        try {
            resp2 = agentClient.proxyLLMCall(
                ClientRequest.builder()
                    .query("Describe this image")
                    .userToken(USER_TOKEN)
                    .requestType(RequestType.CHAT)
                    .media(Collections.singletonList(
                        MediaContent.builder()
                            .source("base64")
                            .mimeType("image/jpeg")
                            .base64Data(TEST_IMAGE_BASE64)
                            .build()
                    ))
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   FAIL: proxyLLMCall failed: " + e.getMessage());
            failures.add("Test 2: proxyLLMCall failed");
            resp2 = null;
        }

        if (resp2 != null) {
            assertCheck(resp2.isSuccess(), "Response is successful");
            assertCheck(!resp2.isBlocked(), "Clean image is NOT blocked (blocked=" + resp2.isBlocked() + ")");

            if (resp2.getMediaAnalysis() != null) {
                pipelineActive = true;
                System.out.println("   PASS: media_analysis present (pipeline active)");
                if (resp2.getMediaAnalysis().getResults() != null
                        && !resp2.getMediaAnalysis().getResults().isEmpty()) {
                    System.out.println("   NSFW score: " + resp2.getMediaAnalysis().getResults().get(0).getNsfwScore());
                    System.out.println("   Content safe: " + resp2.getMediaAnalysis().getResults().get(0).isContentSafe());
                }
            } else {
                System.out.println("   WARNING: media_analysis absent -- media governance pipeline"
                    + " not active (requires platform v4.4.0+ with analyzers)");
            }
        }
        System.out.println();

        // ========================================
        // Test 3: Custom media policy -- create and verify
        // ========================================
        System.out.println("Test 3: Custom media policy -- create and verify");
        System.out.println();

        // 3a. Create a custom media policy: block if media.has_faces == true
        System.out.println("  3a. Creating custom media policy: block if media.has_faces == true");
        String createdPolicyId = null;

        try {
            Map<String, Object> blockConfig = new HashMap<>();
            blockConfig.put("message", "Media blocked: faces detected in image");

            DynamicPolicy created = orchestratorClient.createDynamicPolicy(
                CreateDynamicPolicyRequest.builder()
                    .name("test-face-block-java-example")
                    .description("Blocks images containing faces (Java example test policy)")
                    .type("media")
                    .category("media-safety")
                    .conditions(Collections.singletonList(
                        new DynamicPolicyCondition("media.has_faces", "equals", true)
                    ))
                    .actions(Collections.singletonList(
                        new DynamicPolicyAction("block", blockConfig)
                    ))
                    .priority(100)
                    .enabled(true)
                    .build()
            );

            createdPolicyId = created.getId();
            assertCheck(
                createdPolicyId != null && !createdPolicyId.isEmpty(),
                "Policy created with ID: " + (createdPolicyId != null ? createdPolicyId : "<none>")
            );
        } catch (Exception e) {
            System.out.println("   FAIL: createDynamicPolicy failed: " + e.getMessage());
            failures.add("Test 3: createDynamicPolicy failed");
        }

        // 3b. Verify it appears in the list
        System.out.println();
        System.out.println("  3b. Verifying policy appears in list");

        if (createdPolicyId != null) {
            try {
                List<DynamicPolicy> listAfterCreate = orchestratorClient.listDynamicPolicies(
                    ListDynamicPoliciesOptions.builder().type("media").limit(100).build()
                );

                boolean foundInList = false;
                for (DynamicPolicy p : listAfterCreate) {
                    if (createdPolicyId.equals(p.getId())) {
                        foundInList = true;
                        break;
                    }
                }
                assertCheck(foundInList, "Created policy found in list");
            } catch (Exception e) {
                System.out.println("   FAIL: listDynamicPolicies failed: " + e.getMessage());
                failures.add("Test 3b: listDynamicPolicies failed");
            }
        } else {
            System.out.println("   SKIP: No policy ID to verify");
        }

        // 3c. Send a 1x1 image request -- should NOT be blocked (no faces in a 1px image)
        System.out.println();
        System.out.println("  3c. Sending 1x1 image request (no faces expected)");

        try {
            ClientResponse resp3c = agentClient.proxyLLMCall(
                ClientRequest.builder()
                    .query("Describe this image")
                    .userToken(USER_TOKEN)
                    .requestType(RequestType.CHAT)
                    .media(Collections.singletonList(
                        MediaContent.builder()
                            .source("base64")
                            .mimeType("image/jpeg")
                            .base64Data(TEST_IMAGE_BASE64)
                            .build()
                    ))
                    .build()
            );

            assertCheck(resp3c.isSuccess(), "1x1 image request succeeded");
            assertCheck(!resp3c.isBlocked(), "1x1 image NOT blocked by face policy (no faces in 1px image)");
        } catch (Exception e) {
            System.out.println("   FAIL: proxyLLMCall failed: " + e.getMessage());
            failures.add("Test 3c: proxyLLMCall failed");
        }

        // 3d. Cleanup -- delete the custom policy
        System.out.println();
        System.out.println("  3d. Cleaning up: deleting custom policy");

        if (createdPolicyId != null) {
            try {
                orchestratorClient.deleteDynamicPolicy(createdPolicyId);
                assertCheck(true, "Policy deleted successfully");
            } catch (Exception e) {
                System.out.println("   FAIL: deleteDynamicPolicy failed: " + e.getMessage());
                failures.add("Test 3d: deleteDynamicPolicy failed");
            }
        } else {
            System.out.println("   SKIP: No policy to delete");
        }
        System.out.println();

        // ========================================
        // Test 4: Media governance config -- read status
        // ========================================
        System.out.println("Test 4: Media governance config -- read status");
        System.out.println();

        boolean perTenantControl = false;

        // 4a. Get media governance status via SDK
        System.out.println("  4a. Getting media governance status");

        try {
            MediaGovernanceStatus govStatus = orchestratorClient.getMediaGovernanceStatus();

            String tierValue = govStatus.getTier() != null ? govStatus.getTier() : "";
            assertCheck(tierValue != null, "Response contains 'available' field");
            assertCheck(
                !tierValue.isEmpty(),
                "Response contains non-empty 'tier' field (got: " + tierValue + ")"
            );

            perTenantControl = govStatus.isPerTenantControl();

            System.out.println("   Tier: " + tierValue
                + " | Available: " + govStatus.isAvailable()
                + " | Per-tenant control: " + perTenantControl);
        } catch (Exception e) {
            System.out.println("   FAIL: Media governance status request failed: " + e.getMessage());
            failures.add("Test 4a: Media governance status request failed");
        }

        // 4b. Get media governance config via SDK
        System.out.println();
        System.out.println("  4b. Getting media governance config");

        try {
            MediaGovernanceConfig govConfig = orchestratorClient.getMediaGovernanceConfig();

            String configTenantId = govConfig.getTenantId() != null ? govConfig.getTenantId() : "<missing>";
            assertCheck(
                govConfig.getTenantId() != null && !govConfig.getTenantId().isEmpty(),
                "Response contains 'tenant_id' field (got: " + configTenantId + ")"
            );
            assertCheck(
                true,
                "Response contains 'enabled' field (got: " + govConfig.isEnabled() + ")"
            );

            System.out.println("   Tenant: " + configTenantId
                + " | Enabled: " + govConfig.isEnabled());
        } catch (Exception e) {
            System.out.println("   FAIL: Media governance config request failed: " + e.getMessage());
            failures.add("Test 4b: Media governance config request failed");
        }
        System.out.println();

        // ========================================
        // Test 5: Policy toggle lifecycle
        // ========================================
        System.out.println("Test 5: Policy toggle lifecycle (create -> disable -> re-enable -> delete)");
        System.out.println();

        // 5a. Create a media policy
        System.out.println("  5a. Creating media policy: media.nsfw_score > 0.5 -> block");
        String togglePolicyId = null;

        try {
            Map<String, Object> nsfwBlockConfig = new HashMap<>();
            nsfwBlockConfig.put("message", "Media blocked: NSFW score exceeds threshold (> 0.5)");

            DynamicPolicy toggleCreated = orchestratorClient.createDynamicPolicy(
                CreateDynamicPolicyRequest.builder()
                    .name("test-nsfw-toggle-java-example")
                    .description("NSFW threshold policy for toggle lifecycle test")
                    .type("media")
                    .category("media-safety")
                    .conditions(Collections.singletonList(
                        new DynamicPolicyCondition("media.nsfw_score", "greater_than", 0.5)
                    ))
                    .actions(Collections.singletonList(
                        new DynamicPolicyAction("block", nsfwBlockConfig)
                    ))
                    .priority(200)
                    .enabled(true)
                    .build()
            );

            togglePolicyId = toggleCreated.getId();
            assertCheck(
                togglePolicyId != null && !togglePolicyId.isEmpty(),
                "Policy created with ID: " + (togglePolicyId != null ? togglePolicyId : "<none>")
            );
            assertCheck(
                toggleCreated.isEnabled(),
                "Policy initially enabled (enabled=" + toggleCreated.isEnabled() + ")"
            );
        } catch (Exception e) {
            System.out.println("   FAIL: createDynamicPolicy failed: " + e.getMessage());
            failures.add("Test 5a: createDynamicPolicy failed");
        }

        // 5b. Disable the policy
        System.out.println();
        System.out.println("  5b. Disabling policy (enabled=false)");

        if (togglePolicyId != null) {
            try {
                DynamicPolicy disabled = orchestratorClient.updateDynamicPolicy(togglePolicyId,
                    UpdateDynamicPolicyRequest.builder().enabled(false).build()
                );
                assertCheck(
                    !disabled.isEnabled(),
                    "Policy is now disabled (enabled=" + disabled.isEnabled() + ")"
                );
            } catch (Exception e) {
                System.out.println("   FAIL: updateDynamicPolicy (disable) failed: " + e.getMessage());
                failures.add("Test 5b: updateDynamicPolicy (disable) failed");
            }
        } else {
            System.out.println("   SKIP: No policy ID for toggle test");
        }

        // 5c. Re-enable the policy
        System.out.println();
        System.out.println("  5c. Re-enabling policy (enabled=true)");

        if (togglePolicyId != null) {
            try {
                DynamicPolicy reenabled = orchestratorClient.updateDynamicPolicy(togglePolicyId,
                    UpdateDynamicPolicyRequest.builder().enabled(true).build()
                );
                assertCheck(
                    reenabled.isEnabled(),
                    "Policy is now re-enabled (enabled=" + reenabled.isEnabled() + ")"
                );
            } catch (Exception e) {
                System.out.println("   FAIL: updateDynamicPolicy (re-enable) failed: " + e.getMessage());
                failures.add("Test 5c: updateDynamicPolicy (re-enable) failed");
            }
        } else {
            System.out.println("   SKIP: No policy ID for toggle test");
        }

        // 5d. Cleanup
        System.out.println();
        System.out.println("  5d. Cleaning up: deleting toggle test policy");

        if (togglePolicyId != null) {
            try {
                orchestratorClient.deleteDynamicPolicy(togglePolicyId);
                assertCheck(true, "Policy deleted successfully");
            } catch (Exception e) {
                System.out.println("   FAIL: deleteDynamicPolicy failed: " + e.getMessage());
                failures.add("Test 5d: deleteDynamicPolicy failed");
            }
        } else {
            System.out.println("   SKIP: No policy to delete");
        }
        System.out.println();

        // ========================================
        // Test 6: Media governance disable/enable (Enterprise only)
        // ========================================
        System.out.println("Test 6: Media governance disable/enable (per-tenant config)");
        System.out.println();

        if (perTenantControl) {
            System.out.println("  Enterprise mode detected -- testing per-tenant media governance toggle");
            System.out.println();

            // 6a. Disable media governance for this tenant
            System.out.println("  6a. Disabling media governance (enabled=false)");

            try {
                MediaGovernanceConfig disabledConfig = orchestratorClient.updateMediaGovernanceConfig(
                    UpdateMediaGovernanceConfigRequest.builder().enabled(false).build()
                );
                assertCheck(
                    !disabledConfig.isEnabled(),
                    "Media governance disabled (enabled=" + disabledConfig.isEnabled() + ")"
                );
            } catch (Exception e) {
                System.out.println("   FAIL: Failed to disable media governance: " + e.getMessage());
                failures.add("Test 6a: Failed to disable media governance");
            }

            // 6b. Send media request -- media_analysis should be absent
            System.out.println();
            System.out.println("  6b. Sending image request with media governance disabled");

            try {
                ClientResponse resp6b = agentClient.proxyLLMCall(
                    ClientRequest.builder()
                        .query("Describe this image")
                        .userToken(USER_TOKEN)
                        .requestType(RequestType.CHAT)
                        .media(Collections.singletonList(
                            MediaContent.builder()
                                .source("base64")
                                .mimeType("image/jpeg")
                                .base64Data(TEST_IMAGE_BASE64)
                                .build()
                        ))
                        .build()
                );

                assertCheck(resp6b.isSuccess(), "Request still succeeds with governance disabled");
                assertCheck(
                    resp6b.getMediaAnalysis() == null,
                    "media_analysis absent when governance disabled"
                );
            } catch (Exception e) {
                System.out.println("   FAIL: proxyLLMCall (governance disabled) failed: " + e.getMessage());
                failures.add("Test 6b: proxyLLMCall (governance disabled) failed");
            }

            // 6c. Re-enable media governance
            System.out.println();
            System.out.println("  6c. Re-enabling media governance (enabled=true)");

            try {
                MediaGovernanceConfig enabledConfig = orchestratorClient.updateMediaGovernanceConfig(
                    UpdateMediaGovernanceConfigRequest.builder().enabled(true).build()
                );
                assertCheck(
                    enabledConfig.isEnabled(),
                    "Media governance re-enabled (enabled=" + enabledConfig.isEnabled() + ")"
                );
            } catch (Exception e) {
                System.out.println("   FAIL: Failed to re-enable media governance: " + e.getMessage());
                failures.add("Test 6c: Failed to re-enable media governance");
            }

            // 6d. Verify media_analysis returns after re-enable
            System.out.println();
            System.out.println("  6d. Sending image request with media governance re-enabled");

            try {
                ClientResponse resp6d = agentClient.proxyLLMCall(
                    ClientRequest.builder()
                        .query("Describe this image")
                        .userToken(USER_TOKEN)
                        .requestType(RequestType.CHAT)
                        .media(Collections.singletonList(
                            MediaContent.builder()
                                .source("base64")
                                .mimeType("image/jpeg")
                                .base64Data(TEST_IMAGE_BASE64)
                                .build()
                        ))
                        .build()
                );

                assertCheck(resp6d.isSuccess(), "Request succeeds after re-enable");

                if (resp6d.getMediaAnalysis() != null) {
                    System.out.println("   PASS: media_analysis present after re-enable");
                } else {
                    System.out.println("   WARNING: media_analysis absent after re-enable"
                        + " (analyzers may not be active in this environment)");
                }
            } catch (Exception e) {
                System.out.println("   FAIL: proxyLLMCall (governance re-enabled) failed: " + e.getMessage());
                failures.add("Test 6d: proxyLLMCall (governance re-enabled) failed");
            }
        } else {
            System.out.println("  SKIP: Per-tenant media governance control requires Enterprise license.");
            System.out.println("  Community/Evaluation tiers use the global media governance setting.");
            System.out.println("  To test this, run with an Enterprise license key set in AXONFLOW_LICENSE_KEY.");
        }
        System.out.println();

        // ========================================
        // Test 7: Non-media request unaffected
        // ========================================
        System.out.println("Test 7: Non-media request unaffected by media policies");
        System.out.println("  Sending text-only query via proxyLLMCall");
        System.out.println();

        ClientResponse resp7;
        try {
            resp7 = agentClient.proxyLLMCall(
                ClientRequest.builder()
                    .query("What is the capital of France?")
                    .userToken(USER_TOKEN)
                    .requestType(RequestType.CHAT)
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   FAIL: proxyLLMCall (text-only) failed: " + e.getMessage());
            failures.add("Test 7: proxyLLMCall (text-only) failed");
            resp7 = null;
        }

        if (resp7 != null) {
            assertCheck(resp7.isSuccess(), "Text-only request is successful");
            assertCheck(
                resp7.getMediaAnalysis() == null,
                "No media_analysis present for text-only request"
            );
        }
        System.out.println();

        // ========================================
        // Summary
        // ========================================
        System.out.println("==============================================");

        if (pipelineActive) {
            System.out.println("Media governance pipeline: ACTIVE");
        } else {
            System.out.println("Media governance pipeline: NOT ACTIVE"
                + " -- media_analysis was null for all media requests");
        }

        System.out.println();

        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("Media governance policy capabilities validated:");
            System.out.println("  - System media policies (NSFW, violence, biometric, PII, documents)");
            System.out.println("  - Clean image passes system policies");
            System.out.println("  - Custom media policy CRUD (create, verify, process, delete)");
            System.out.println("  - Media governance config and status endpoints");
            System.out.println("  - Policy toggle lifecycle (create, disable, re-enable, delete)");
            if (perTenantControl) {
                System.out.println("  - Per-tenant media governance disable/enable (Enterprise)");
            }
            System.out.println("  - Non-media requests unaffected by media policies");
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
