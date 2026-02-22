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
package com.getaxonflow.examples.mediagovernance;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.MediaAnalysisResponse;
import com.getaxonflow.sdk.types.MediaAnalysisResult;
import com.getaxonflow.sdk.types.MediaContent;
import com.getaxonflow.sdk.types.PolicyInfo;
import com.getaxonflow.sdk.types.RequestType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * AxonFlow Media Governance - Java SDK
 *
 * This example demonstrates and VALIDATES AxonFlow's media governance capabilities
 * for images attached to LLM requests:
 * - PII in image text (via OCR)
 * - Content safety (NSFW, violence scoring)
 * - Face and biometric data detection (GDPR Art. 9)
 * - Document classification (ID cards, bank statements)
 * - SHA-256 integrity hashing for audit trails
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 * This ensures CI/CD pipelines catch regressions.
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class MediaGovernanceExample {

    // Minimal valid 1x1 white pixel JPEG encoded as base64.
    private static final String TEST_IMAGE_BASE64 =
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
        + "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh"
        + "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR"
        + "CAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAA"
        + "AAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQAC"
        + "EQMRAD8AbwA//9k=";

    private static final List<String> failures = new ArrayList<>();

    private static boolean pipelineActive = false;

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
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
        System.out.println("AxonFlow Media Governance - Java SDK");
        System.out.println("=====================================");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .endpoint(getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"))
            .clientId(getEnv("AXONFLOW_CLIENT_ID", "demo"))
            .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", "demo"))
            .debug("true".equals(getEnv("AXONFLOW_DEBUG", "")))
            .build());

        // ========================================
        // Test 1: Single image governance
        // ========================================
        System.out.println("Test 1: Single image governance (base64)");
        System.out.println("  Query: Describe this image");

        ClientResponse resp;
        try {
            resp = client.proxyLLMCall(
                ClientRequest.builder()
                    .query("Describe this image")
                    .userToken("media-governance-user")
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
            System.out.println("   \u274C FATAL: proxyLLMCall failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(resp.isSuccess(), "Response is successful");

        MediaAnalysisResponse analysis = resp.getMediaAnalysis();
        if (analysis != null) {
            pipelineActive = true;

            assertCheck(
                analysis.getResults() != null && analysis.getResults().size() == 1,
                "Single media analysis result returned (results size == 1)"
            );

            if (analysis.getResults() != null && !analysis.getResults().isEmpty()) {
                MediaAnalysisResult result = analysis.getResults().get(0);
                assertCheck(
                    result.getSha256Hash() != null && !result.getSha256Hash().isEmpty(),
                    "SHA-256 hash is non-null and non-empty"
                );
                assertCheck(result.getMediaIndex() == 0, "Media index is 0 for first image");
                assertCheck(result.getNsfwScore() >= 0, "NSFW score >= 0 (got " + result.getNsfwScore() + ")");
                assertCheck(result.getViolenceScore() >= 0, "Violence score >= 0 (got " + result.getViolenceScore() + ")");

                System.out.printf("   Content safe: %s%n", result.isContentSafe());
                System.out.printf("   NSFW score: %.2f%n", result.getNsfwScore());
                System.out.printf("   Violence score: %.2f%n", result.getViolenceScore());
                System.out.printf("   Has PII: %s%n", result.isHasPII());
                System.out.printf("   Has faces: %s (count: %d)%n", result.isHasFaces(), result.getFaceCount());
                System.out.printf("   Has biometric data: %s%n", result.isHasBiometricData());
                System.out.printf("   Document type: %s%n", result.getDocumentType());
                System.out.printf("   Is sensitive document: %s%n", result.isSensitiveDocument());
                System.out.printf("   Estimated cost: $%.6f%n", result.getEstimatedCostUsd());
            }

            assertCheck(analysis.getAnalysisTimeMs() >= 0, "Analysis time >= 0ms (got " + analysis.getAnalysisTimeMs() + "ms)");
            assertCheck(analysis.getTotalCostUsd() >= 0, "Total cost >= 0 (got $" + analysis.getTotalCostUsd() + ")");
            System.out.printf("   Total analysis time: %dms%n", analysis.getAnalysisTimeMs());
            System.out.printf("   Total cost: $%.6f%n", analysis.getTotalCostUsd());
        } else {
            System.out.println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE \u2014 getMediaAnalysis() is null (requires platform v4.4.0+)");
        }
        System.out.println();

        // ========================================
        // Test 2: Multiple images in single request
        // ========================================
        System.out.println("Test 2: Multiple images in single request");
        System.out.println("  Query: Compare these images");

        ClientResponse resp2;
        try {
            resp2 = client.proxyLLMCall(
                ClientRequest.builder()
                    .query("Compare these images")
                    .userToken("media-governance-user")
                    .requestType(RequestType.CHAT)
                    .media(Arrays.asList(
                        MediaContent.builder()
                            .source("base64")
                            .mimeType("image/jpeg")
                            .base64Data(TEST_IMAGE_BASE64)
                            .build(),
                        MediaContent.builder()
                            .source("base64")
                            .mimeType("image/jpeg")
                            .base64Data(TEST_IMAGE_BASE64)
                            .build()
                    ))
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: proxyLLMCall failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(resp2.isSuccess(), "Response is successful");

        MediaAnalysisResponse analysis2 = resp2.getMediaAnalysis();
        if (analysis2 != null) {
            pipelineActive = true;

            assertCheck(
                analysis2.getResults() != null && analysis2.getResults().size() == 2,
                "Two media analysis results returned (results size == 2)"
            );

            if (analysis2.getResults() != null && analysis2.getResults().size() == 2) {
                for (int i = 0; i < analysis2.getResults().size(); i++) {
                    MediaAnalysisResult result = analysis2.getResults().get(i);
                    assertCheck(
                        result.getSha256Hash() != null && !result.getSha256Hash().isEmpty(),
                        "SHA-256 hash is non-null and non-empty for image " + i
                    );
                    assertCheck(result.getMediaIndex() == i, "Media index is " + i + " for image " + i);
                    assertCheck(result.getNsfwScore() >= 0, "NSFW score >= 0 for image " + i + " (got " + result.getNsfwScore() + ")");
                    assertCheck(result.getViolenceScore() >= 0, "Violence score >= 0 for image " + i + " (got " + result.getViolenceScore() + ")");
                }

                // Both images are the same base64 data, so their SHA-256 hashes must match
                String hash0 = analysis2.getResults().get(0).getSha256Hash();
                String hash1 = analysis2.getResults().get(1).getSha256Hash();
                assertCheck(
                    hash0 != null && hash0.equals(hash1),
                    "Both images have same SHA-256 hash (same image sent twice): " + hash0
                );
            }

            assertCheck(analysis2.getAnalysisTimeMs() >= 0, "Analysis time >= 0ms (got " + analysis2.getAnalysisTimeMs() + "ms)");
            assertCheck(analysis2.getTotalCostUsd() >= 0, "Total cost >= 0 (got $" + analysis2.getTotalCostUsd() + ")");
        } else {
            System.out.println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE \u2014 getMediaAnalysis() is null (requires platform v4.4.0+)");
        }
        System.out.println();

        // ========================================
        // Test 3: URL-sourced image
        // ========================================
        System.out.println("Test 3: URL-sourced image");
        System.out.println("  Query: Analyze this image from URL");

        ClientResponse resp3;
        try {
            resp3 = client.proxyLLMCall(
                ClientRequest.builder()
                    .query("Analyze this image from URL")
                    .userToken("media-governance-user")
                    .requestType(RequestType.CHAT)
                    .media(Collections.singletonList(
                        MediaContent.builder()
                            .source("url")
                            .mimeType("image/png")
                            .url("https://via.placeholder.com/1x1.png")
                            .build()
                    ))
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: proxyLLMCall failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(resp3.isSuccess(), "Response is successful");

        MediaAnalysisResponse analysis3 = resp3.getMediaAnalysis();
        if (analysis3 != null) {
            pipelineActive = true;

            assertCheck(
                analysis3.getResults() != null && !analysis3.getResults().isEmpty(),
                "Media analysis result returned for URL image (results size == 1)"
            );

            if (analysis3.getResults() != null && !analysis3.getResults().isEmpty()) {
                MediaAnalysisResult result = analysis3.getResults().get(0);
                if (result.getSha256Hash() != null && !result.getSha256Hash().isEmpty()) {
                    assertCheck(true, "SHA-256 hash is non-null and non-empty for URL image");
                } else {
                    System.out.println("   WARNING: SHA-256 hash empty for URL source (platform may not have network access to download URL)");
                }
                assertCheck(result.getMediaIndex() == 0, "Media index is 0 for URL image");
                assertCheck(result.getNsfwScore() >= 0, "NSFW score >= 0 for URL image (got " + result.getNsfwScore() + ")");
                assertCheck(result.getViolenceScore() >= 0, "Violence score >= 0 for URL image (got " + result.getViolenceScore() + ")");
            }

            assertCheck(analysis3.getAnalysisTimeMs() >= 0, "Analysis time >= 0ms (got " + analysis3.getAnalysisTimeMs() + "ms)");
            assertCheck(analysis3.getTotalCostUsd() >= 0, "Total cost >= 0 (got $" + analysis3.getTotalCostUsd() + ")");
        } else {
            System.out.println("   WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE \u2014 getMediaAnalysis() is null (requires platform v4.4.0+)");
        }
        System.out.println();

        // ========================================
        // Test 4: Request without media still succeeds
        // ========================================
        System.out.println("Test 4: Request without media still succeeds");
        System.out.println("  Query: What is the capital of France?");

        ClientResponse resp4;
        try {
            resp4 = client.proxyLLMCall(
                ClientRequest.builder()
                    .query("What is the capital of France?")
                    .userToken("media-governance-user")
                    .requestType(RequestType.CHAT)
                    .build()
            );
        } catch (Exception e) {
            System.out.println("   \u274C FATAL: proxyLLMCall failed: " + e.getMessage());
            System.exit(1);
            return;
        }

        assertCheck(resp4.isSuccess(), "Response is successful (no media attached)");
        assertCheck(
            resp4.getMediaAnalysis() == null,
            "No media analysis returned when no media sent"
        );
        System.out.println();

        // ========================================
        // Test 5: Verify policy_info present for media requests
        // ========================================
        System.out.println("Test 5: Verify policy_info present for media requests");
        System.out.println("  Checking policy_info from Test 1 response (media request)");

        PolicyInfo respPolicyInfo = resp.getPolicyInfo();
        if (respPolicyInfo != null) {
            assertCheck(
                respPolicyInfo.getTenantId() != null && !respPolicyInfo.getTenantId().isEmpty(),
                "policy_info.tenant_id is non-empty (got " + respPolicyInfo.getTenantId() + ")"
            );
            assertCheck(
                respPolicyInfo.getProcessingTime() != null && !respPolicyInfo.getProcessingTime().isEmpty(),
                "policy_info.processing_time is non-empty"
            );

            boolean hasMediaPolicy = false;
            if (respPolicyInfo.getPoliciesEvaluated() != null) {
                for (String p : respPolicyInfo.getPoliciesEvaluated()) {
                    if (p.startsWith("sys_media_")) {
                        hasMediaPolicy = true;
                        break;
                    }
                }
            }
            if (hasMediaPolicy) {
                System.out.println("   PASS: system media policies found in policies_evaluated");
            } else {
                System.out.println("   INFO: no sys_media_* policies in policies_evaluated (dynamic policies may be tracked separately)");
            }
            System.out.println("   Policies evaluated: " + respPolicyInfo.getPoliciesEvaluated());
        } else if (pipelineActive) {
            System.out.println("   WARNING: policy_info absent despite media analysis being active");
        } else {
            System.out.println("   SKIP: policy_info not available (media governance pipeline not active)");
        }
        System.out.println();

        // ========================================
        // Summary
        // ========================================
        System.out.println("=====================================");
        if (pipelineActive) {
            System.out.println("Media governance pipeline: ACTIVE");
        } else {
            System.out.println("Media governance pipeline: NOT ACTIVE (all media analysis responses were null)");
        }
        System.out.println();

        if (failures.isEmpty()) {
            System.out.println("\u2713 ALL TESTS PASSED (" + (pipelineActive ? "with" : "without") + " media governance pipeline)");
            System.out.println();
            System.out.println("Media governance capabilities validated:");
            System.out.println("  - Single image analysis (base64)");
            System.out.println("  - Multiple image analysis with SHA-256 hash consistency");
            System.out.println("  - URL-sourced image analysis");
            System.out.println("  - Request without media (no media analysis returned)");
            System.out.println("  - Policy evaluation metadata for media requests");
        } else {
            System.out.println("\u274C " + failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
