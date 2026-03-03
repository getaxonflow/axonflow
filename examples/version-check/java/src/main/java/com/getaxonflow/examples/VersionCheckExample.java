package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.HealthStatus;
import com.getaxonflow.sdk.types.PlatformCapability;

import java.util.ArrayList;
import java.util.List;

/**
 * Version Discovery Example - Java SDK
 *
 * Demonstrates SDK-platform version discovery:
 * 1. healthCheck() returns platform version and capabilities
 * 2. hasCapability() checks for specific platform features
 * 3. SDK version constant
 *
 * Run with: mvn compile exec:java
 * Prerequisites: docker compose up -d
 */
public class VersionCheckExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (!condition) {
            failures.add(message);
            System.out.println("   FAIL: " + message);
        } else {
            System.out.println("   PASS: " + message);
        }
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    public static void main(String[] args) {
        System.out.println("Version Discovery — Java SDK");
        System.out.println("============================");
        System.out.println();

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(env("AXONFLOW_ENDPOINT", "http://localhost:8080"))
                .clientId(env("AXONFLOW_CLIENT_ID", "demo"))
                .clientSecret(env("AXONFLOW_CLIENT_SECRET", ""))
                .build();

        AxonFlow client = AxonFlow.create(config);

        // ---------------------------------------------------------------
        // Test 1: healthCheck returns version and capabilities
        // ---------------------------------------------------------------
        System.out.println("Test 1: healthCheck — Version and Capabilities");
        System.out.println("-----------------------------------------------");

        HealthStatus health = client.healthCheck();

        System.out.println("   Platform version: " + health.getVersion());
        System.out.println("   Status: " + health.getStatus());
        System.out.println("   Capabilities: " +
                (health.getCapabilities() != null ? health.getCapabilities().size() : 0));

        assertCheck(health.getVersion() != null && !health.getVersion().isEmpty(),
                "version is non-empty");
        assertCheck(health.isHealthy(), "status is healthy");
        assertCheck(health.getCapabilities() != null && !health.getCapabilities().isEmpty(),
                "capabilities list is non-empty");
        assertCheck(health.getSdkCompatibility() != null,
                "sdk_compatibility is present");

        if (health.getSdkCompatibility() != null) {
            System.out.println("   Min SDK: " + health.getSdkCompatibility().getMinSdkVersion());
            System.out.println("   Recommended SDK: " + health.getSdkCompatibility().getRecommendedSdkVersion());
            assertCheck(health.getSdkCompatibility().getMinSdkVersion() != null
                            && !health.getSdkCompatibility().getMinSdkVersion().isEmpty(),
                    "min_sdk_version is non-empty");
            assertCheck(health.getSdkCompatibility().getRecommendedSdkVersion() != null
                            && !health.getSdkCompatibility().getRecommendedSdkVersion().isEmpty(),
                    "recommended_sdk_version is non-empty");
        }
        System.out.println();

        // ---------------------------------------------------------------
        // Test 2: hasCapability
        // ---------------------------------------------------------------
        System.out.println("Test 2: hasCapability");
        System.out.println("---------------------");

        assertCheck(health.hasCapability("health_check"),
                "hasCapability('health_check') = true");
        assertCheck(health.hasCapability("version_discovery"),
                "hasCapability('version_discovery') = true");
        assertCheck(!health.hasCapability("nonexistent_feature"),
                "hasCapability('nonexistent_feature') = false");
        System.out.println();

        // ---------------------------------------------------------------
        // Test 3: List all capabilities
        // ---------------------------------------------------------------
        System.out.println("Test 3: All Capabilities");
        System.out.println("------------------------");
        if (health.getCapabilities() != null) {
            for (PlatformCapability cap : health.getCapabilities()) {
                System.out.println("   - " + cap.getName()
                        + " (since " + cap.getSince() + "): " + cap.getDescription());
            }
        }
        System.out.println();

        // ---------------------------------------------------------------
        // Test 4: SDK version info
        // ---------------------------------------------------------------
        System.out.println("Test 4: SDK Version");
        System.out.println("-------------------");
        System.out.println("   SDK version: " + AxonFlowConfig.SDK_VERSION);
        assertCheck(AxonFlowConfig.SDK_VERSION != null && !AxonFlowConfig.SDK_VERSION.isEmpty(),
                "SDK version is non-empty");
        System.out.println();

        // ---------------------------------------------------------------
        // Summary
        // ---------------------------------------------------------------
        System.out.println("============================");
        if (!failures.isEmpty()) {
            System.out.println("FAILED: " + failures.size() + " failures");
            for (String f : failures) {
                System.out.println("  - " + f);
            }
            System.exit(1);
        }
        System.out.println("ALL PASSED");
    }
}
