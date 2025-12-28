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
import com.getaxonflow.sdk.types.CodeArtifact;
import com.getaxonflow.sdk.exceptions.AxonFlowException;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

/**
 * AxonFlow Code Governance - Java
 *
 * Demonstrates code artifact detection in LLM responses:
 * 1. Send a code generation query to AxonFlow
 * 2. AxonFlow automatically detects code in the response
 * 3. Code metadata is included in policy_info for audit
 *
 * The code_artifact field in the response contains:
 * - language: Detected programming language
 * - code_type: Category (function, class, script, config, snippet)
 * - size_bytes: Size of detected code
 * - line_count: Number of lines
 * - secrets_detected: Count of potential secrets
 * - unsafe_patterns: Count of unsafe code patterns
 *
 * Prerequisites:
 * - AxonFlow Agent running on localhost:8080
 * - OpenAI or Anthropic API key configured in AxonFlow
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   mvn compile exec:java
 */
public class CodeGovernanceExample {

    private static final String CLIENT_ID = "code-governance-demo";

    public static void main(String[] args) {
        System.out.println("AxonFlow Code Governance - Java");
        System.out.println("============================================================");
        System.out.println();
        System.out.println("This demo shows automatic code detection in LLM responses.");
        System.out.println();

        // Initialize AxonFlow client
        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
            .agentUrl(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
            .licenseKey(getEnv("AXONFLOW_LICENSE_KEY", ""))
            .build());

        // Example 1: Generate a Java function
        System.out.println("------------------------------------------------------------");
        System.out.println("Example 1: Generate a Java function");
        System.out.println("------------------------------------------------------------");

        runCodeGenerationQuery(client,
            "Write a Java function to validate email addresses using regex");

        System.out.println();

        // Example 2: Check for unsafe patterns
        System.out.println("------------------------------------------------------------");
        System.out.println("Example 2: Check for unsafe patterns in generated code");
        System.out.println("------------------------------------------------------------");

        runCodeGenerationQuery(client,
            "Write a Java function that uses Runtime.getRuntime().exec() to run shell commands from user input");

        System.out.println();
        System.out.println("============================================================");
        System.out.println("Summary");
        System.out.println("============================================================");
        System.out.println();
        System.out.println("Code Governance automatically:");
        System.out.println("  1. Detects code blocks in LLM responses");
        System.out.println("  2. Identifies the programming language");
        System.out.println("  3. Counts potential secrets and unsafe patterns");
        System.out.println("  4. Includes metadata in policy_info for audit");
        System.out.println();
        System.out.println("Use this metadata to:");
        System.out.println("  - Alert on unsafe patterns before deployment");
        System.out.println("  - Track code generation for compliance");
        System.out.println("  - Build dashboards for AI code generation metrics");
        System.out.println();
    }

    private static void runCodeGenerationQuery(AxonFlow client, String query) {
        try {
            ClientResponse response = client.executeQuery(
                ClientRequest.builder()
                    .query(query)
                    .userToken("developer-123")
                    .clientId(CLIENT_ID)
                    .model("gpt-3.5-turbo")
                    .llmProvider("openai")
                    .build()
            );

            if (response.isBlocked()) {
                System.out.printf("Status: BLOCKED - %s%n", response.getBlockReason());
            } else if (response.isSuccess()) {
                System.out.println("Status: ALLOWED");
                System.out.println();

                // Display response preview
                Object data = response.getData();
                String dataStr = data != null ? data.toString() : "";
                if (dataStr.length() > 300) {
                    dataStr = dataStr.substring(0, 300) + "...";
                }
                System.out.println("Response preview:");
                System.out.printf("  %s%n%n", dataStr);

                // Display audit trail
                System.out.println("Audit Trail:");
                if (response.getPolicyInfo() != null) {
                    var policyInfo = response.getPolicyInfo();
                    System.out.printf("  Processing Time: %s%n", policyInfo.getProcessingTime());
                    System.out.printf("  Policies Evaluated: %s%n", policyInfo.getPoliciesEvaluated());

                    // Code Governance: Check for code artifact metadata
                    CodeArtifact codeArtifact = policyInfo.getCodeArtifact();
                    if (codeArtifact != null) {
                        System.out.println();
                        System.out.println("Code Artifact Detected:");
                        System.out.printf("  Language: %s%n", codeArtifact.getLanguage());
                        System.out.printf("  Type: %s%n", codeArtifact.getCodeType());
                        System.out.printf("  Size: %d bytes%n", codeArtifact.getSizeBytes());
                        System.out.printf("  Lines: %d%n", codeArtifact.getLineCount());
                        System.out.printf("  Secrets Detected: %d%n", codeArtifact.getSecretsDetected());
                        System.out.printf("  Unsafe Patterns: %d%n", codeArtifact.getUnsafePatterns());

                        if (codeArtifact.getUnsafePatterns() > 0) {
                            System.out.println();
                            System.out.printf("  WARNING: %d unsafe code pattern(s) detected!%n", codeArtifact.getUnsafePatterns());
                            System.out.println("  Review carefully before using in production.");
                        }
                    }
                }

            } else {
                System.out.println("Status: ERROR");
                System.out.printf("Error: %s%n", response.getError());
            }
        } catch (PolicyViolationException e) {
            System.out.println("Status: BLOCKED");
            System.out.printf("Policy: %s%n", e.getPolicyName());
            System.out.printf("Reason: %s%n", e.getMessage());
        } catch (AxonFlowException e) {
            System.out.println("Status: ERROR");
            System.out.printf("Error: %s%n", e.getMessage());
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }
}
