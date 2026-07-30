package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.AuditOptions;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;
import com.getaxonflow.sdk.types.PolicyApprovalRequest;
import com.getaxonflow.sdk.types.PolicyApprovalResult;
import com.getaxonflow.sdk.types.TokenUsage;
import com.getaxonflow.sdk.exceptions.PolicyViolationException;

import java.util.Map;

/**
 * Mistral LLM Provider - Hello World (Java SDK)
 *
 * Demonstrates Gateway Mode and Proxy Mode with Mistral through AxonFlow.
 *
 * Prerequisites:
 *   docker compose up -d
 *   export AXONFLOW_CLIENT_SECRET=your-secret
 *
 * Usage:
 *   mvn exec:java -q
 */
public class MistralExample {

    private static final String CLIENT_ID = "mistral-hello-world";

    /**
     * The provider and model go in the request CONTEXT, not in the
     * {@code llmProvider}/{@code model} builder fields.
     *
     * <p>Those fields exist on {@code ClientRequest} and serialise as
     * {@code llm_provider}/{@code model}, but the agent's request struct has no
     * such fields and the orchestrator reads the provider only from
     * {@code context["provider"]} — so setting them routes the call to the
     * deployment's default provider while looking like it worked. See #3192.
     * The Go and Python siblings of this example both pass the provider in
     * context for the same reason.
     */
    private static final Map<String, Object> MISTRAL_CONTEXT =
            Map.of("provider", "mistral", "model", "mistral-small-latest");

    public static void main(String[] args) throws Exception {
        String endpoint = System.getenv().getOrDefault("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = System.getenv().getOrDefault("AXONFLOW_CLIENT_ID", "community");
        String clientSecret = System.getenv().getOrDefault("AXONFLOW_CLIENT_SECRET", "");
        String userToken = System.getenv().getOrDefault("AXONFLOW_USER_TOKEN", "mistral-demo-user");

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        System.out.println("Mistral LLM Provider - Hello World (Java SDK)");
        System.out.println("=".repeat(50));

        // Gateway Mode: Pre-check + Audit
        // A block is an EXCEPTION on every call in this SDK, never a returned
        // object to interrogate: preCheck throws PolicyViolationException on
        // `!result.isApproved()` and proxyLLMCall throws on `result.isBlocked()`,
        // both before returning. So `if (precheck.isApproved())` would have a
        // dead else-branch, and an unhandled block would leave the example as a
        // stack trace rather than the outcome it exists to demonstrate.
        //
        // userToken is also REQUIRED on this call: PolicyApprovalRequest.build()
        // rejects a null one, unlike ClientRequest which defaults to "anonymous".
        System.out.println("\n--- Gateway Mode ---");
        try {
            PolicyApprovalResult precheck = client.preCheck(PolicyApprovalRequest.builder()
                    .query("Explain Mistral AI in one sentence.")
                    .userToken(userToken)
                    .clientId(CLIENT_ID)
                    .context(MISTRAL_CONTEXT)
                    .build());

            System.out.printf("Pre-check approved (context: %s)%n", precheck.getContextId());

            client.auditLLMCall(AuditOptions.builder()
                    .contextId(precheck.getContextId())
                    .clientId(CLIENT_ID)
                    .responseSummary("Mistral Java SDK gateway test")
                    .provider("mistral")
                    .model("mistral-small-latest")
                    .latencyMs(350)
                    .tokenUsage(new TokenUsage(15, 40, 55))
                    .build());
            System.out.println("Audit logged successfully");
        } catch (PolicyViolationException e) {
            System.out.printf("Pre-check blocked: %s%n", e.getMessage());
        }

        // Proxy Mode
        System.out.println("\n--- Proxy Mode ---");
        try {
            ClientResponse resp = client.proxyLLMCall(ClientRequest.builder()
                    .query("What is 2 + 2? Answer with just the number.")
                    .userToken(userToken)
                    .clientId(CLIENT_ID)
                    .context(MISTRAL_CONTEXT)
                    .build());

            System.out.printf("Response: %s%n", resp.getData());
            if (resp.getPolicyInfo() != null && resp.getPolicyInfo().getPoliciesEvaluated() != null) {
                System.out.printf("Policies evaluated: %d%n",
                        resp.getPolicyInfo().getPoliciesEvaluated().size());
            }
        } catch (PolicyViolationException e) {
            System.out.printf("Request blocked by policy: %s%n", e.getMessage());
        }

        // Policy enforcement
        System.out.println("\n--- Policy Enforcement ---");
        try {
            client.proxyLLMCall(ClientRequest.builder()
                    .query("SELECT * FROM users; DROP TABLE users;")
                    .userToken(userToken)
                    .clientId(CLIENT_ID)
                    .context(MISTRAL_CONTEXT)
                    .build());
            System.out.println("WARNING: SQLi was not blocked");
        } catch (PolicyViolationException e) {
            System.out.printf("SQLi correctly blocked by policy: %s%n", e.getMessage());
        }

        System.out.println("\nDone.");
    }
}
