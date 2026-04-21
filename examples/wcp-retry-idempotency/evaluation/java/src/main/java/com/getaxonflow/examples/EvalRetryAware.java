// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// Evaluation-tier retry-aware policy demo (Java SDK).
//
// Creates a dynamic policy via raw HTTP (the Java SDK doesn't expose a
// createPolicy helper), then uses the SDK's stepGate to prove the
// retry-aware condition fires on retry_policy=reevaluate.
//
// ⚠️ Evaluation or Enterprise license required.
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EvalRetryAware {

    private static final String POLICY_JSON = "{"
            + "\"name\":\"Retry on gated-not-completed wire requires approval (Java)\","
            + "\"description\":\"Human verification required before re-executing a wire when the prior attempt never completed.\","
            + "\"type\":\"context_aware\","
            + "\"priority\":100,"
            + "\"enabled\":true,"
            + "\"conditions\":["
            + "  {\"field\":\"step.gate_count\",\"operator\":\"greater_than\",\"value\":1},"
            + "  {\"field\":\"step.prior_completion_status\",\"operator\":\"equals\",\"value\":\"gated_not_completed\"},"
            + "  {\"field\":\"context.tool_name\",\"operator\":\"equals\",\"value\":\"core_banking_transfer\"}"
            + "],"
            + "\"actions\":[{"
            + "  \"type\":\"require_approval\","
            + "  \"config\":{\"reason\":\"Retry on un-completed wire — verify with bank before re-execution\",\"severity\":\"high\"}"
            + "}]"
            + "}";

    public static void main(String[] args) throws Exception {
        String endpoint = envOrDefault("AXONFLOW_BASE_URL", "http://localhost:8080");
        String clientId = mustEnv("AXONFLOW_CLIENT_ID");
        String clientSecret = mustEnv("AXONFLOW_CLIENT_SECRET");

        banner("Retry-aware policy (Java SDK, Evaluation tier)");

        HttpClient http = HttpClient.newHttpClient();
        String auth = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        String policyId = createRetryAwarePolicy(http, endpoint, auth);
        System.out.println("  policy created: " + policyId);

        try {
            AxonFlow client = AxonFlow.create(
                    AxonFlowConfig.builder()
                            .endpoint(endpoint)
                            .clientId(clientId)
                            .clientSecret(clientSecret)
                            .build());

            WorkflowTypes.CreateWorkflowResponse wf = client.createWorkflow(
                    WorkflowTypes.CreateWorkflowRequest.builder()
                            .workflowName("eval-retry-aware-java")
                            .build());
            System.out.println("  workflow: " + wf.getWorkflowId());

            Map<String, Object> stepInput = new HashMap<>();
            stepInput.put("amount_eur", 750);
            stepInput.put("to_account", "1234");

            WorkflowTypes.ToolContext toolCtx = WorkflowTypes.ToolContext.builder("core_banking_transfer")
                    .toolType("api")
                    .build();

            // 1) First gate — allow
            WorkflowTypes.StepGateRequest baseReq = WorkflowTypes.StepGateRequest.builder()
                    .stepName("Initiate Wire")
                    .stepType(WorkflowTypes.StepType.TOOL_CALL)
                    .stepInput(stepInput)
                    .toolContext(toolCtx)
                    .build();
            WorkflowTypes.StepGateResponse first = client.stepGate(wf.getWorkflowId(), "step-1", baseReq);
            if (first.getDecision() != WorkflowTypes.GateDecision.ALLOW) {
                fail("first gate: want allow, got " + first.getDecision());
            }
            System.out.println("  first gate: allow (gate_count=1, policy doesn't fire) ✔");

            // 2) Cached retry — still allow
            WorkflowTypes.StepGateResponse cached = client.stepGate(wf.getWorkflowId(), "step-1", baseReq);
            if (!cached.isCached()) fail("second gate should be cached");
            if (cached.getDecision() != WorkflowTypes.GateDecision.ALLOW) {
                fail("cached gate: want allow, got " + cached.getDecision());
            }
            System.out.println("  second gate cached: still allow (cache bypasses policy) ✔");

            // 3) Reevaluate — retry-aware policy fires
            WorkflowTypes.StepGateRequest reevalReq = WorkflowTypes.StepGateRequest.builder()
                    .stepName("Initiate Wire")
                    .stepType(WorkflowTypes.StepType.TOOL_CALL)
                    .stepInput(stepInput)
                    .toolContext(toolCtx)
                    .retryPolicy("reevaluate")
                    .build();
            WorkflowTypes.StepGateResponse third = client.stepGate(wf.getWorkflowId(), "step-1", reevalReq);
            if (third.isCached()) fail("reevaluate gate should not be cached");
            if (third.getDecision() != WorkflowTypes.GateDecision.REQUIRE_APPROVAL) {
                fail("reevaluate gate: want require_approval, got " + third.getDecision() + " (" + third.getReason() + ")");
            }
            System.out.println("  third gate (reevaluate): require_approval (policy FIRED) ✔");

            banner("Evaluation-tier Java SDK demo passed ✔");
        } finally {
            deletePolicy(http, endpoint, auth, policyId);
        }
    }

    private static String createRetryAwarePolicy(HttpClient http, String endpoint, String auth) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint + "/api/v1/policies"))
                .header("Content-Type", "application/json")
                .header("Authorization", auth)
                .POST(HttpRequest.BodyPublishers.ofString(POLICY_JSON))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200 && resp.statusCode() != 201) {
            fail("create policy: status=" + resp.statusCode() + " body=" + resp.body());
        }
        // Minimal JSON extraction: policy.id
        Matcher m = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"").matcher(resp.body());
        if (!m.find()) {
            fail("create policy: missing policy.id in response, body=" + resp.body());
        }
        return m.group(1);
    }

    private static void deletePolicy(HttpClient http, String endpoint, String auth, String policyId) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint + "/api/v1/policies/" + policyId))
                    .header("Authorization", auth)
                    .DELETE()
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException ignored) { /* best-effort teardown */ }
    }

    private static String envOrDefault(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }
    private static String mustEnv(String k) {
        String v = System.getenv(k);
        if (v == null || v.isEmpty()) fail("missing env: " + k);
        return v;
    }
    private static void fail(String msg) { System.err.println("FAIL: " + msg); System.exit(1); }
    private static void banner(String s) { System.out.println(); System.out.println("━━━ " + s + " ━━━"); }
}
