/*
 * Example 5: Data Pipeline Workflow - Java
 *
 * Demonstrates a 5-stage data pipeline: Extract → Clean → Enrich → Aggregate → Report
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ClientRequest;
import com.getaxonflow.sdk.types.ClientResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class Main {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   ✓ PASS: " + message);
        } else {
            System.out.println("   ❌ FAIL: " + message);
            failures.add(message);
        }
    }

    public static void main(String[] args) {
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
            System.err.println("❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set");
            System.exit(1);
        }

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(agentUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());

        System.out.println("✅ Connected to AxonFlow");
        System.out.println("🔄 Starting 5-stage data pipeline for customer analytics...");
        System.out.println();

        long startTime = System.currentTimeMillis();
        int stagesCompleted = 0;

        try {
            // Stage 1: Extract
            System.out.println("📥 Stage 1/5: Extracting customer transaction data...");
            ClientResponse extractResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Extract customer purchase data from the last 30 days. Include customer ID, purchase amount, product categories, and timestamps. Simulate 500 customer transactions.")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "data-pipeline-extract"))
                            .build()
            );
            stagesCompleted++;
            System.out.println("✅ Stage 1 complete: Data extracted");

            System.out.println("=== Stage 1 Assertions ===");
            assertCheck(extractResp != null, "Extract response is not null");
            assertCheck(extractResp.isSuccess() || extractResp.isBlocked(), "Extract response has valid status");
            if (!extractResp.isBlocked()) {
                assertCheck(extractResp.getData() != null, "Extract response data is not null");
            }
            System.out.println();

            // Stage 2: Transform (Clean & Normalize)
            System.out.println("🧹 Stage 2/5: Cleaning and normalizing data...");
            ClientResponse cleanResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("From the extracted data above, perform the following transformations:\n" +
                                    "1. Remove duplicate transactions\n" +
                                    "2. Standardize date formats to ISO 8601\n" +
                                    "3. Normalize product category names\n" +
                                    "4. Validate all amounts are positive numbers\n" +
                                    "5. Flag any anomalies (unusually high amounts)")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "data-pipeline-clean"))
                            .build()
            );
            stagesCompleted++;
            System.out.println("✅ Stage 2 complete: Data cleaned and normalized");

            System.out.println("=== Stage 2 Assertions ===");
            assertCheck(cleanResp != null, "Clean response is not null");
            if (!cleanResp.isBlocked()) {
                assertCheck(cleanResp.getData() != null, "Clean response data is not null");
            }
            System.out.println();

            // Stage 3: Enrich
            System.out.println("💎 Stage 3/5: Enriching with customer segments and lifetime value...");
            ClientResponse enrichResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Based on the cleaned transaction data:\n" +
                                    "1. Calculate customer lifetime value (CLV)\n" +
                                    "2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)\n" +
                                    "3. Identify top-spending product categories per segment\n" +
                                    "4. Calculate average order value per segment")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "data-pipeline-enrich"))
                            .build()
            );
            stagesCompleted++;
            System.out.println("✅ Stage 3 complete: Data enriched with segments and metrics");

            System.out.println("=== Stage 3 Assertions ===");
            assertCheck(enrichResp != null, "Enrich response is not null");
            if (!enrichResp.isBlocked()) {
                assertCheck(enrichResp.getData() != null, "Enrich response data is not null");
            }
            System.out.println();

            // Stage 4: Aggregate
            System.out.println("📊 Stage 4/5: Aggregating insights and trends...");
            ClientResponse aggregateResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Generate aggregated insights:\n" +
                                    "1. Total revenue by customer segment\n" +
                                    "2. Growth trends (week-over-week)\n" +
                                    "3. Top 5 products by revenue\n" +
                                    "4. Customer churn risk indicators\n" +
                                    "5. Recommended actions for each segment")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "data-pipeline-aggregate"))
                            .build()
            );
            stagesCompleted++;
            System.out.println("✅ Stage 4 complete: Insights aggregated");

            System.out.println("=== Stage 4 Assertions ===");
            assertCheck(aggregateResp != null, "Aggregate response is not null");
            if (!aggregateResp.isBlocked()) {
                assertCheck(aggregateResp.getData() != null, "Aggregate response data is not null");
            }
            System.out.println();

            // Stage 5: Report
            System.out.println("📈 Stage 5/5: Generating executive summary report...");
            ClientResponse reportResp = client.proxyLLMCall(
                    ClientRequest.builder()
                            .userToken("user-123")
                            .query("Create an executive summary report with:\n" +
                                    "1. Key metrics (total revenue, customer count, avg order value)\n" +
                                    "2. Segment analysis\n" +
                                    "3. Top actionable recommendations\n" +
                                    "4. Risk alerts (if any)\n" +
                                    "Format as a concise business report.")
                            .clientId(clientId)
                            .model("gpt-3.5-turbo")
                            .llmProvider("openai")
                            .context(Map.of("workflow", "data-pipeline-report"))
                            .build()
            );
            stagesCompleted++;

            double duration = (System.currentTimeMillis() - startTime) / 1000.0;

            System.out.println();
            System.out.println("📊 CUSTOMER ANALYTICS REPORT");
            System.out.println("============================================================");
            if (reportResp.isBlocked()) {
                System.out.println("BLOCKED: " + reportResp.getBlockReason());
            } else {
                System.out.println(reportResp.getData());
            }
            System.out.println("============================================================");
            System.out.println();

            // Final assertions
            System.out.println("=== Final Assertions ===");
            assertCheck(reportResp != null, "Report response is not null");
            if (!reportResp.isBlocked()) {
                assertCheck(reportResp.getData() != null, "Report response data is not null");
                String reportStr = String.valueOf(reportResp.getData());
                assertCheck(reportStr.length() > 100, "Report has substantial content (length > 100)");
            }
            assertCheck(stagesCompleted == 5, "All 5 pipeline stages completed");
            assertCheck(duration > 0, "Execution time was recorded");

            System.out.println();
            System.out.printf("⏱️  Pipeline completed in %.1f seconds%n", duration);
            System.out.println("✅ All 5 stages executed successfully");
            System.out.println("💡 Data pipeline: Extract → Clean → Enrich → Aggregate → Report");
        } catch (Exception e) {
            System.err.println("❌ Pipeline failed: " + e.getMessage());
            failures.add("Pipeline execution failed: " + e.getMessage());
        }

        // Exit with failure if any assertions failed
        if (!failures.isEmpty()) {
            System.err.println();
            System.err.println("❌ " + failures.size() + " assertion(s) failed:");
            for (String failure : failures) {
                System.err.println("   - " + failure);
            }
            System.exit(1);
        }
    }
}
