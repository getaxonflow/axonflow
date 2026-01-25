/*
 * Example 5: Data Pipeline Workflow - Java
 *
 * Demonstrates a 5-stage data pipeline: Extract → Clean → Enrich → Aggregate → Report
 */
package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ExecuteQueryRequest;
import com.getaxonflow.sdk.types.ExecuteResponse;

import java.util.Map;
import java.util.Optional;

public class Main {

    public static void main(String[] args) {
        String agentUrl = Optional.ofNullable(System.getenv("AXONFLOW_AGENT_URL"))
                .orElse("http://localhost:8080");
        String clientId = System.getenv("AXONFLOW_CLIENT_ID");
        String clientSecret = System.getenv("AXONFLOW_CLIENT_SECRET");

        if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
            System.err.println("❌ AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set");
            System.exit(1);
        }

        AxonFlowConfig config = AxonFlowConfig.builder()
                .endpoint(agentUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();

        AxonFlow client = new AxonFlow(config);

        System.out.println("✅ Connected to AxonFlow");
        System.out.println("🔄 Starting 5-stage data pipeline for customer analytics...");
        System.out.println();

        long startTime = System.currentTimeMillis();

        try {
            // Stage 1: Extract
            System.out.println("📥 Stage 1/5: Extracting customer transaction data...");
            client.proxyLLMCall(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Extract customer purchase data from the last 30 days. Include customer ID, purchase amount, product categories, and timestamps. Simulate 500 customer transactions.")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );
            System.out.println("✅ Stage 1 complete: Data extracted");
            System.out.println();

            // Stage 2: Transform (Clean & Normalize)
            System.out.println("🧹 Stage 2/5: Cleaning and normalizing data...");
            client.proxyLLMCall(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("From the extracted data above, perform the following transformations:\n" +
                                    "1. Remove duplicate transactions\n" +
                                    "2. Standardize date formats to ISO 8601\n" +
                                    "3. Normalize product category names\n" +
                                    "4. Validate all amounts are positive numbers\n" +
                                    "5. Flag any anomalies (unusually high amounts)")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );
            System.out.println("✅ Stage 2 complete: Data cleaned and normalized");
            System.out.println();

            // Stage 3: Enrich
            System.out.println("💎 Stage 3/5: Enriching with customer segments and lifetime value...");
            client.proxyLLMCall(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Based on the cleaned transaction data:\n" +
                                    "1. Calculate customer lifetime value (CLV)\n" +
                                    "2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)\n" +
                                    "3. Identify top-spending product categories per segment\n" +
                                    "4. Calculate average order value per segment")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );
            System.out.println("✅ Stage 3 complete: Data enriched with segments and metrics");
            System.out.println();

            // Stage 4: Aggregate
            System.out.println("📊 Stage 4/5: Aggregating insights and trends...");
            client.proxyLLMCall(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Generate aggregated insights:\n" +
                                    "1. Total revenue by customer segment\n" +
                                    "2. Growth trends (week-over-week)\n" +
                                    "3. Top 5 products by revenue\n" +
                                    "4. Customer churn risk indicators\n" +
                                    "5. Recommended actions for each segment")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );
            System.out.println("✅ Stage 4 complete: Insights aggregated");
            System.out.println();

            // Stage 5: Report
            System.out.println("📈 Stage 5/5: Generating executive summary report...");
            ExecuteResponse reportResp = client.proxyLLMCall(
                    ExecuteQueryRequest.builder()
                            .userToken("user-123")
                            .query("Create an executive summary report with:\n" +
                                    "1. Key metrics (total revenue, customer count, avg order value)\n" +
                                    "2. Segment analysis\n" +
                                    "3. Top actionable recommendations\n" +
                                    "4. Risk alerts (if any)\n" +
                                    "Format as a concise business report.")
                            .requestType("chat")
                            .context(Map.of("model", "gpt-4"))
                            .build()
            );

            double duration = (System.currentTimeMillis() - startTime) / 1000.0;

            System.out.println();
            System.out.println("📊 CUSTOMER ANALYTICS REPORT");
            System.out.println("============================================================");
            System.out.println(reportResp.getData());
            System.out.println("============================================================");
            System.out.println();
            System.out.printf("⏱️  Pipeline completed in %.1f seconds%n", duration);
            System.out.println("✅ All 5 stages executed successfully");
            System.out.println("💡 Data pipeline: Extract → Clean → Enrich → Aggregate → Report");
        } catch (Exception e) {
            System.err.println("❌ Pipeline failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
