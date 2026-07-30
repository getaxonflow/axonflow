package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.ConnectorInfo;
import com.getaxonflow.sdk.types.ConnectorQuery;
import com.getaxonflow.sdk.types.ConnectorResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Cloud Storage Connector Example - Java SDK
 *
 * Tests S3 cloud storage connector operations via the AxonFlow Java SDK.
 * Uses MinIO as S3-compatible backend (started by docker compose).
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * Usage:
 *   docker compose up -d
 *   cd examples/mcp-connectors/cloud-storage/java
 *   mvn compile exec:java
 */
public class CloudStorageExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   PASS: " + message);
        } else {
            System.out.println("   FAIL: " + message);
            failures.add(message);
        }
    }

    /** Convert ConnectorResponse.getData() to a list of maps. */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> dataToRows(Object data) {
        List<Map<String, Object>> rows = new ArrayList<>();
        if (data instanceof List<?>) {
            for (Object item : (List<?>) data) {
                if (item instanceof Map) {
                    rows.add((Map<String, Object>) item);
                }
            }
        }
        return rows;
    }

    /**
     * Runs a parameterised connector operation.
     *
     * <p>Java SDK 9.0.0 has no overload of {@code mcpExecute} that carries parameters —
     * {@code mcpExecute(connector, statement)} is a two-argument alias for {@code mcpQuery}.
     * {@code mcpQuery(connector, statement, options)} does take a third argument, but
     * serialises it under the JSON key {@code "options"}, and the agent's request struct has
     * no such field — only {@code "parameters"}. So {@code queryConnector(ConnectorQuery)} is
     * the only call on this client that actually DELIVERS parameters to a connector; it is the
     * shape the Python sibling of this example uses for every one of its steps.
     *
     * <p><b>Two known limitations, both tracked in #3192.</b>
     *
     * <p>First: the {@code mcpQuery} calls below (Tests 3, 4, 5 and 7) have the same
     * {@code "options"} problem, so their bucket and key do not reach the connector. They are
     * left on {@code mcpQuery} rather than converted because {@code queryConnector} is not a
     * drop-in substitute for a read — it returns the router's envelope shape rather than a row
     * array, so {@code dataToRows} would yield nothing, and it hardcodes {@code policyInfo} to
     * null, so the policy-info assertion in Test 3 would flip to FAIL. Converting them is part
     * of the SDK fix, not a local edit.
     *
     * <p>Second: even with parameters delivered, the Java, Python and TypeScript SDKs all reach
     * the agent's {@code /mcp/resources/query} route, which dispatches to the connector's
     * read-side {@code Query}. S3 write actions ({@code put_object}, {@code delete_object})
     * live on the connector's {@code Execute} side behind {@code /mcp/tools/execute}, which
     * only the Go SDK and the {@code http/} sibling of this example call.
     *
     * <p>This example therefore compiles and runs, but its S3 assertions cannot pass against a
     * real MinIO backend until #3192 lands. The Go and {@code http/} siblings are the ones to
     * follow for a working cloud-storage walkthrough today.
     */
    private static ConnectorResponse runOperation(AxonFlow client, String connectorId,
                                                  String operation, Map<String, Object> params) {
        return client.queryConnector(ConnectorQuery.builder()
            .connectorId(connectorId)
            .operation(operation)
            .parameters(params)
            .build());
    }

    public static void main(String[] args) {
        String endpoint = System.getenv().getOrDefault("AXONFLOW_ENDPOINT", "http://localhost:8080");
        String clientId = System.getenv().getOrDefault("AXONFLOW_CLIENT_ID", "test-client");
        String clientSecret = System.getenv().getOrDefault("AXONFLOW_CLIENT_SECRET", "test-secret");

        AxonFlow client = AxonFlow.create(
            AxonFlowConfig.builder()
                .endpoint(endpoint)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build()
        );

        String testKey = "test-object-" + System.currentTimeMillis() + ".txt";
        String testContent = "Hello from AxonFlow Java SDK cloud storage example - " + Instant.now();
        String bucket = "axonflow-test-bucket";

        System.out.println("==============================================");
        System.out.println("Cloud Storage Connector - Java SDK Example");
        System.out.println("==============================================");
        System.out.println("Endpoint: " + endpoint);
        System.out.println("Test key: " + testKey);
        System.out.println();

        // Test 1: Verify S3 connector is registered
        System.out.println("Test 1: Verify S3 connector is registered...");
        System.out.println("----------------------------------------------");

        try {
            List<ConnectorInfo> connectors = client.listConnectors();
            boolean hasS3 = connectors.stream().anyMatch(c -> "s3".equals(c.getType()));
            assertCheck(hasS3, "S3 connector is registered");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "List connectors succeeded");
        }
        System.out.println();

        // Test 2: Put object
        System.out.println("Test 2: Put object to S3 (MinIO)...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> putParams = new HashMap<>();
            putParams.put("bucket", bucket);
            putParams.put("key", testKey);
            putParams.put("content", testContent);
            putParams.put("content_type", "text/plain");

            ConnectorResponse putResp = runOperation(client, "s3", "put_object", putParams);
            assertCheck(putResp.isSuccess(), "Put object succeeded");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "Put object succeeded");
        }
        System.out.println();

        // Test 3: Get object and verify content
        System.out.println("Test 3: Get object and verify content...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> getParams = new HashMap<>();
            getParams.put("bucket", bucket);
            getParams.put("key", testKey);

            ConnectorResponse getResp = client.mcpQuery("s3", "get_object", getParams);
            List<Map<String, Object>> rows = dataToRows(getResp.getData());
            assertCheck(!rows.isEmpty(), "Get object returned data");

            if (!rows.isEmpty()) {
                String content = String.valueOf(rows.get(0).getOrDefault("content", ""));
                assertCheck(content.contains("Hello from AxonFlow Java SDK"), "Content matches uploaded data");
            }
            assertCheck(getResp.getPolicyInfo() != null, "Policy info present in response");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "Get object returned data");
        }
        System.out.println();

        // Test 4: List objects and verify key
        System.out.println("Test 4: List objects and verify key exists...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> listParams = new HashMap<>();
            listParams.put("bucket", bucket);
            listParams.put("prefix", "test-object-");

            ConnectorResponse listResp = client.mcpQuery("s3", "list_objects", listParams);
            List<Map<String, Object>> rows = dataToRows(listResp.getData());
            assertCheck(!rows.isEmpty(), "List objects returned results");

            boolean foundKey = rows.stream()
                .anyMatch(r -> testKey.equals(r.getOrDefault("key", "")));
            assertCheck(foundKey, "Uploaded key found in listing");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "List objects returned results");
        }
        System.out.println();

        // Test 5: Head object metadata
        System.out.println("Test 5: Head object metadata...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> headParams = new HashMap<>();
            headParams.put("bucket", bucket);
            headParams.put("key", testKey);

            ConnectorResponse headResp = client.mcpQuery("s3", "head_object", headParams);
            List<Map<String, Object>> rows = dataToRows(headResp.getData());
            assertCheck(!rows.isEmpty(), "Head object returned metadata");

            if (!rows.isEmpty()) {
                Map<String, Object> row = rows.get(0);
                String ct = String.valueOf(row.getOrDefault("content_type", ""));
                assertCheck(ct.contains("text/plain"), "Content-Type is text/plain");

                Object sizeObj = row.getOrDefault("content_length", row.getOrDefault("size", 0));
                long size = sizeObj instanceof Number ? ((Number) sizeObj).longValue() : 0;
                assertCheck(size > 0, "Object has non-zero size");
            }
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "Head object returned metadata");
        }
        System.out.println();

        // Test 6: Delete object
        System.out.println("Test 6: Delete object...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> delParams = new HashMap<>();
            delParams.put("bucket", bucket);
            delParams.put("key", testKey);

            ConnectorResponse delResp = runOperation(client, "s3", "delete_object", delParams);
            assertCheck(delResp.isSuccess(), "Delete object succeeded");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "Delete object succeeded");
        }
        System.out.println();

        // Test 7: Verify deletion
        System.out.println("Test 7: Verify object was deleted...");
        System.out.println("----------------------------------------------");

        try {
            Map<String, Object> verifyParams = new HashMap<>();
            verifyParams.put("bucket", bucket);
            verifyParams.put("prefix", testKey);

            ConnectorResponse verifyResp = client.mcpQuery("s3", "list_objects", verifyParams);
            List<Map<String, Object>> rows = dataToRows(verifyResp.getData());

            boolean foundKey = rows.stream()
                .anyMatch(r -> testKey.equals(r.getOrDefault("key", "")));
            assertCheck(!foundKey, "Deleted object no longer in listing");
        } catch (Exception e) {
            System.out.println("  Error: " + e.getMessage());
            assertCheck(false, "Deleted object no longer in listing");
        }
        System.out.println();

        // Results
        System.out.println("==============================================");
        if (!failures.isEmpty()) {
            System.out.println("FAILED: " + failures.size() + " assertions failed");
            failures.forEach(f -> System.out.println("  - " + f));
            System.exit(1);
        }

        System.out.println("ALL ASSERTIONS PASSED - Cloud storage connector tests verified!");
        System.out.println("==============================================");
    }
}
