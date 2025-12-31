/**
 * MCP Connector Example - Tests Orchestrator-to-Agent Routing
 *
 * This example tests the FULL MCP connector flow:
 *   SDK -> Orchestrator (port 8081) -> Agent (port 8080) -> Connector
 *
 * Usage:
 *   docker compose up -d  # Start AxonFlow
 *   cd examples/mcp-connectors/java
 *   java McpConnectorExample.java  # Java 11+
 */

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class McpConnectorExample {
    
    public static void main(String[] args) throws Exception {
        String orchestratorUrl = System.getenv("ORCHESTRATOR_URL");
        if (orchestratorUrl == null || orchestratorUrl.isEmpty()) {
            orchestratorUrl = "http://localhost:8081";
        }

        System.out.println("==============================================");
        System.out.println("MCP Connector Example - Orchestrator Routing");
        System.out.println("==============================================");
        System.out.println("Orchestrator URL: " + orchestratorUrl + "\n");

        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

        // Test 1: Query postgres connector through orchestrator
        System.out.println("Test 1: Query postgres connector via orchestrator...");

        String requestId = "mcp-test-" + System.currentTimeMillis();
        String requestBody = String.format("""
            {
                "request_id": "%s",
                "query": "SELECT 1 as test_value, 'hello' as test_message",
                "request_type": "mcp-query",
                "user": {
                    "email": "test@example.com",
                    "role": "user",
                    "tenant_id": "default"
                },
                "client": {
                    "id": "test-client",
                    "tenant_id": "default"
                },
                "context": {
                    "connector": "postgres",
                    "params": {}
                }
            }
            """, requestId);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(orchestratorUrl + "/api/v1/process"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String responseBody = response.body();

        if (responseBody.contains("\"success\":true")) {
            System.out.println("SUCCESS: MCP query through orchestrator worked!");
            System.out.println("  Response: " + responseBody.substring(0, Math.min(200, responseBody.length())) + "...");
        } else {
            System.out.println("FAILED: " + responseBody);
            System.exit(1);
        }

        // Test 2: Query with database alias
        System.out.println("\nTest 2: Query 'database' connector (alias for postgres)...");

        requestId = "mcp-test-" + System.currentTimeMillis();
        requestBody = String.format("""
            {
                "request_id": "%s",
                "query": "SELECT 1 as test_value",
                "request_type": "mcp-query",
                "user": {
                    "email": "test@example.com",
                    "role": "user",
                    "tenant_id": "default"
                },
                "client": {
                    "id": "test-client",
                    "tenant_id": "default"
                },
                "context": {
                    "connector": "database",
                    "params": {}
                }
            }
            """, requestId);

        request = HttpRequest.newBuilder()
            .uri(URI.create(orchestratorUrl + "/api/v1/process"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

        response = client.send(request, HttpResponse.BodyHandlers.ofString());
        responseBody = response.body();

        if (responseBody.contains("\"success\":true")) {
            System.out.println("SUCCESS: Database alias connector worked!");
        } else {
            System.out.println("FAILED: " + responseBody);
            System.exit(1);
        }

        System.out.println("\n==============================================");
        System.out.println("All MCP connector tests PASSED!");
        System.out.println("==============================================");
    }
}
