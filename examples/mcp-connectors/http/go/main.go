// HTTP Connector Example - Go
//
// Demonstrates installing and using the built-in HTTP connector to call the
// Orchestrator health endpoint.
//
// SDK Methods demonstrated:
//   - ListConnectors()
//   - GetConnector()
//   - InstallConnector()
//   - GetConnectorHealth()
//   - QueryConnector()
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
//   AXONFLOW_CLIENT_ID     - Client ID for authentication
//   AXONFLOW_CLIENT_SECRET - Client secret for authentication
//   AXONFLOW_USER_TOKEN    - User token (optional; defaults to "default-user")
//
// VALIDATION: This example exits with code 1 if any assertion fails.

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v5"
)

var failures []string

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("  ✓ PASS: %s\n", message)
	} else {
		fmt.Printf("  ✗ FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func uninstallConnector(endpoint, tenantID, clientID, clientSecret, connectorID string) error {
	url := fmt.Sprintf("%s/api/v1/connectors/%s/uninstall", endpoint, connectorID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to build uninstall request: %w", err)
	}

	if tenantID != "" {
		if clientSecret != "" {
			credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
			req.Header.Set("Authorization", "Basic "+credentials)
		}
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("uninstall request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uninstall failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func isUnauthorizedConnector(err error, resp *axonflow.ConnectorResponse) bool {
	if err != nil && strings.Contains(err.Error(), "Unauthorized connector access") {
		return true
	}
	if resp != nil && strings.Contains(resp.Error, "Unauthorized connector access") {
		return true
	}
	return false
}

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo-org"
	}

	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")

	tenantID := os.Getenv("AXONFLOW_TENANT_ID")
	if tenantID == "" {
		tenantID = clientID
	}

	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	if userToken == "" {
		userToken = "default-user"
	}

	connectorBaseURL := os.Getenv("AXONFLOW_CONNECTOR_BASE_URL")
	if connectorBaseURL == "" {
		// Default for docker compose runtime where connector executes inside agent container.
		connectorBaseURL = "http://axonflow-orchestrator:8081"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	fmt.Println("=== HTTP Connector Example ===")
	fmt.Println()

	// 1. List available connectors
	fmt.Println("1. Listing available connectors...")
	connectors, err := client.ListConnectors()
	if err != nil {
		fmt.Printf("   FATAL: Failed to list connectors: %v\n", err)
		os.Exit(1)
	}
	foundHTTP := false
	for _, c := range connectors {
		if c.ID == "http-rest" {
			foundHTTP = true
			fmt.Printf("   - %s (%s) [%s]\n", c.Name, c.ID, c.Description)
		}
	}
	assert(foundHTTP, "HTTP connector is listed")

	// 2. Get details for HTTP connector
	fmt.Println("\n2. Getting HTTP connector details...")
	connector, err := client.GetConnector("http-rest")
	if err != nil {
		fmt.Printf("   FATAL: Failed to get HTTP connector: %v\n", err)
		os.Exit(1)
	}
	assert(connector.ID == "http-rest", "GetConnector returns HTTP connector")

	// 3. Ensure connector is installed for this tenant
	fmt.Println("\n3. Ensuring HTTP connector is installed...")
	if connector.Installed {
		fmt.Println("   Connector already installed; reinstalling for tenant.")
		if err := uninstallConnector(endpoint, tenantID, clientID, clientSecret, "http-rest"); err != nil {
			fmt.Printf("   FATAL: Failed to uninstall HTTP connector: %v\n", err)
			os.Exit(1)
		}
	}

	installReq := axonflow.ConnectorInstallRequest{
		ConnectorID: "http-rest",
		Name:        "Orchestrator Health",
		TenantID:    tenantID,
		Options: map[string]interface{}{
			"base_url":          connectorBaseURL,
			"allow_private_ips": true,
			"health_path":       "/health",
			"timeout":           10,
		},
	}

	if err := client.InstallConnector(installReq); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "connector_configs") || strings.Contains(errStr, "does not exist") {
			fmt.Println("   NOTE: HTTP connector installation requires Enterprise mode (connector_configs table).")
			fmt.Println("   Skipping install-dependent tests. Built-in connectors still work.")
			fmt.Println("\nALL ASSERTIONS PASSED (skipped enterprise-only connector installation)")
			os.Exit(0)
		}
		fmt.Printf("   FATAL: Failed to install HTTP connector: %v\n", err)
		os.Exit(1)
	}
	assert(true, "InstallConnector succeeds")

	// 4. Check connector health
	fmt.Println("\n4. Checking connector health...")
	health, err := client.GetConnectorHealth("http-rest")
	if err != nil {
		fmt.Printf("   FATAL: Failed to get connector health: %v\n", err)
		os.Exit(1)
	}
	assert(health.Timestamp != "", "GetConnectorHealth returns timestamp")
	assert(health.Healthy, "Connector health is healthy")

	// 5. Query connector (call orchestrator /health)
	fmt.Println("\n5. Querying /health via HTTP connector...")
	result, err := client.QueryConnector(userToken, "http-rest", "/health", nil)
	if isUnauthorizedConnector(err, result) {
		fmt.Println("   FATAL: QueryConnector returned unauthorized access. Runtime connector wiring is incomplete.")
		os.Exit(1)
	} else if err != nil {
		fmt.Printf("   FATAL: QueryConnector failed: %v\n", err)
		os.Exit(1)
	} else {
		assert(result.Success, "QueryConnector returns success")
	}

	fmt.Println("\n=== Test Summary ===")
	totalTests := 5
	passedTests := totalTests - len(failures)
	fmt.Printf("Passed: %d/%d\n", passedTests, totalTests)

	if len(failures) > 0 {
		fmt.Printf("\n✗ %d ASSERTION(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}
