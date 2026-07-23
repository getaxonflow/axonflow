// Cloud Storage Connector Example - Go SDK
//
// Tests S3 cloud storage connector operations via the AxonFlow Go SDK.
// Uses MinIO as S3-compatible backend (started by docker compose).
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Usage:
//   docker compose up -d
//   cd examples/mcp-connectors/cloud-storage/go
//   go run main.go

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

// dataToRows converts ConnectorResponse.Data (interface{}) to a slice of maps.
// The MCP query endpoint returns data as a JSON array of objects.
func dataToRows(data interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	arr, ok := data.([]interface{})
	if !ok {
		return nil
	}
	rows := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			rows = append(rows, m)
		}
	}
	return rows
}

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "test-client"
	}
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "test-secret"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	ctx := context.Background()
	testKey := fmt.Sprintf("test-object-%d.txt", time.Now().UnixNano())
	testContent := fmt.Sprintf("Hello from AxonFlow Go SDK cloud storage example - %s", time.Now().UTC().Format(time.RFC3339))
	bucket := "axonflow-test-bucket"

	fmt.Println("==============================================")
	fmt.Println("Cloud Storage Connector - Go SDK Example")
	fmt.Println("==============================================")
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Test key: %s\n\n", testKey)

	// Test 1: Verify S3 connector is registered
	fmt.Println("Test 1: Verify S3 connector is registered...")
	fmt.Println("----------------------------------------------")

	connectors, err := client.ListConnectors()
	if err != nil {
		fmt.Printf("  Error listing connectors: %v\n", err)
		assertCheck(false, "List connectors succeeded")
	} else {
		foundS3 := false
		for _, c := range connectors {
			if c.Type == "s3" {
				foundS3 = true
				break
			}
		}
		if !foundS3 {
			fmt.Println("  NOTE: S3 connector is not registered in this environment.")
			fmt.Println("  To test cloud storage, configure an S3-compatible connector (e.g., MinIO).")
			fmt.Println("  See: docs/connectors/cloud-storage.md")
			fmt.Println("\nS3 connector not available — skipping cloud storage tests.")
			os.Exit(0)
		}
		assertCheck(foundS3, "S3 connector is registered")
	}
	fmt.Println()

	// Test 2: Put object
	fmt.Println("Test 2: Put object to S3 (MinIO)...")
	fmt.Println("----------------------------------------------")

	putResp, err := client.MCPExecute(ctx, axonflow.MCPExecuteRequest{
		Connector: "s3",
		Action:    "put_object",
		Params: map[string]interface{}{
			"bucket":       bucket,
			"key":          testKey,
			"content":      testContent,
			"content_type": "text/plain",
		},
	})
	if err != nil {
		fmt.Printf("  Error putting object: %v\n", err)
		assertCheck(false, "Put object succeeded")
	} else {
		assertCheck(putResp.Success, "Put object succeeded")
	}
	fmt.Println()

	// Test 3: Get object and verify content
	fmt.Println("Test 3: Get object and verify content...")
	fmt.Println("----------------------------------------------")

	getResp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "s3",
		Statement: "get_object",
		Options: map[string]interface{}{
			"bucket": bucket,
			"key":    testKey,
		},
	})
	if err != nil {
		fmt.Printf("  Error getting object: %v\n", err)
		assertCheck(false, "Get object returned data")
		assertCheck(false, "Content matches uploaded data")
	} else {
		rows := dataToRows(getResp.Data)
		assertCheck(len(rows) > 0, "Get object returned data")

		if len(rows) > 0 {
			content, _ := rows[0]["content"].(string)
			assertCheck(strings.Contains(content, "Hello from AxonFlow Go SDK"), "Content matches uploaded data")
		}
		assertCheck(getResp.PolicyInfo != nil, "Policy info present in response")
	}
	fmt.Println()

	// Test 4: List objects and verify key
	fmt.Println("Test 4: List objects and verify key exists...")
	fmt.Println("----------------------------------------------")

	listResp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "s3",
		Statement: "list_objects",
		Options: map[string]interface{}{
			"bucket": bucket,
			"prefix": "test-object-",
		},
	})
	if err != nil {
		fmt.Printf("  Error listing objects: %v\n", err)
		assertCheck(false, "List objects returned results")
		assertCheck(false, "Uploaded key found in listing")
	} else {
		rows := dataToRows(listResp.Data)
		assertCheck(len(rows) > 0, "List objects returned results")

		foundKey := false
		for _, row := range rows {
			if key, _ := row["key"].(string); key == testKey {
				foundKey = true
				break
			}
		}
		assertCheck(foundKey, "Uploaded key found in listing")
	}
	fmt.Println()

	// Test 5: Head object metadata
	fmt.Println("Test 5: Head object metadata...")
	fmt.Println("----------------------------------------------")

	headResp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "s3",
		Statement: "head_object",
		Options: map[string]interface{}{
			"bucket": bucket,
			"key":    testKey,
		},
	})
	if err != nil {
		fmt.Printf("  Error head object: %v\n", err)
		assertCheck(false, "Head object returned metadata")
	} else {
		rows := dataToRows(headResp.Data)
		assertCheck(len(rows) > 0, "Head object returned metadata")

		if len(rows) > 0 {
			ct, _ := rows[0]["content_type"].(string)
			assertCheck(strings.Contains(ct, "text/plain"), "Content-Type is text/plain")

			var size float64
			if s, ok := rows[0]["content_length"].(float64); ok {
				size = s
			} else if s, ok := rows[0]["size"].(float64); ok {
				size = s
			}
			assertCheck(size > 0, "Object has non-zero size")
		}
	}
	fmt.Println()

	// Test 6: Delete object
	fmt.Println("Test 6: Delete object...")
	fmt.Println("----------------------------------------------")

	delResp, err := client.MCPExecute(ctx, axonflow.MCPExecuteRequest{
		Connector: "s3",
		Action:    "delete_object",
		Params: map[string]interface{}{
			"bucket": bucket,
			"key":    testKey,
		},
	})
	if err != nil {
		fmt.Printf("  Error deleting object: %v\n", err)
		assertCheck(false, "Delete object succeeded")
	} else {
		assertCheck(delResp.Success, "Delete object succeeded")
	}
	fmt.Println()

	// Test 7: Verify deletion
	fmt.Println("Test 7: Verify object was deleted...")
	fmt.Println("----------------------------------------------")

	verifyResp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "s3",
		Statement: "list_objects",
		Options: map[string]interface{}{
			"bucket": bucket,
			"prefix": testKey,
		},
	})
	if err != nil {
		fmt.Printf("  Error verifying deletion: %v\n", err)
		assertCheck(false, "Deleted object no longer in listing")
	} else {
		rows := dataToRows(verifyResp.Data)
		foundKey := false
		for _, row := range rows {
			if key, _ := row["key"].(string); key == testKey {
				foundKey = true
				break
			}
		}
		assertCheck(!foundKey, "Deleted object no longer in listing")
	}
	fmt.Println()

	// Results
	fmt.Println("==============================================")
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL ASSERTIONS PASSED - Cloud storage connector tests verified!")
	fmt.Println("==============================================")
}
