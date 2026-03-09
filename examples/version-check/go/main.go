// Package main demonstrates SDK-platform version discovery using the Go SDK.
//
// The health endpoint returns platform version, capabilities, and SDK
// compatibility information. Use HealthCheckDetailed() to access this data.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("Version Discovery — Go SDK")
	fmt.Println("==========================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// ---------------------------------------------------------------
	// Test 1: HealthCheckDetailed returns version and capabilities
	// ---------------------------------------------------------------
	fmt.Println("Test 1: HealthCheckDetailed — Version and Capabilities")
	fmt.Println("------------------------------------------------------")

	health, err := client.HealthCheckDetailed()
	if err != nil {
		fmt.Printf("   FAIL: HealthCheckDetailed error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Platform version: %s\n", health.Version)
	fmt.Printf("   Service: %s\n", health.Service)
	fmt.Printf("   Status: %s\n", health.Status)
	fmt.Printf("   Capabilities: %d\n", len(health.Capabilities))

	assert(health.Version != "", "version is non-empty")
	assert(health.Status == "healthy" || health.Status == "starting", "status is healthy or starting")
	assert(len(health.Capabilities) > 0, "capabilities list is non-empty")
	assert(health.SDKCompat != nil, "sdk_compatibility is present")

	if health.SDKCompat != nil {
		fmt.Printf("   Min SDK: %s\n", health.SDKCompat.MinSDKVersion)
		fmt.Printf("   Recommended SDK: %s\n", health.SDKCompat.RecommendedSDKVersion)
		assert(health.SDKCompat.MinSDKVersion != "", "min_sdk_version is non-empty")
		assert(health.SDKCompat.RecommendedSDKVersion != "", "recommended_sdk_version is non-empty")
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 2: HasCapability
	// ---------------------------------------------------------------
	fmt.Println("Test 2: HasCapability")
	fmt.Println("---------------------")

	assert(health.HasCapability("health_check"), "HasCapability('health_check') = true")
	assert(health.HasCapability("version_discovery"), "HasCapability('version_discovery') = true")
	assert(!health.HasCapability("nonexistent_feature"), "HasCapability('nonexistent_feature') = false")
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 3: List all capabilities
	// ---------------------------------------------------------------
	fmt.Println("Test 3: All Capabilities")
	fmt.Println("------------------------")
	for _, cap := range health.Capabilities {
		fmt.Printf("   - %s (since %s): %s\n", cap.Name, cap.Since, cap.Description)
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 4: SDK version info
	// ---------------------------------------------------------------
	fmt.Println("Test 4: SDK Version")
	fmt.Println("-------------------")
	fmt.Printf("   SDK version: %s\n", axonflow.Version)
	assert(axonflow.Version != "", "SDK version is non-empty")
	fmt.Println()

	// ---------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------
	fmt.Println("==========================")
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d failures\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL PASSED")
}
