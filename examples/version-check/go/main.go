// Package main demonstrates SDK-platform version discovery using the Go SDK.
//
// The health endpoint returns platform version, capabilities, and SDK
// compatibility information. Uses HealthCheck() for basic health and
// raw HTTP for detailed version discovery (sdk_compatibility returns
// per-language version objects).
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// healthResponse represents the full health endpoint response with
// per-language version maps for SDK compatibility.
type healthResponse struct {
	Status       string                   `json:"status"`
	Version      string                   `json:"version"`
	Service      string                   `json:"service"`
	Capabilities []map[string]interface{} `json:"capabilities"`
	SDKCompat    *sdkCompat               `json:"sdk_compatibility"`
}

type sdkCompat struct {
	MinSDKVersion         map[string]string `json:"min_sdk_version"`
	RecommendedSDKVersion map[string]string `json:"recommended_sdk_version"`
}

func (h *healthResponse) HasCapability(name string) bool {
	for _, cap := range h.Capabilities {
		if cap["name"] == name {
			return true
		}
	}
	return false
}

func main() {
	fmt.Println("Version Discovery — Go SDK")
	fmt.Println("==========================")
	fmt.Println()

	endpoint := getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// ---------------------------------------------------------------
	// Test 1: Basic HealthCheck via SDK
	// ---------------------------------------------------------------
	fmt.Println("Test 1: HealthCheck — Basic Health via SDK")
	fmt.Println("------------------------------------------")

	err := client.HealthCheck()
	if err != nil {
		fmt.Printf("   FAIL: HealthCheck error: %v\n", err)
		os.Exit(1)
	}

	assert(true, "HealthCheck() succeeded (agent is reachable)")
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 2: Detailed health via raw HTTP (per-language version maps)
	// ---------------------------------------------------------------
	fmt.Println("Test 2: Detailed Health — Version and Capabilities")
	fmt.Println("--------------------------------------------------")

	resp, err := http.Get(endpoint + "/health")
	if err != nil {
		fmt.Printf("   FAIL: HTTP GET /health error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("   FAIL: Read body error: %v\n", err)
		os.Exit(1)
	}

	var health healthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		fmt.Printf("   FAIL: Parse health response error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Platform version: %s\n", health.Version)
	fmt.Printf("   Service: %s\n", health.Service)
	fmt.Printf("   Capabilities: %d\n", len(health.Capabilities))

	assert(health.Version != "", "detailed version is non-empty")
	assert(len(health.Capabilities) > 0, "capabilities list is non-empty")
	assert(health.SDKCompat != nil, "sdk_compatibility is present")

	if health.SDKCompat != nil {
		goMin := health.SDKCompat.MinSDKVersion["go"]
		goRec := health.SDKCompat.RecommendedSDKVersion["go"]
		fmt.Printf("   Min Go SDK: %s\n", goMin)
		fmt.Printf("   Recommended Go SDK: %s\n", goRec)
		assert(goMin != "", "min_sdk_version['go'] is non-empty")
		assert(goRec != "", "recommended_sdk_version['go'] is non-empty")
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 3: HasCapability
	// ---------------------------------------------------------------
	fmt.Println("Test 3: HasCapability")
	fmt.Println("---------------------")

	assert(health.HasCapability("health_check"), "HasCapability('health_check') = true")
	assert(health.HasCapability("version_discovery"), "HasCapability('version_discovery') = true")
	assert(!health.HasCapability("nonexistent_feature"), "HasCapability('nonexistent_feature') = false")
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 4: List all capabilities
	// ---------------------------------------------------------------
	fmt.Println("Test 4: All Capabilities")
	fmt.Println("------------------------")
	for _, cap := range health.Capabilities {
		name, _ := cap["name"].(string)
		since, _ := cap["since"].(string)
		desc, _ := cap["description"].(string)
		fmt.Printf("   - %s (since %s): %s\n", name, since, desc)
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 5: SDK version info
	// ---------------------------------------------------------------
	fmt.Println("Test 5: SDK Version")
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
