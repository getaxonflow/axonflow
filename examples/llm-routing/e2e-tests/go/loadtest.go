// Concurrent Requests Load Test using Go
// Tests parallel request handling and routing distribution under load
//
// Usage:
//   go run load_test.go
//   CONCURRENT=20 TOTAL=100 go run load_test.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type ProcessRequest struct {
	Query       string                 `json:"query"`
	RequestType string                 `json:"request_type"`
	User        map[string]string      `json:"user"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

type ProcessResponse struct {
	Success      bool `json:"success"`
	ProviderInfo struct {
		Provider       string  `json:"provider"`
		Model          string  `json:"model"`
		ResponseTimeMs int64   `json:"response_time_ms"`
		Cost           float64 `json:"cost"`
	} `json:"provider_info"`
}

type Result struct {
	Success      bool
	Provider     string
	ResponseTime time.Duration
	Error        error
}

func main() {
	baseURL := os.Getenv("ORCHESTRATOR_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8081"
	}

	concurrent := 10
	if c := os.Getenv("CONCURRENT"); c != "" {
		if v, err := strconv.Atoi(c); err == nil {
			concurrent = v
		}
	}

	total := 30
	if t := os.Getenv("TOTAL"); t != "" {
		if v, err := strconv.Atoi(t); err == nil {
			total = v
		}
	}

	fmt.Println("========================================")
	fmt.Println("Concurrent Requests Load Test (Go)")
	fmt.Println("========================================")
	fmt.Printf("Target: %s\n", baseURL)
	fmt.Printf("Concurrent: %d\n", concurrent)
	fmt.Printf("Total requests: %d\n\n", total)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	// Test 1: Baseline
	fmt.Println("Test 1: Baseline (single request)")
	start := time.Now()
	result := makeRequest(client, baseURL)
	baseline := time.Since(start)
	fmt.Printf("  Response time: %dms\n", baseline.Milliseconds())
	if result.Success {
		fmt.Printf("  Provider: %s\n", result.Provider)
	}
	fmt.Println()

	// Test 2: Concurrent burst
	fmt.Printf("Test 2: Concurrent burst (%d parallel requests)\n", concurrent)
	results := runConcurrent(client, baseURL, concurrent, concurrent)
	printResults(results, concurrent)
	fmt.Println()

	// Test 3: Sustained load
	fmt.Printf("Test 3: Sustained load (%d requests, %d concurrent)\n", total, concurrent)
	results = runConcurrent(client, baseURL, total, concurrent)
	printResults(results, total)
	fmt.Println()

	// Test 4: Response time percentiles
	fmt.Println("Test 4: Response time percentiles")
	var times []int64
	for _, r := range results {
		if r.Success {
			times = append(times, r.ResponseTime.Milliseconds())
		}
	}
	if len(times) > 0 {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		fmt.Printf("  Min: %dms\n", times[0])
		fmt.Printf("  P50: %dms\n", times[len(times)/2])
		fmt.Printf("  P95: %dms\n", times[int(float64(len(times))*0.95)])
		fmt.Printf("  P99: %dms\n", times[int(float64(len(times))*0.99)])
		fmt.Printf("  Max: %dms\n", times[len(times)-1])
	}
	fmt.Println()

	fmt.Println("========================================")
	fmt.Println("Load Test Complete")
	fmt.Println("========================================")
}

func makeRequest(client *http.Client, baseURL string) Result {
	req := ProcessRequest{
		Query:       "Hello",
		RequestType: "chat",
		User:        map[string]string{"email": "test@example.com", "role": "user"},
	}

	body, _ := json.Marshal(req)
	start := time.Now()

	resp, err := client.Post(baseURL+"/api/v1/process", "application/json", bytes.NewReader(body))
	elapsed := time.Since(start)

	if err != nil {
		return Result{Success: false, ResponseTime: elapsed, Error: err}
	}
	defer resp.Body.Close()

	var response ProcessResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Result{Success: false, ResponseTime: elapsed, Error: err}
	}

	return Result{
		Success:      response.Success,
		Provider:     response.ProviderInfo.Provider,
		ResponseTime: elapsed,
	}
}

func runConcurrent(client *http.Client, baseURL string, total, concurrent int) []Result {
	results := make([]Result, total)
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrent)
	var completed int64

	start := time.Now()

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = makeRequest(client, baseURL)
			atomic.AddInt64(&completed, 1)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("  Total time: %dms\n", elapsed.Milliseconds())
	fmt.Printf("  Throughput: %.2f req/sec\n", float64(total)/elapsed.Seconds())

	return results
}

func printResults(results []Result, total int) {
	var success, failed int
	providers := make(map[string]int)

	for _, r := range results {
		if r.Success {
			success++
			providers[r.Provider]++
		} else {
			failed++
		}
	}

	fmt.Printf("  Successful: %d / %d\n", success, total)
	fmt.Printf("  Failed: %d\n", failed)
	fmt.Println("  Provider distribution:")
	for p, count := range providers {
		fmt.Printf("    %s: %d (%.1f%%)\n", p, count, float64(count)*100/float64(total))
	}
}
