// Azure OpenAI Integration Example - Go
// Demonstrates Gateway Mode and Proxy Mode with AxonFlow

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	axonflowURL = "http://localhost:8080"
	timeout     = 30 * time.Second
)

func main() {
	// Get Azure OpenAI credentials from environment
	endpoint := os.Getenv("AZURE_OPENAI_ENDPOINT")
	apiKey := os.Getenv("AZURE_OPENAI_API_KEY")
	deploymentName := os.Getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
	apiVersion := os.Getenv("AZURE_OPENAI_API_VERSION")

	if endpoint == "" || apiKey == "" || deploymentName == "" {
		fmt.Println("Error: Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT_NAME")
		os.Exit(1)
	}

	if apiVersion == "" {
		apiVersion = "2024-08-01-preview"
	}

	fmt.Println("=== Azure OpenAI with AxonFlow ===")
	fmt.Printf("Endpoint: %s\n", endpoint)
	fmt.Printf("Deployment: %s\n", deploymentName)
	fmt.Printf("Auth: %s\n", detectAuthType(endpoint))
	fmt.Println()

	// Example 1: Gateway Mode (recommended)
	fmt.Println("--- Example 1: Gateway Mode ---")
	if err := gatewayModeExample(endpoint, apiKey, deploymentName, apiVersion); err != nil {
		fmt.Printf("Gateway mode error: %v\n", err)
	}
	fmt.Println()

	// Example 2: Proxy Mode
	fmt.Println("--- Example 2: Proxy Mode ---")
	if err := proxyModeExample(); err != nil {
		fmt.Printf("Proxy mode error: %v\n", err)
	}
}

// detectAuthType determines authentication type from endpoint
func detectAuthType(endpoint string) string {
	if strings.Contains(strings.ToLower(endpoint), "cognitiveservices.azure.com") {
		return "Bearer token (Foundry)"
	}
	return "api-key (Classic)"
}

// gatewayModeExample demonstrates Gateway Mode:
// 1. Pre-check with AxonFlow
// 2. Call Azure OpenAI directly
// 3. Audit the response with AxonFlow
func gatewayModeExample(endpoint, apiKey, deploymentName, apiVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	userPrompt := "What are the key benefits of using Azure OpenAI over standard OpenAI API?"

	// Step 1: Pre-check with AxonFlow
	fmt.Println("Step 1: Pre-checking with AxonFlow...")
	preCheckResp, err := preCheck(ctx, userPrompt, "azure-openai", deploymentName)
	if err != nil {
		return fmt.Errorf("pre-check failed: %w", err)
	}

	if !preCheckResp.Approved {
		fmt.Printf("Request blocked by policy\n")
		return nil
	}
	fmt.Printf("Pre-check passed (context: %s)\n", preCheckResp.ContextID)

	// Step 2: Call Azure OpenAI directly
	fmt.Println("Step 2: Calling Azure OpenAI...")
	startTime := time.Now()

	azureURL := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		strings.TrimRight(endpoint, "/"), deploymentName, apiVersion)

	reqBody := map[string]any{
		"messages": []map[string]string{
			{"role": "user", "content": userPrompt},
		},
		"max_tokens":  500,
		"temperature": 0.7,
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", azureURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Set auth header based on endpoint type
	if strings.Contains(strings.ToLower(endpoint), "cognitiveservices.azure.com") {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Set("api-key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Azure OpenAI error (status %d): %s", resp.StatusCode, string(body))
	}

	var azureResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&azureResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	latency := time.Since(startTime)
	content := ""
	if len(azureResp.Choices) > 0 {
		content = azureResp.Choices[0].Message.Content
	}

	fmt.Printf("Response received (latency: %v)\n", latency)
	fmt.Printf("Response: %s...\n", truncate(content, 200))

	// Step 3: Audit the response
	fmt.Println("Step 3: Auditing with AxonFlow...")
	if err := auditLLMCall(ctx, preCheckResp.ContextID, content, "azure-openai", deploymentName, latency, azureResp.Usage.PromptTokens, azureResp.Usage.CompletionTokens); err != nil {
		fmt.Printf("Audit warning: %v\n", err)
	} else {
		fmt.Println("Audit logged successfully")
	}

	return nil
}

// proxyModeExample demonstrates Proxy Mode:
// Send request to AxonFlow, which handles the Azure OpenAI call
func proxyModeExample() error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Println("Sending request through AxonFlow proxy...")

	reqBody := map[string]any{
		"query": "Explain the difference between Azure OpenAI Classic and Foundry patterns in 2 sentences.",
		"context": map[string]string{
			"provider": "azure-openai",
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", axonflowURL+"/api/request", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	startTime := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AxonFlow error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse the actual AxonFlow response structure
	var proxyResp struct {
		Success bool `json:"success"`
		Data    struct {
			Data     string `json:"data"`
			Metadata struct {
				ProcessedAt string `json:"processed_at"`
			} `json:"metadata"`
		} `json:"data"`
		Blocked    bool `json:"blocked"`
		PolicyInfo struct {
			ProcessingTime string `json:"processing_time"`
		} `json:"policy_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&proxyResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Printf("Response received (latency: %v)\n", time.Since(startTime))
	fmt.Printf("Blocked: %v\n", proxyResp.Blocked)
	fmt.Printf("Response: %s\n", truncate(proxyResp.Data.Data, 300))

	return nil
}

// preCheck calls AxonFlow's pre-check endpoint
func preCheck(ctx context.Context, prompt, provider, model string) (*preCheckResponse, error) {
	reqBody := map[string]any{
		"client_id": "azure-openai-example",
		"query":     prompt,
		"context": map[string]string{
			"provider": provider,
			"model":    model,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", axonflowURL+"/api/policy/pre-check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pre-check failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result preCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

type preCheckResponse struct {
	ContextID string   `json:"context_id"`
	Approved  bool     `json:"approved"`
	Policies  []string `json:"policies"`
	ExpiresAt string   `json:"expires_at"`
}

// auditLLMCall logs the LLM response with AxonFlow
func auditLLMCall(ctx context.Context, contextID, response, provider, model string, latency time.Duration, promptTokens, completionTokens int) error {
	reqBody := map[string]any{
		"client_id":        "azure-openai-example",
		"context_id":       contextID,
		"response_summary": truncate(response, 500),
		"provider":         provider,
		"model":            model,
		"latency_ms":       latency.Milliseconds(),
		"token_usage": map[string]int{
			"prompt_tokens":     promptTokens,
			"completion_tokens": completionTokens,
			"total_tokens":      promptTokens + completionTokens,
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", axonflowURL+"/api/audit/llm-call", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("audit failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
