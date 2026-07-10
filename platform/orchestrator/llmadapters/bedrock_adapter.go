//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

package llmadapters

import (
	"axonflow/platform/shared/llmdefaults"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"

	"axonflow/platform/orchestrator/llm"
	llmsdk "axonflow/platform/orchestrator/llm/sdk"
)

const (
	// defaultTemperature is used when temperature is not explicitly set (nil/unspecified).
	// Note: Temperature of 0 is valid and means deterministic output.
	defaultTemperature = 0.7

	// defaultMaxTokens is used when max_tokens is not specified.
	defaultMaxTokens = 1024
)

// BedrockClient is an interface for the Bedrock runtime client (for testing).
type BedrockClient interface {
	InvokeModel(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

// BedrockAdapter implements the unified llm.Provider interface for AWS Bedrock.
// This adapter provides direct integration without depending on the legacy EE llm package.
type BedrockAdapter struct {
	client       BedrockClient
	name         string
	model        string
	region       string
	modelFamily  string
	base         *llmsdk.CustomProvider
	authProvider llmsdk.AuthProvider
	rateLimiter  *llmsdk.RateLimiter
}

// BedrockAdapterConfig contains configuration for creating a BedrockAdapter.
type BedrockAdapterConfig struct {
	// Name is the unique identifier for this provider instance.
	Name string

	// Region is the AWS region (e.g., "us-east-1", "eu-central-1").
	Region string

	// Model is the Bedrock model ID (e.g., "us.anthropic.claude-haiku-4-5-20251001-v1:0").
	Model string

	// ModelFamily overrides auto-detection for custom models.
	// Valid values: "anthropic", "amazon", "meta", "mistral"
	ModelFamily string

	// RateLimit is the maximum requests per minute (0 = unlimited).
	RateLimit int
}

// inferenceProfilePrefixes are the known AWS Bedrock inference profile prefixes.
var inferenceProfilePrefixes = []string{"eu", "us", "apac", "global"}

// supportedModelFamilies are the model families that we know how to handle.
var supportedModelFamilies = []string{"anthropic", "amazon", "meta", "mistral"}

// NewBedrockAdapter creates a new BedrockAdapter.
func NewBedrockAdapter(cfg BedrockAdapterConfig) (*BedrockAdapter, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("bedrock region is required")
	}

	if cfg.Model == "" {
		cfg.Model = llmdefaults.BedrockModel
	}

	modelFamily := cfg.ModelFamily
	if modelFamily == "" {
		modelFamily = detectModelFamily(cfg.Model)
	}

	if modelFamily == "" {
		return nil, fmt.Errorf("unable to detect model family from model ID %q; set ModelFamily explicitly in config", cfg.Model)
	}

	// Load AWS configuration
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(awsCfg)

	name := cfg.Name
	if name == "" {
		name = "bedrock"
	}

	adapter := &BedrockAdapter{
		client:      client,
		name:        name,
		model:       cfg.Model,
		region:      cfg.Region,
		modelFamily: modelFamily,
	}
	if cfg.RateLimit > 0 {
		ratePerSecond := float64(cfg.RateLimit) / 60.0
		burst := math.Max(1, ratePerSecond)
		adapter.rateLimiter = llmsdk.NewRateLimiter(ratePerSecond, burst)
	}

	builder := llmsdk.NewProviderBuilder(adapter.name, llm.ProviderTypeBedrock).
		WithModel(adapter.model).
		WithEndpoint(fmt.Sprintf("bedrock://%s", adapter.region)).
		WithTimeout(2 * time.Minute).
		WithCapabilities(adapter.Capabilities()...).
		WithStreaming(true).
		WithCompleteFunc(adapter.completeRequest)
	if adapter.rateLimiter != nil {
		builder.WithRateLimiter(adapter.rateLimiter)
	}
	adapter.base = builder.Build()

	return adapter, nil
}

// NewBedrockAdapterWithClient creates a BedrockAdapter with a custom client (for testing).
func NewBedrockAdapterWithClient(name string, client BedrockClient, model, modelFamily string) *BedrockAdapter {
	if name == "" {
		name = "bedrock"
	}
	if modelFamily == "" {
		modelFamily = detectModelFamily(model)
	}
	return &BedrockAdapter{
		client:      client,
		name:        name,
		model:       model,
		modelFamily: modelFamily,
	}
}

// Name returns the unique identifier for this provider instance.
func (a *BedrockAdapter) Name() string {
	return a.name
}

// Type returns the provider type.
func (a *BedrockAdapter) Type() llm.ProviderType {
	return llm.ProviderTypeBedrock
}

// Complete generates a completion using AWS Bedrock.
func (a *BedrockAdapter) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if a.base != nil {
		return a.base.Complete(ctx, req)
	}
	return a.completeRequest(ctx, req)
}

func (a *BedrockAdapter) completeRequest(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	start := time.Now()

	model := req.Model
	if model == "" {
		model = a.model
	}

	requestBody, err := a.buildRequestBody(req)
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeInvalidRequest,
			Message:   err.Error(),
			Retryable: false,
			Cause:     err,
		}
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeInvalidRequest,
			Message:   fmt.Sprintf("failed to marshal request: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}

	output, err := a.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(model),
		Body:        requestJSON,
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
	})
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeServerError,
			Message:   err.Error(),
			Retryable: true,
			Cause:     err,
		}
	}

	response, err := a.parseResponseBody(output.Body)
	if err != nil {
		return nil, &llm.ProviderError{
			Provider:  a.name,
			Code:      llm.ErrCodeServerError,
			Message:   fmt.Sprintf("failed to parse response: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}

	response.Model = model
	response.Latency = time.Since(start)

	return response, nil
}

// HealthCheck verifies the provider is operational.
func (a *BedrockAdapter) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	start := time.Now()

	testReq := llm.CompletionRequest{
		Prompt:      "Hello",
		MaxTokens:   5,
		Temperature: 0,
	}

	_, err := a.Complete(ctx, testReq)
	latency := time.Since(start)

	if err != nil {
		return &llm.HealthCheckResult{
			Status:      llm.HealthStatusUnhealthy,
			Latency:     latency,
			Message:     err.Error(),
			LastChecked: time.Now(),
		}, nil
	}

	return &llm.HealthCheckResult{
		Status:      llm.HealthStatusHealthy,
		Latency:     latency,
		Message:     "Bedrock API is responsive",
		LastChecked: time.Now(),
	}, nil
}

// Capabilities returns the features supported by Bedrock.
func (a *BedrockAdapter) Capabilities() []llm.Capability {
	return []llm.Capability{
		llm.CapabilityChat,
		llm.CapabilityCompletion,
		llm.CapabilityStreaming,
		llm.CapabilityLongContext,
	}
}

// SupportsStreaming indicates Bedrock supports streaming responses.
func (a *BedrockAdapter) SupportsStreaming() bool {
	return true
}

// EstimateCost provides cost estimation for Bedrock requests.
func (a *BedrockAdapter) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
	inputTokens := len(req.Prompt) / 4
	if inputTokens < 1 {
		inputTokens = 1
	}

	outputTokens := req.MaxTokens
	if outputTokens == 0 {
		outputTokens = 1000
	}

	// Bedrock Claude pricing (approximate)
	inputCostPer1K := 0.003
	outputCostPer1K := 0.015

	totalCost := (float64(inputTokens)/1000)*inputCostPer1K +
		(float64(outputTokens)/1000)*outputCostPer1K

	return &llm.CostEstimate{
		InputCostPer1K:        inputCostPer1K,
		OutputCostPer1K:       outputCostPer1K,
		EstimatedInputTokens:  inputTokens,
		EstimatedOutputTokens: outputTokens,
		TotalEstimate:         totalCost,
		Currency:              "USD",
	}
}

// buildRequestBody builds the request body based on model family.
// Note: Temperature=0 cannot be distinguished from "not set" in Go.
// To use temperature=0 (deterministic), set a very small value like 0.001.
func (a *BedrockAdapter) buildRequestBody(req llm.CompletionRequest) (map[string]interface{}, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = defaultMaxTokens
	}

	temperature := req.Temperature
	if temperature == 0 {
		temperature = defaultTemperature
	}

	switch a.modelFamily {
	case "anthropic":
		return map[string]interface{}{
			"anthropic_version": "bedrock-2023-05-31",
			"max_tokens":        maxTokens,
			"temperature":       temperature,
			"messages": []map[string]string{
				{"role": "user", "content": req.Prompt},
			},
		}, nil
	case "amazon":
		return map[string]interface{}{
			"inputText": req.Prompt,
			"textGenerationConfig": map[string]interface{}{
				"maxTokenCount": maxTokens,
				"temperature":   temperature,
				"topP":          0.9,
			},
		}, nil
	case "meta":
		return map[string]interface{}{
			"prompt":      req.Prompt,
			"max_gen_len": maxTokens,
			"temperature": temperature,
			"top_p":       0.9,
		}, nil
	case "mistral":
		return map[string]interface{}{
			"prompt":      req.Prompt,
			"max_tokens":  maxTokens,
			"temperature": temperature,
			"top_p":       0.9,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported model family: %s", a.modelFamily)
	}
}

// parseResponseBody parses the response body based on model family.
func (a *BedrockAdapter) parseResponseBody(body []byte) (*llm.CompletionResponse, error) {
	switch a.modelFamily {
	case "anthropic":
		return a.parseAnthropicResponse(body)
	case "amazon":
		return a.parseAmazonTitanResponse(body)
	case "meta":
		return a.parseMetaLlamaResponse(body)
	case "mistral":
		return a.parseMistralResponse(body)
	default:
		return nil, fmt.Errorf("unsupported model family: %s", a.modelFamily)
	}
}

func (a *BedrockAdapter) parseAnthropicResponse(body []byte) (*llm.CompletionResponse, error) {
	var resp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	content := ""
	if len(resp.Content) > 0 {
		content = resp.Content[0].Text
	}

	return &llm.CompletionResponse{
		Content: content,
		Usage: llm.UsageStats{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}, nil
}

func (a *BedrockAdapter) parseAmazonTitanResponse(body []byte) (*llm.CompletionResponse, error) {
	var resp struct {
		Results []struct {
			OutputText string `json:"outputText"`
			TokenCount int    `json:"tokenCount"`
		} `json:"results"`
		InputTextTokenCount int `json:"inputTextTokenCount"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	content := ""
	outputTokens := 0
	if len(resp.Results) > 0 {
		content = resp.Results[0].OutputText
		outputTokens = resp.Results[0].TokenCount
	}

	return &llm.CompletionResponse{
		Content: content,
		Usage: llm.UsageStats{
			PromptTokens:     resp.InputTextTokenCount,
			CompletionTokens: outputTokens,
			TotalTokens:      resp.InputTextTokenCount + outputTokens,
		},
	}, nil
}

func (a *BedrockAdapter) parseMetaLlamaResponse(body []byte) (*llm.CompletionResponse, error) {
	var resp struct {
		Generation       string `json:"generation"`
		PromptTokenCount int    `json:"prompt_token_count"`
		GenTokenCount    int    `json:"generation_token_count"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &llm.CompletionResponse{
		Content: resp.Generation,
		Usage: llm.UsageStats{
			PromptTokens:     resp.PromptTokenCount,
			CompletionTokens: resp.GenTokenCount,
			TotalTokens:      resp.PromptTokenCount + resp.GenTokenCount,
		},
	}, nil
}

func (a *BedrockAdapter) parseMistralResponse(body []byte) (*llm.CompletionResponse, error) {
	var resp struct {
		Outputs []struct {
			Text string `json:"text"`
		} `json:"outputs"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	content := ""
	if len(resp.Outputs) > 0 {
		content = resp.Outputs[0].Text
	}

	return &llm.CompletionResponse{
		Content: content,
		Usage:   llm.UsageStats{},
	}, nil
}

// detectModelFamily detects the model family from model ID.
// Handles both standard model IDs (e.g., "anthropic.claude-sonnet-4...")
// and inference profile IDs (e.g., "eu.anthropic.claude...").
func detectModelFamily(modelID string) string {
	if modelID == "" {
		return ""
	}

	segments := strings.Split(modelID, ".")
	if len(segments) < 2 {
		return ""
	}

	firstSegment := segments[0]
	for _, prefix := range inferenceProfilePrefixes {
		if firstSegment == prefix {
			if len(segments) > 1 {
				return validateModelFamily(segments[1])
			}
			return ""
		}
	}

	return validateModelFamily(firstSegment)
}

func validateModelFamily(family string) string {
	for _, supported := range supportedModelFamilies {
		if family == supported {
			return family
		}
	}
	return ""
}

// Compile-time interface compliance check
var _ llm.Provider = (*BedrockAdapter)(nil)
