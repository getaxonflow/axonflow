// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"testing"

	"axonflow/platform/orchestrator/llm"
)

func TestLLMConfigToProviderConfigs_EmptyConfig(t *testing.T) {
	cfg := LLMRouterConfig{}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 0 {
		t.Errorf("Expected 0 provider configs for empty config, got %d", len(configs))
	}
}

func TestLLMConfigToProviderConfigs_OpenAIOnly(t *testing.T) {
	cfg := LLMRouterConfig{
		OpenAIKey: "sk-test-key",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Name != "openai" {
		t.Errorf("Expected name 'openai', got %q", configs[0].Name)
	}
	if configs[0].Type != llm.ProviderTypeOpenAI {
		t.Errorf("Expected type ProviderTypeOpenAI, got %q", configs[0].Type)
	}
	if configs[0].APIKey != "sk-test-key" {
		t.Errorf("Expected API key 'sk-test-key', got %q", configs[0].APIKey)
	}
	if !configs[0].Enabled {
		t.Error("Expected Enabled to be true")
	}
}

func TestLLMConfigToProviderConfigs_AnthropicOnly(t *testing.T) {
	cfg := LLMRouterConfig{
		AnthropicKey: "sk-ant-test",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Name != "anthropic" {
		t.Errorf("Expected name 'anthropic', got %q", configs[0].Name)
	}
	if configs[0].Type != llm.ProviderTypeAnthropic {
		t.Errorf("Expected type ProviderTypeAnthropic, got %q", configs[0].Type)
	}
	if configs[0].APIKey != "sk-ant-test" {
		t.Errorf("Expected API key 'sk-ant-test', got %q", configs[0].APIKey)
	}
}

func TestLLMConfigToProviderConfigs_GeminiWithModel(t *testing.T) {
	cfg := LLMRouterConfig{
		GeminiKey:   "gemini-key-123",
		GeminiModel: "gemini-2.0-flash",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Name != "gemini" {
		t.Errorf("Expected name 'gemini', got %q", configs[0].Name)
	}
	if configs[0].Type != llm.ProviderTypeGemini {
		t.Errorf("Expected type ProviderTypeGemini, got %q", configs[0].Type)
	}
	if configs[0].Model != "gemini-2.0-flash" {
		t.Errorf("Expected model 'gemini-2.0-flash', got %q", configs[0].Model)
	}
}

func TestLLMConfigToProviderConfigs_GeminiWithoutModel(t *testing.T) {
	cfg := LLMRouterConfig{
		GeminiKey: "gemini-key-456",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Model != "" {
		t.Errorf("Expected empty model when GeminiModel not set, got %q", configs[0].Model)
	}
}

func TestLLMConfigToProviderConfigs_OllamaWithModel(t *testing.T) {
	cfg := LLMRouterConfig{
		OllamaEndpoint: "http://localhost:11434",
		OllamaModel:    "llama3.1:70b",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Name != "ollama" {
		t.Errorf("Expected name 'ollama', got %q", configs[0].Name)
	}
	if configs[0].Type != llm.ProviderTypeOllama {
		t.Errorf("Expected type ProviderTypeOllama, got %q", configs[0].Type)
	}
	if configs[0].Endpoint != "http://localhost:11434" {
		t.Errorf("Expected endpoint 'http://localhost:11434', got %q", configs[0].Endpoint)
	}
	if configs[0].Model != "llama3.1:70b" {
		t.Errorf("Expected model 'llama3.1:70b', got %q", configs[0].Model)
	}
}

func TestLLMConfigToProviderConfigs_OllamaWithoutModel(t *testing.T) {
	cfg := LLMRouterConfig{
		OllamaEndpoint: "http://localhost:11434",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	if configs[0].Model != "" {
		t.Errorf("Expected empty model when OllamaModel not set, got %q", configs[0].Model)
	}
}

func TestLLMConfigToProviderConfigs_AzureOpenAI_AllFieldsRequired(t *testing.T) {
	// Azure requires all three: endpoint, key, and deployment name
	tests := []struct {
		name      string
		cfg       LLMRouterConfig
		wantCount int
	}{
		{
			name: "all Azure fields present",
			cfg: LLMRouterConfig{
				AzureOpenAIEndpoint:       "https://example.openai.azure.com",
				AzureOpenAIAPIKey:         "azure-key",
				AzureOpenAIDeploymentName: "gpt-4o-mini",
			},
			wantCount: 1,
		},
		{
			name: "missing endpoint",
			cfg: LLMRouterConfig{
				AzureOpenAIAPIKey:         "azure-key",
				AzureOpenAIDeploymentName: "gpt-4o-mini",
			},
			wantCount: 0,
		},
		{
			name: "missing API key",
			cfg: LLMRouterConfig{
				AzureOpenAIEndpoint:       "https://example.openai.azure.com",
				AzureOpenAIDeploymentName: "gpt-4o-mini",
			},
			wantCount: 0,
		},
		{
			name: "missing deployment name",
			cfg: LLMRouterConfig{
				AzureOpenAIEndpoint: "https://example.openai.azure.com",
				AzureOpenAIAPIKey:   "azure-key",
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configs := LLMConfigToProviderConfigs(tt.cfg)
			if len(configs) != tt.wantCount {
				t.Errorf("Expected %d provider configs, got %d", tt.wantCount, len(configs))
			}
		})
	}
}

func TestLLMConfigToProviderConfigs_AzureOpenAI_WithAPIVersion(t *testing.T) {
	cfg := LLMRouterConfig{
		AzureOpenAIEndpoint:       "https://example.openai.azure.com",
		AzureOpenAIAPIKey:         "azure-key",
		AzureOpenAIDeploymentName: "gpt-4o-mini",
		AzureOpenAIAPIVersion:     "2024-08-01-preview",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	c := configs[0]
	if c.Name != "azure-openai" {
		t.Errorf("Expected name 'azure-openai', got %q", c.Name)
	}
	if c.Type != llm.ProviderTypeAzureOpenAI {
		t.Errorf("Expected type ProviderTypeAzureOpenAI, got %q", c.Type)
	}
	if c.Endpoint != "https://example.openai.azure.com" {
		t.Errorf("Expected endpoint, got %q", c.Endpoint)
	}
	if c.APIKey != "azure-key" {
		t.Errorf("Expected API key 'azure-key', got %q", c.APIKey)
	}
	if c.Model != "gpt-4o-mini" {
		t.Errorf("Expected model 'gpt-4o-mini', got %q", c.Model)
	}
	if c.Settings == nil {
		t.Fatal("Expected non-nil Settings map")
	}
	if c.Settings["api_version"] != "2024-08-01-preview" {
		t.Errorf("Expected api_version '2024-08-01-preview', got %v", c.Settings["api_version"])
	}
}

func TestLLMConfigToProviderConfigs_AzureOpenAI_WithoutAPIVersion(t *testing.T) {
	cfg := LLMRouterConfig{
		AzureOpenAIEndpoint:       "https://example.openai.azure.com",
		AzureOpenAIAPIKey:         "azure-key",
		AzureOpenAIDeploymentName: "gpt-4o",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 config, got %d", len(configs))
	}
	if _, ok := configs[0].Settings["api_version"]; ok {
		t.Error("Expected no api_version in Settings when AzureOpenAIAPIVersion is empty")
	}
}

func TestLLMConfigToProviderConfigs_Bedrock(t *testing.T) {
	cfg := LLMRouterConfig{
		BedrockRegion: "us-east-1",
		BedrockModel:  "anthropic.claude-3-haiku-20240307-v1:0",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 1 {
		t.Fatalf("Expected 1 provider config, got %d", len(configs))
	}
	c := configs[0]
	if c.Name != "bedrock" {
		t.Errorf("Expected name 'bedrock', got %q", c.Name)
	}
	if c.Type != llm.ProviderTypeBedrock {
		t.Errorf("Expected type ProviderTypeBedrock, got %q", c.Type)
	}
	if c.Region != "us-east-1" {
		t.Errorf("Expected region 'us-east-1', got %q", c.Region)
	}
	if c.Model != "anthropic.claude-3-haiku-20240307-v1:0" {
		t.Errorf("Expected model, got %q", c.Model)
	}
}

func TestLLMConfigToProviderConfigs_Bedrock_PartialConfig(t *testing.T) {
	// Bedrock requires both region and model
	tests := []struct {
		name      string
		cfg       LLMRouterConfig
		wantCount int
	}{
		{
			name:      "only region",
			cfg:       LLMRouterConfig{BedrockRegion: "us-east-1"},
			wantCount: 0,
		},
		{
			name:      "only model",
			cfg:       LLMRouterConfig{BedrockModel: "some-model"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configs := LLMConfigToProviderConfigs(tt.cfg)
			if len(configs) != tt.wantCount {
				t.Errorf("Expected %d provider configs, got %d", tt.wantCount, len(configs))
			}
		})
	}
}

func TestLLMConfigToProviderConfigs_AllProviders(t *testing.T) {
	cfg := LLMRouterConfig{
		OpenAIKey:                 "openai-key",
		AnthropicKey:              "anthropic-key",
		GeminiKey:                 "gemini-key",
		GeminiModel:               "gemini-2.0-flash",
		OllamaEndpoint:            "http://localhost:11434",
		OllamaModel:               "llama3.1:latest",
		AzureOpenAIEndpoint:       "https://example.openai.azure.com",
		AzureOpenAIAPIKey:         "azure-key",
		AzureOpenAIDeploymentName: "gpt-4o-mini",
		AzureOpenAIAPIVersion:     "2024-08-01-preview",
		BedrockRegion:             "us-east-1",
		BedrockModel:              "anthropic.claude-3-haiku-20240307-v1:0",
	}
	configs := LLMConfigToProviderConfigs(cfg)

	if len(configs) != 6 {
		t.Fatalf("Expected 6 provider configs (all providers), got %d", len(configs))
	}

	// Verify ordering: openai, anthropic, gemini, ollama, azure-openai, bedrock
	expectedNames := []string{"openai", "anthropic", "gemini", "ollama", "azure-openai", "bedrock"}
	for i, expected := range expectedNames {
		if configs[i].Name != expected {
			t.Errorf("configs[%d].Name = %q, want %q", i, configs[i].Name, expected)
		}
		if !configs[i].Enabled {
			t.Errorf("configs[%d].Enabled should be true", i)
		}
	}
}
