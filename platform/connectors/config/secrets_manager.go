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

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSecretsManager implements SecretsManager using AWS Secrets Manager
type AWSSecretsManager struct {
	client *secretsmanager.Client
	cache  map[string]*secretCacheEntry
	mu     sync.RWMutex
	ttl    time.Duration
	logger *log.Logger
}

type secretCacheEntry struct {
	value     map[string]string
	expiresAt time.Time
}

// AWSSecretsManagerOptions holds options for creating an AWSSecretsManager
type AWSSecretsManagerOptions struct {
	Region   string
	CacheTTL time.Duration
	Logger   *log.Logger
}

// NewAWSSecretsManager creates a new AWS Secrets Manager client
func NewAWSSecretsManager(ctx context.Context, opts AWSSecretsManagerOptions) (*AWSSecretsManager, error) {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[SECRETS_MANAGER] ", log.LstdFlags)
	}

	cfgOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(opts.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute // Cache secrets for 5 minutes by default
	}

	return &AWSSecretsManager{
		client: client,
		cache:  make(map[string]*secretCacheEntry),
		ttl:    ttl,
		logger: logger,
	}, nil
}

// GetSecret retrieves a secret from AWS Secrets Manager
// The secret value is expected to be a JSON object with string values
func (s *AWSSecretsManager) GetSecret(ctx context.Context, secretARN string) (map[string]string, error) {
	// Check cache first
	s.mu.RLock()
	entry, exists := s.cache[secretARN]
	s.mu.RUnlock()

	if exists && time.Now().Before(entry.expiresAt) {
		s.logger.Printf("Cache hit for secret %s", maskARN(secretARN))
		return entry.value, nil
	}

	s.logger.Printf("Fetching secret %s from AWS Secrets Manager", maskARN(secretARN))

	// Fetch from AWS Secrets Manager
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	}

	result, err := s.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s: %w", maskARN(secretARN), err)
	}

	var secretValue string
	if result.SecretString != nil {
		secretValue = *result.SecretString
	} else {
		return nil, fmt.Errorf("secret %s has no string value", maskARN(secretARN))
	}

	// Parse JSON secret
	var credentials map[string]string
	if err := json.Unmarshal([]byte(secretValue), &credentials); err != nil {
		// Try parsing as a simple key-value where the entire string is the value
		// This handles secrets that are just a single API key
		credentials = map[string]string{
			"value": secretValue,
		}
	}

	// Update cache
	s.mu.Lock()
	s.cache[secretARN] = &secretCacheEntry{
		value:     credentials,
		expiresAt: time.Now().Add(s.ttl),
	}
	s.mu.Unlock()

	s.logger.Printf("Successfully retrieved and cached secret %s", maskARN(secretARN))
	return credentials, nil
}

// InvalidateSecret removes a secret from the cache
func (s *AWSSecretsManager) InvalidateSecret(secretARN string) {
	s.mu.Lock()
	delete(s.cache, secretARN)
	s.mu.Unlock()
	s.logger.Printf("Invalidated cache for secret %s", maskARN(secretARN))
}

// InvalidateAll clears the entire secret cache
func (s *AWSSecretsManager) InvalidateAll() {
	s.mu.Lock()
	s.cache = make(map[string]*secretCacheEntry)
	s.mu.Unlock()
	s.logger.Println("Invalidated all cached secrets")
}

// maskARN masks the secret ARN for logging (shows only last 8 characters)
func maskARN(arn string) string {
	if len(arn) <= 12 {
		return "***"
	}
	return "..." + arn[len(arn)-8:]
}

// LocalSecretsManager implements SecretsManager using local environment variables
// Useful for development and OSS deployments without AWS Secrets Manager
type LocalSecretsManager struct {
	secrets map[string]map[string]string
	mu      sync.RWMutex
	logger  *log.Logger
}

// NewLocalSecretsManager creates a local secrets manager for development
func NewLocalSecretsManager(logger *log.Logger) *LocalSecretsManager {
	if logger == nil {
		logger = log.New(os.Stdout, "[LOCAL_SECRETS] ", log.LstdFlags)
	}
	return &LocalSecretsManager{
		secrets: make(map[string]map[string]string),
		logger:  logger,
	}
}

// GetSecret retrieves a secret from local storage
func (s *LocalSecretsManager) GetSecret(ctx context.Context, secretARN string) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if secret, exists := s.secrets[secretARN]; exists {
		return secret, nil
	}

	return nil, fmt.Errorf("secret %s not found in local secrets manager", secretARN)
}

// SetSecret stores a secret locally (for testing/development)
func (s *LocalSecretsManager) SetSecret(secretARN string, value map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[secretARN] = value
	s.logger.Printf("Set local secret %s", maskARN(secretARN))
}

// EnvSecretsManager implements SecretsManager using environment variables
// The secretARN is used as an environment variable name prefix
type EnvSecretsManager struct {
	logger *log.Logger
}

// NewEnvSecretsManager creates a secrets manager that reads from environment variables
func NewEnvSecretsManager(logger *log.Logger) *EnvSecretsManager {
	if logger == nil {
		logger = log.New(os.Stdout, "[ENV_SECRETS] ", log.LstdFlags)
	}
	return &EnvSecretsManager{
		logger: logger,
	}
}

// GetSecret retrieves credentials from environment variables
// The secretARN should be an env var prefix (e.g., "POSTGRES" will look for POSTGRES_USERNAME, POSTGRES_PASSWORD)
func (s *EnvSecretsManager) GetSecret(ctx context.Context, secretARN string) (map[string]string, error) {
	// Common credential field names to check
	fields := []string{
		"USERNAME", "PASSWORD", "API_KEY", "API_SECRET",
		"CLIENT_ID", "CLIENT_SECRET", "TOKEN", "PRIVATE_KEY",
		"ACCESS_KEY", "SECRET_KEY", "HOST", "PORT", "DATABASE",
	}

	credentials := make(map[string]string)
	for _, field := range fields {
		envVar := secretARN + "_" + field
		if value := os.Getenv(envVar); value != "" {
			credentials[fieldToKey(field)] = value
		}
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials found for prefix %s", secretARN)
	}

	s.logger.Printf("Loaded %d credentials from environment for %s", len(credentials), secretARN)
	return credentials, nil
}

// fieldToKey converts an environment variable field name to a credential key
func fieldToKey(field string) string {
	switch field {
	case "USERNAME":
		return "username"
	case "PASSWORD":
		return "password"
	case "API_KEY":
		return "api_key"
	case "API_SECRET":
		return "api_secret"
	case "CLIENT_ID":
		return "client_id"
	case "CLIENT_SECRET":
		return "client_secret"
	case "TOKEN":
		return "token"
	case "PRIVATE_KEY":
		return "private_key"
	case "ACCESS_KEY":
		return "access_key"
	case "SECRET_KEY":
		return "secret_key"
	case "HOST":
		return "host"
	case "PORT":
		return "port"
	case "DATABASE":
		return "database"
	default:
		return field
	}
}
