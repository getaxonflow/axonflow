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
	"os"
	"testing"
)

// TestLoadSnowflakeConfig_PasswordAuth tests traditional password authentication
func TestLoadSnowflakeConfig_PasswordAuth(t *testing.T) {
	// Set up environment variables for password auth
	if err := os.Setenv("MCP_test_sf_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf_DATABASE", "test-db"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf_DATABASE"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Verify configuration
	if config.Name != "test_sf" {
		t.Errorf("Expected name 'test_sf', got '%s'", config.Name)
	}
	if config.Type != "snowflake" {
		t.Errorf("Expected type 'snowflake', got '%s'", config.Type)
	}
	if config.Credentials["account"] != "test-account" {
		t.Errorf("Expected account 'test-account', got '%s'", config.Credentials["account"])
	}
	if config.Credentials["username"] != "test-user" {
		t.Errorf("Expected username 'test-user', got '%s'", config.Credentials["username"])
	}
	if config.Credentials["password"] != "test-password" {
		t.Errorf("Expected password 'test-password', got '%s'", config.Credentials["password"])
	}
	if config.Credentials["database"] != "test-db" {
		t.Errorf("Expected database 'test-db', got '%s'", config.Credentials["database"])
	}
}

// TestLoadSnowflakeConfig_PrivateKeyPathAuth tests key-pair authentication with file path
func TestLoadSnowflakeConfig_PrivateKeyPathAuth(t *testing.T) {
	// Set up environment variables for key-pair auth (path)
	if err := os.Setenv("MCP_test_sf2_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf2_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf2_PRIVATE_KEY_PATH", "/path/to/key.p8"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf2_WAREHOUSE", "test-warehouse"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf2_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf2_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf2_PRIVATE_KEY_PATH"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf2_WAREHOUSE"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf2")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Verify configuration
	if config.Credentials["private_key_path"] != "/path/to/key.p8" {
		t.Errorf("Expected private_key_path '/path/to/key.p8', got '%s'", config.Credentials["private_key_path"])
	}
	if config.Credentials["warehouse"] != "test-warehouse" {
		t.Errorf("Expected warehouse 'test-warehouse', got '%s'", config.Credentials["warehouse"])
	}
	// Password should not be present
	if _, exists := config.Credentials["password"]; exists {
		t.Error("Password should not be present when using key-pair auth")
	}
}

// TestLoadSnowflakeConfig_PrivateKeyContentAuth tests key-pair authentication with inline key
func TestLoadSnowflakeConfig_PrivateKeyContentAuth(t *testing.T) {
	// Set up environment variables for key-pair auth (content)
	if err := os.Setenv("MCP_test_sf3_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf3_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf3_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\ntest-key-content\n-----END PRIVATE KEY-----"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf3_SCHEMA", "test-schema"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf3_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf3_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf3_PRIVATE_KEY"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf3_SCHEMA"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf3")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Verify configuration
	expectedKey := "-----BEGIN PRIVATE KEY-----\ntest-key-content\n-----END PRIVATE KEY-----"
	if config.Credentials["private_key"] != expectedKey {
		t.Errorf("Expected private_key with test content, got '%s'", config.Credentials["private_key"])
	}
	if config.Credentials["schema"] != "test-schema" {
		t.Errorf("Expected schema 'test-schema', got '%s'", config.Credentials["schema"])
	}
}

// TestLoadSnowflakeConfig_MissingAccount tests missing required account field
func TestLoadSnowflakeConfig_MissingAccount(t *testing.T) {
	// Only set username and password
	if err := os.Setenv("MCP_test_sf4_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf4_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf4_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf4_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	_, err := LoadSnowflakeConfig("test_sf4")
	if err == nil {
		t.Fatal("Expected error for missing account, got nil")
	}

	expectedError := "missing required Snowflake credentials (account, username)"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got: %v", expectedError, err)
	}
}

// TestLoadSnowflakeConfig_MissingUsername tests missing required username field
func TestLoadSnowflakeConfig_MissingUsername(t *testing.T) {
	// Only set account and password
	if err := os.Setenv("MCP_test_sf5_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf5_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf5_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf5_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	_, err := LoadSnowflakeConfig("test_sf5")
	if err == nil {
		t.Fatal("Expected error for missing username, got nil")
	}

	expectedError := "missing required Snowflake credentials (account, username)"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got: %v", expectedError, err)
	}
}

// TestLoadSnowflakeConfig_MissingAllAuthMethods tests missing all authentication methods
func TestLoadSnowflakeConfig_MissingAllAuthMethods(t *testing.T) {
	// Set only required fields, no auth methods
	if err := os.Setenv("MCP_test_sf6_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf6_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf6_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf6_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	_, err := LoadSnowflakeConfig("test_sf6")
	if err == nil {
		t.Fatal("Expected error for missing auth methods, got nil")
	}

	expectedError := "missing authentication: provide either PASSWORD or PRIVATE_KEY_PATH or PRIVATE_KEY"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got: %v", expectedError, err)
	}
}

// TestLoadSnowflakeConfig_AllOptionalFields tests all optional fields
func TestLoadSnowflakeConfig_AllOptionalFields(t *testing.T) {
	// Set all possible fields
	if err := os.Setenv("MCP_test_sf7_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_DATABASE", "test-db"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_SCHEMA", "test-schema"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_WAREHOUSE", "test-warehouse"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_ROLE", "test-role"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_MAX_OPEN_CONNS", "10"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf7_TENANT_ID", "tenant-123"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf7_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_DATABASE"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_SCHEMA"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_WAREHOUSE"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_ROLE"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_MAX_OPEN_CONNS"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf7_TENANT_ID"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf7")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Verify all optional fields
	if config.Credentials["database"] != "test-db" {
		t.Errorf("Expected database 'test-db', got '%s'", config.Credentials["database"])
	}
	if config.Credentials["schema"] != "test-schema" {
		t.Errorf("Expected schema 'test-schema', got '%s'", config.Credentials["schema"])
	}
	if config.Credentials["warehouse"] != "test-warehouse" {
		t.Errorf("Expected warehouse 'test-warehouse', got '%s'", config.Credentials["warehouse"])
	}
	if config.Credentials["role"] != "test-role" {
		t.Errorf("Expected role 'test-role', got '%s'", config.Credentials["role"])
	}
	if config.Options["max_open_conns"] != 10 {
		t.Errorf("Expected max_open_conns 10, got %v", config.Options["max_open_conns"])
	}
	if config.TenantID != "tenant-123" {
		t.Errorf("Expected TenantID 'tenant-123', got '%s'", config.TenantID)
	}
}

// TestLoadSnowflakeConfig_MultipleAuthMethods tests config with multiple auth methods provided
func TestLoadSnowflakeConfig_MultipleAuthMethods(t *testing.T) {
	// Set both password and private key (should accept both)
	if err := os.Setenv("MCP_test_sf8_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf8_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf8_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf8_PRIVATE_KEY_PATH", "/path/to/key.p8"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf8_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf8_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf8_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf8_PRIVATE_KEY_PATH"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf8")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Both auth methods should be present (connector will prefer key-pair)
	if config.Credentials["password"] != "test-password" {
		t.Error("Password should be present")
	}
	if config.Credentials["private_key_path"] != "/path/to/key.p8" {
		t.Error("Private key path should be present")
	}
}

// TestLoadSnowflakeConfig_InvalidMaxOpenConns tests non-integer max_open_conns
func TestLoadSnowflakeConfig_InvalidMaxOpenConns(t *testing.T) {
	// Set invalid max_open_conns (should be ignored)
	if err := os.Setenv("MCP_test_sf9_ACCOUNT", "test-account"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf9_USERNAME", "test-user"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf9_PASSWORD", "test-password"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	if err := os.Setenv("MCP_test_sf9_MAX_OPEN_CONNS", "not-a-number"); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("MCP_test_sf9_ACCOUNT"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf9_USERNAME"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf9_PASSWORD"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
		if err := os.Unsetenv("MCP_test_sf9_MAX_OPEN_CONNS"); err != nil {
			t.Fatalf("failed to unset env: %v", err)
		}
	}()

	config, err := LoadSnowflakeConfig("test_sf9")
	if err != nil {
		t.Fatalf("LoadSnowflakeConfig failed: %v", err)
	}

	// Invalid max_open_conns should be ignored (not set in options)
	if _, exists := config.Options["max_open_conns"]; exists {
		t.Error("Invalid max_open_conns should be ignored")
	}
}
