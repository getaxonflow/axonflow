// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"net"
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		opts    URLValidationOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid HTTPS URL",
			url:  "https://api.github.com/v1/resource",
			opts: URLValidationOptions{
				AllowPrivateIPs: true, // Skip DNS resolution for tests
				AllowedSchemes:  []string{"https", "http"},
			},
			wantErr: false,
		},
		{
			name: "valid HTTP URL",
			url:  "http://api.github.com/v1/resource",
			opts: URLValidationOptions{
				AllowPrivateIPs: true, // Skip DNS resolution for tests
				AllowedSchemes:  []string{"https", "http"},
			},
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "invalid scheme - FTP",
			url:     "ftp://files.example.com/data",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name:    "invalid scheme - file",
			url:     "file:///etc/passwd",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name: "blocked host",
			url:  "https://malicious.com/api",
			opts: URLValidationOptions{
				AllowedSchemes: []string{"https"},
				BlockedHosts:   []string{"malicious.com"},
			},
			wantErr: true,
			errMsg:  "blocked",
		},
		{
			name: "allowed host suffix - match",
			url:  "https://myinstance.salesforce.com/api",
			opts: URLValidationOptions{
				AllowedSchemes:      []string{"https"},
				AllowedHostSuffixes: []string{".salesforce.com"},
				AllowPrivateIPs:     true, // Skip IP validation for this test
			},
			wantErr: false,
		},
		{
			name: "allowed host suffix - no match",
			url:  "https://evil.com/api",
			opts: URLValidationOptions{
				AllowedSchemes:      []string{"https"},
				AllowedHostSuffixes: []string{".salesforce.com"},
			},
			wantErr: true,
			errMsg:  "not in the allowed list",
		},
		{
			name: "exact host match",
			url:  "https://api.slack.com/users.list",
			opts: URLValidationOptions{
				AllowedSchemes:  []string{"https"},
				AllowedHosts:    []string{"api.slack.com"},
				AllowPrivateIPs: true,
			},
			wantErr: false,
		},
		{
			name: "URL with port number",
			url:  "https://api.github.com:443/v1/resource",
			opts: URLValidationOptions{
				AllowPrivateIPs: true,
				AllowedSchemes:  []string{"https"},
			},
			wantErr: false,
		},
		{
			name: "URL with non-standard port",
			url:  "https://custom.example.com:8443/api",
			opts: URLValidationOptions{
				AllowPrivateIPs: true,
				AllowedSchemes:  []string{"https"},
			},
			wantErr: false,
		},
		{
			name:    "URL missing hostname",
			url:     "https:///path/only",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "must contain a hostname",
		},
		{
			name:    "javascript scheme blocked",
			url:     "javascript:alert(1)",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name:    "data scheme blocked",
			url:     "data:text/html,<script>alert(1)</script>",
			opts:    DefaultURLValidationOptions(),
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name: "subdomain of blocked host",
			url:  "https://sub.malicious.com/api",
			opts: URLValidationOptions{
				AllowedSchemes: []string{"https"},
				BlockedHosts:   []string{"malicious.com"},
			},
			wantErr: true,
			errMsg:  "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateURL() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateURL() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateURL() unexpected error = %v", err)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private IPs (should return true)
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv4 alt", "127.0.0.2", true},
		{"private 10.x.x.x", "10.0.0.1", true},
		{"private 172.16.x.x", "172.16.0.1", true},
		{"private 192.168.x.x", "192.168.1.1", true},
		{"link-local", "169.254.1.1", true},
		{"unspecified", "0.0.0.0", true},
		{"carrier-grade NAT", "100.64.0.1", true},
		{"multicast", "224.0.0.1", true},
		{"reserved", "240.0.0.1", true},
		{"test-net-1", "192.0.2.1", true},
		{"test-net-2", "198.51.100.1", true},
		{"test-net-3", "203.0.113.1", true},
		{"loopback IPv6", "::1", true},
		{"private IPv6 fc00::", "fc00::1", true},
		{"private IPv6 fd00::", "fd00::1", true},
		{"link-local IPv6", "fe80::1", true},
		{"unspecified IPv6", "::", true},

		// Public IPs (should return false)
		{"public google DNS", "8.8.8.8", false},
		{"public IPv6 google", "2001:4860:4860::8888", false},
		{"public cloudflare", "1.1.1.1", false},
		{"public AWS", "52.94.76.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestSanitizeLogString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "newline injection",
			input:    "hello\nworld",
			expected: "hello\\nworld",
		},
		{
			name:     "carriage return injection",
			input:    "hello\rworld",
			expected: "hello\\rworld",
		},
		{
			name:     "CRLF injection",
			input:    "hello\r\nworld",
			expected: "hello\\r\\nworld",
		},
		{
			name:     "ANSI escape sequence",
			input:    "hello\x1b[31mred\x1b[0m",
			expected: "hellored",
		},
		{
			name:     "long string truncation",
			input:    strings.Repeat("a", 600),
			expected: strings.Repeat("a", 500) + "...[truncated]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeLogString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeLogString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestValidateSQLIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantErr    bool
	}{
		{"valid simple", "users", false},
		{"valid with underscore", "user_accounts", false},
		{"valid with number", "user123", false},
		{"valid uppercase", "UserAccounts", false},
		{"empty", "", true},
		{"starts with number", "123users", true},
		{"contains space", "user accounts", true},
		{"contains dash", "user-accounts", true},
		{"SQL reserved word SELECT", "SELECT", true},
		{"SQL reserved word DROP", "DROP", true},
		{"SQL reserved word TABLE", "table", true},
		{"SQL injection attempt", "users; DROP TABLE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSQLIdentifier(tt.identifier)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateSQLIdentifier(%q) expected error, got nil", tt.identifier)
			} else if !tt.wantErr && err != nil {
				t.Errorf("ValidateSQLIdentifier(%q) unexpected error = %v", tt.identifier, err)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid relative path", "data/file.txt", false},
		{"valid filename", "report.csv", false},
		{"empty path", "", true},
		{"path traversal ..", "../etc/passwd", true},
		{"path traversal multiple", "../../secret", true},
		{"null byte injection", "file\x00.txt", true},
		{"system path /etc/", "/etc/passwd", true},
		{"system path /proc/", "/proc/self/environ", true},
		{"valid absolute path", "/home/user/data.txt", false},
		{"windows path traversal", "..\\windows\\system32", true},
		{"system path /dev/", "/dev/null", true},
		{"system path /sys/", "/sys/kernel/debug", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateFilePath(%q) expected error, got nil", tt.path)
			} else if !tt.wantErr && err != nil {
				t.Errorf("ValidateFilePath(%q) unexpected error = %v", tt.path, err)
			}
		})
	}
}

// TestSSRFProtectionIntegration tests the complete SSRF protection flow
// as it would be used in a connector implementation.
func TestSSRFProtectionIntegration(t *testing.T) {
	// This test demonstrates how connectors should use the security utilities
	// to protect against SSRF attacks in a real-world scenario.

	t.Run("SaaS connector with host suffix allowlist", func(t *testing.T) {
		// Simulating a Salesforce-like SaaS connector that should only
		// connect to official Salesforce endpoints.
		// Note: Using AllowPrivateIPs=true to skip DNS resolution in tests,
		// since we're testing the allowlist logic, not DNS resolution.
		opts := URLValidationOptions{
			AllowPrivateIPs:     true, // Skip DNS for test (would resolve in production)
			AllowedSchemes:      []string{"https"},
			AllowedHostSuffixes: []string{".salesforce.com", ".force.com"},
		}

		// Valid Salesforce URLs should pass (host suffix matches)
		validURLs := []string{
			"https://mycompany.salesforce.com/services/data/v58.0/query",
			"https://mycompany.my.salesforce.com/services/oauth2/token",
			"https://login.salesforce.com/services/oauth2/authorize",
			"https://na1.force.com/api/v1/data",
		}
		for _, url := range validURLs {
			if err := ValidateURL(url, opts); err != nil {
				t.Errorf("Expected valid URL %q to pass, got error: %v", url, err)
			}
		}

		// Attacker-controlled URLs should be blocked (host suffix doesn't match)
		attackURLs := []string{
			"https://attacker.com/fake-salesforce",
			"https://salesforce.com.attacker.com/phishing", // Doesn't end with .salesforce.com
			"http://mycompany.salesforce.com/data",         // Wrong scheme (http not https)
		}
		for _, url := range attackURLs {
			if err := ValidateURL(url, opts); err == nil {
				t.Errorf("Expected attack URL %q to be blocked, but it passed", url)
			}
		}
	})

	t.Run("Self-hosted connector with allow_private_ips", func(t *testing.T) {
		// Simulating a Jira Server connector that needs to connect
		// to an internal corporate network
		opts := URLValidationOptions{
			AllowPrivateIPs: true, // Enabled for self-hosted
			AllowedSchemes:  []string{"https", "http"},
			// No AllowedHostSuffixes - allow any host
		}

		// Internal URLs should now pass
		internalURLs := []string{
			"https://jira.internal.company.com/rest/api/2/issue",
			"http://10.0.1.50:8080/rest/api/2/search",
			"https://192.168.1.100/gitlab/api/v4/projects",
		}
		for _, url := range internalURLs {
			if err := ValidateURL(url, opts); err != nil {
				t.Errorf("Expected internal URL %q to pass with AllowPrivateIPs=true, got error: %v", url, err)
			}
		}

		// Dangerous schemes should still be blocked
		if err := ValidateURL("file:///etc/passwd", opts); err == nil {
			t.Error("Expected file:// scheme to be blocked even with AllowPrivateIPs=true")
		}
	})

	t.Run("Combined security checks for connector initialization", func(t *testing.T) {
		// Simulating the security checks that should happen when
		// a connector is initialized with user-provided configuration
		type ConnectorConfig struct {
			BaseURL        string
			PrivateKeyPath string
		}

		testCases := []struct {
			name      string
			config    ConnectorConfig
			wantError bool
		}{
			{
				name: "valid SaaS configuration",
				config: ConnectorConfig{
					BaseURL: "https://api.service.com/v1",
				},
				wantError: false,
			},
			{
				name: "path traversal in private key path",
				config: ConnectorConfig{
					BaseURL:        "https://api.service.com/v1",
					PrivateKeyPath: "../../../etc/passwd",
				},
				wantError: true,
			},
			{
				name: "system path in private key path",
				config: ConnectorConfig{
					BaseURL:        "https://api.service.com/v1",
					PrivateKeyPath: "/etc/shadow",
				},
				wantError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Check URL first
				urlOpts := URLValidationOptions{
					AllowPrivateIPs: true, // Skip DNS for test
					AllowedSchemes:  []string{"https"},
				}
				err := ValidateURL(tc.config.BaseURL, urlOpts)

				// If URL is valid, check private key path if provided
				if err == nil && tc.config.PrivateKeyPath != "" {
					err = ValidateFilePath(tc.config.PrivateKeyPath)
				}

				if tc.wantError && err == nil {
					t.Errorf("Expected config validation to fail for %q", tc.name)
				} else if !tc.wantError && err != nil {
					t.Errorf("Expected config validation to pass for %q, got error: %v", tc.name, err)
				}
			})
		}
	})
}

// TestDefaultURLValidationOptions verifies secure defaults
func TestDefaultURLValidationOptions(t *testing.T) {
	opts := DefaultURLValidationOptions()

	// Defaults should block private IPs
	if opts.AllowPrivateIPs {
		t.Error("Default should have AllowPrivateIPs=false for security")
	}

	// Defaults should allow https and http
	if len(opts.AllowedSchemes) != 2 {
		t.Errorf("Expected 2 default schemes, got %d", len(opts.AllowedSchemes))
	}

	// No host restrictions by default (allows any public host)
	if len(opts.AllowedHosts) != 0 || len(opts.AllowedHostSuffixes) != 0 {
		t.Error("Default should not restrict hosts")
	}
}
