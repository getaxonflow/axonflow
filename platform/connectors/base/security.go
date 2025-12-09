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
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// URLValidationOptions configures URL validation behavior
type URLValidationOptions struct {
	// AllowPrivateIPs permits connections to private/internal IP addresses
	AllowPrivateIPs bool
	// AllowedSchemes specifies permitted URL schemes (default: ["https", "http"])
	AllowedSchemes []string
	// AllowedHostSuffixes restricts URLs to specific domain suffixes
	// e.g., [".salesforce.com", ".service-now.com"]
	AllowedHostSuffixes []string
	// AllowedHosts restricts URLs to specific exact hostnames
	AllowedHosts []string
	// BlockedHosts explicitly blocks certain hostnames
	BlockedHosts []string
}

// DefaultURLValidationOptions returns secure defaults for URL validation
func DefaultURLValidationOptions() URLValidationOptions {
	return URLValidationOptions{
		AllowPrivateIPs: false,
		AllowedSchemes:  []string{"https", "http"},
	}
}

// ValidateURL performs SSRF protection by validating a URL against security rules.
// It checks:
// - URL format and scheme
// - Host resolution to prevent DNS rebinding
// - Private/internal IP blocking (unless explicitly allowed)
// - Domain allowlist/blocklist enforcement
func ValidateURL(rawURL string, opts URLValidationOptions) error {
	if rawURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Validate scheme
	if err := validateScheme(parsedURL.Scheme, opts.AllowedSchemes); err != nil {
		return err
	}

	// Extract hostname
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must contain a hostname")
	}

	// Check blocked hosts
	if isHostBlocked(hostname, opts.BlockedHosts) {
		return fmt.Errorf("hostname %q is blocked", hostname)
	}

	// Check allowed hosts/suffixes if specified
	if len(opts.AllowedHosts) > 0 || len(opts.AllowedHostSuffixes) > 0 {
		if !isHostAllowed(hostname, opts.AllowedHosts, opts.AllowedHostSuffixes) {
			return fmt.Errorf("hostname %q is not in the allowed list", hostname)
		}
	}

	// SSRF protection: validate resolved IPs
	if !opts.AllowPrivateIPs {
		if err := validateHostNotPrivate(hostname); err != nil {
			return err
		}
	}

	return nil
}

// validateScheme checks if the URL scheme is allowed
func validateScheme(scheme string, allowedSchemes []string) error {
	if len(allowedSchemes) == 0 {
		allowedSchemes = []string{"https", "http"}
	}

	scheme = strings.ToLower(scheme)
	for _, allowed := range allowedSchemes {
		if scheme == strings.ToLower(allowed) {
			return nil
		}
	}

	return fmt.Errorf("URL scheme %q is not allowed; permitted schemes: %v", scheme, allowedSchemes)
}

// validateHostNotPrivate resolves the hostname and checks for private IPs
func validateHostNotPrivate(hostname string) error {
	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %q: %w", hostname, err)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("connection to private/internal IP %s is not allowed (hostname: %s)", ip, hostname)
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is private, loopback, or otherwise internal
func isPrivateIP(ip net.IP) bool {
	// Check for loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local addresses (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	if ip.IsPrivate() {
		return true
	}

	// Check for unspecified addresses (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Additional IPv4 checks
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16 (link-local, may not be caught by IsLinkLocalUnicast)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 127.0.0.0/8 (loopback range)
		if ip4[0] == 127 {
			return true
		}
		// 0.0.0.0/8 (current network)
		if ip4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 (Carrier-grade NAT)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 192.0.0.0/24 (IETF Protocol Assignments)
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
		// 192.0.2.0/24 (TEST-NET-1)
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		// 198.51.100.0/24 (TEST-NET-2)
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		// 203.0.113.0/24 (TEST-NET-3)
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
		// 224.0.0.0/4 (Multicast)
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 (Reserved)
		if ip4[0] >= 240 {
			return true
		}
	}

	return false
}

// isHostBlocked checks if a hostname is in the blocked list
func isHostBlocked(hostname string, blockedHosts []string) bool {
	hostname = strings.ToLower(hostname)
	for _, blocked := range blockedHosts {
		blocked = strings.ToLower(blocked)
		if hostname == blocked || strings.HasSuffix(hostname, "."+blocked) {
			return true
		}
	}
	return false
}

// isHostAllowed checks if a hostname matches allowed hosts or suffixes
func isHostAllowed(hostname string, allowedHosts, allowedSuffixes []string) bool {
	hostname = strings.ToLower(hostname)

	// Check exact matches
	for _, allowed := range allowedHosts {
		if strings.ToLower(allowed) == hostname {
			return true
		}
	}

	// Check suffix matches
	for _, suffix := range allowedSuffixes {
		suffix = strings.ToLower(suffix)
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	return false
}

// SanitizeLogString removes or escapes characters that could be used for log injection
// This prevents attackers from injecting fake log entries or control characters
func SanitizeLogString(s string) string {
	// Remove newlines and carriage returns to prevent log injection
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	// Remove ANSI escape sequences
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	s = ansiRegex.ReplaceAllString(s, "")
	// Limit length to prevent log flooding
	const maxLogLength = 500
	if len(s) > maxLogLength {
		s = s[:maxLogLength] + "...[truncated]"
	}
	return s
}

// ValidateSQLIdentifier checks if a string is safe to use as a SQL identifier
// (table name, column name, etc.) to prevent SQL injection
func ValidateSQLIdentifier(identifier string) error {
	if identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	// SQL identifiers should only contain alphanumeric characters and underscores
	// and should not start with a number
	validIdentifier := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !validIdentifier.MatchString(identifier) {
		return fmt.Errorf("invalid SQL identifier: %q", identifier)
	}

	// Check against SQL reserved words (common ones)
	reserved := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"TABLE", "DATABASE", "INDEX", "FROM", "WHERE", "AND", "OR", "NOT",
		"NULL", "TRUE", "FALSE", "JOIN", "ON", "AS", "ORDER", "BY", "GROUP",
		"HAVING", "UNION", "ALL", "DISTINCT", "LIMIT", "OFFSET", "INTO",
		"VALUES", "SET", "GRANT", "REVOKE", "TRUNCATE", "CASCADE",
	}

	upperIdentifier := strings.ToUpper(identifier)
	for _, word := range reserved {
		if upperIdentifier == word {
			return fmt.Errorf("identifier %q is a SQL reserved word", identifier)
		}
	}

	return nil
}

// ValidateFilePath checks if a file path is safe (no path traversal)
func ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed: %q", path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("null bytes not allowed in path")
	}

	// Check for absolute paths trying to escape
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		// Absolute paths should be validated by the caller
		// but we flag potentially dangerous patterns
		dangerousPaths := []string{"/etc/", "/proc/", "/sys/", "/dev/", "\\windows\\", "\\system32\\"}
		lowerPath := strings.ToLower(path)
		for _, dangerous := range dangerousPaths {
			if strings.HasPrefix(lowerPath, dangerous) {
				return fmt.Errorf("access to system path not allowed: %q", path)
			}
		}
	}

	return nil
}
