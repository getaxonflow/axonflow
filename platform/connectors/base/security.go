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

package base

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"axonflow/platform/shared/egress"
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
	// EgressPolicy selects which shared egress posture the private-IP check
	// applies. nil means egress.ConnectorEgress, which is what every connector
	// wants. Surfaces whose URL is caller-supplied per request rather than
	// operator-configured infrastructure — the orchestrator media fetcher, the
	// SAML metadata fetch — pass egress.CallbackEgress so that their pre-flight
	// and their socket-level guard state the SAME posture. A backstop that
	// disagrees with the check it backstops is how #3104 found this class.
	EgressPolicy *egress.Policy
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
		policy := egress.ConnectorEgress
		if opts.EgressPolicy != nil {
			policy = *opts.EgressPolicy
		}
		if err := validateHostNotPrivate(hostname, policy); err != nil {
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

// validateHostNotPrivate resolves the hostname and checks the answers against
// the caller's egress policy.
func validateHostNotPrivate(hostname string, policy egress.Policy) error {
	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %q: %w", hostname, err)
	}

	for _, ip := range ips {
		if policy.Blocks(ip) {
			return fmt.Errorf("connection to private/internal IP %s is not allowed (hostname: %s; %s)", ip, hostname, policy.Reason(ip))
		}
	}

	return nil
}

// IsPrivateIP reports whether an IP address is private, loopback, or otherwise
// internal/reserved and therefore must not be dialled by a connector.
//
// This is the connector layer's binding to the canonical egress policy. The
// range table itself lives in platform/shared/egress and is shared with every
// other surface that dials a configured URL; see #3104, which found nine
// independent classifiers with five distinct behaviours. Connectors MUST call
// this rather than keeping a local copy: two predicates drift, and the weaker
// one becomes the exploitable path (#3095).
//
// The posture is egress.ConnectorEgress, which permits exactly one reserved
// range — 198.18.0.0/15 (RFC 2544 / RFC 6815 benchmarking) — because
// runtime-e2e suites carve sentinel networks out of it. Every other named
// range in the table is refused. Callback surfaces use egress.CallbackEgress,
// which permits nothing.
//
// Fail-closed: a nil or malformed net.IP is reported as private.
func IsPrivateIP(ip net.IP) bool {
	return egress.ConnectorEgress.Blocks(ip)
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
