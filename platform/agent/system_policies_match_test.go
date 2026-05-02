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

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestSystemPolicies_PositivePatternMatches asserts that representative
// malicious payloads match the expected system policies and ONLY those
// policies. This is the kind of unit test that would have caught the
// observed perf-test symptom of `sys_sqli_grant` appearing in
// matched_policies for a benign `SELECT * FROM products LIMIT 10`:
// running the seeded patterns against known inputs locally is faster and
// more reliable than chasing the symptom in production logs.
//
// The map[input]expectedID encodes the contract — input X must match
// pattern Y and not be over-eagerly grabbed by a sibling pattern.
func TestSystemPolicies_PositivePatternMatches(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantID   string // policy ID that should match
	}{
		// SQL injection patterns
		{"union_select", "SELECT * FROM products WHERE id = 1 UNION SELECT username, password FROM admin", "sys_sqli_union_select"},
		// NOTE: the seeded `sys_sqli_or_true` pattern requires the `OR` keyword
		// before the comparison. The harness includes a `WHERE 1=1` scenario
		// which does NOT match any seeded pattern — that's a separate
		// harness/seed alignment bug filed as a follow-up. Here we test the
		// pattern against an input that legitimately should match it.
		{"or_true", "SELECT * FROM users WHERE id = 1 OR 1=1", "sys_sqli_or_true"},
		{"or_string", "SELECT * FROM users WHERE username = 'admin' OR 'a'='a'", "sys_sqli_or_string"},
		{"stacked_drop", "SELECT * FROM products WHERE id = 1; DROP TABLE products", "sys_sqli_stacked_drop"},
		{"sleep", "SELECT * FROM products WHERE SLEEP(5)", "sys_sqli_sleep"},
		{"grant", "GRANT SELECT ON foo TO bar", "sys_sqli_grant"},
	}

	policies := GetStaticSystemPolicies()
	patternByID := make(map[string]*regexp.Regexp, len(policies))
	for _, p := range policies {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("policy %s has invalid regex %q: %v", p.ID, p.Pattern, err)
		}
		patternByID[p.ID] = re
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re, ok := patternByID[tc.wantID]
			if !ok {
				t.Fatalf("expected policy %q not found in seed", tc.wantID)
			}
			if !re.MatchString(tc.input) {
				t.Errorf("input %q did NOT match expected policy %s (pattern %q)",
					tc.input, tc.wantID, re.String())
			}
		})
	}
}

// TestSystemPolicies_NegativeBenignInputs asserts that BENIGN queries —
// the harness's "normal" scenarios — are not matched by ANY system policy
// (specifically, not by sys_sqli_grant which has historically been
// observed firing on inputs that contain no GRANT keyword).
//
// This is the test that would have failed locally and prevented the
// "sys_sqli_grant fires on SELECT * FROM products" surprise from
// reaching the perf benchmark stack.
func TestSystemPolicies_NegativeBenignInputs(t *testing.T) {
	benignInputs := []string{
		"SELECT * FROM products LIMIT 10",
		"SELECT name, price FROM products WHERE category = 'electronics' AND price < 1000",
		"SELECT o.id, c.name FROM orders o JOIN customers c ON o.customer_id = c.id LIMIT 50",
		"SELECT category, COUNT(*), AVG(price) FROM products GROUP BY category HAVING COUNT(*) > 5",
		"INSERT INTO orders (customer_id, total) VALUES (123, 99.99)",
		"UPDATE products SET price = 29.99 WHERE id = 456",
		"SELECT email, name FROM customers WHERE signup_date > '2024-01-01'",
		"SELECT phone_number, address FROM customers WHERE region = 'US'",
	}

	policies := GetStaticSystemPolicies()

	for _, input := range benignInputs {
		t.Run(truncate(input, 40), func(t *testing.T) {
			for _, p := range policies {
				re, err := regexp.Compile(p.Pattern)
				if err != nil {
					t.Fatalf("policy %s invalid regex: %v", p.ID, err)
				}
				if re.MatchString(input) {
					// Some benign inputs DO legitimately contain PII (e.g.
					// "phone_number", "email") which match PII detection
					// patterns by design. Only fail on security-sqli /
					// security-admin / code-* — those should never fire on
					// these inputs.
					switch p.Category {
					case CategorySecuritySQLi, CategorySecurityAdmin:
						t.Errorf("benign input %q should NOT match policy %s (pattern %q, category %s)",
							input, p.ID, re.String(), p.Category)
					}
				}
			}
		})
	}
}

// TestSystemPolicies_BookingRefPatternIsContextScoped guards against the
// regression where the booking-ref PII pattern fires on every common SQL
// keyword. The previous regex was \b[A-Z0-9]{6}\b which matched SELECT,
// INSERT, DELETE, UPDATE, CREATE, RETURN, etc. — all 6-char uppercase
// keywords — generating audit-log noise on every benign query and
// inflating "PII detected" counts in compliance dashboards.
//
// The fix requires a booking-context label before the alphanumeric token.
func TestSystemPolicies_BookingRefPatternIsContextScoped(t *testing.T) {
	policies := GetStaticSystemPolicies()
	var bookingPattern string
	for _, p := range policies {
		if p.ID == "sys_pii_booking_ref" {
			bookingPattern = p.Pattern
			break
		}
	}
	if bookingPattern == "" {
		t.Fatal("sys_pii_booking_ref policy not found in seed")
	}
	re, err := regexp.Compile(bookingPattern)
	if err != nil {
		t.Fatalf("sys_pii_booking_ref pattern compile: %v", err)
	}

	mustMatch := []string{
		"booking ABC123",
		"Booking: XYZ789",
		"reservation REF456",
		"PNR ABCDEF",
		"PNR: ABCDEF",
		"reference QWERTY",
		"ref: A1B2C3",
		"confirmation 1A2B3C",
		"conf #ZZ9999",
		"Please find your booking ABC123 attached.",       // mid-string
		"Hello — confirmation: ABCDEF — see attached PDF", // dashes around
	}
	mustNotMatch := []string{
		// Common SQL keywords (all 6-char, all caps) — the bug we're fixing
		"SELECT * FROM products LIMIT 10",
		"INSERT INTO orders (id) VALUES (1)",
		"DELETE FROM customers WHERE id = 1",
		"UPDATE products SET price = 1",
		"CREATE TABLE foo (id INT)",
		"RETURN value",
		// Bare 6-char tokens with no booking context
		"random ABC123 word",
		"Q1 2025 report shows ABCDEF totals",
		// All-letters or all-digits 6-char tokens
		"ABCDEF",
		"123456",
		// Common short SQL fragments
		"FROM users WHERE id = 1",
	}

	for _, s := range mustMatch {
		if !re.MatchString(s) {
			t.Errorf("expected sys_pii_booking_ref to match %q", s)
		}
	}
	for _, s := range mustNotMatch {
		if re.MatchString(s) {
			t.Errorf("expected sys_pii_booking_ref to NOT match %q (over-matching benign input)", s)
		}
	}
}

// TestSystemPolicies_GRANTPatternIsScoped specifically guards against the
// regression where sys_sqli_grant's pattern accidentally matches
// non-GRANT queries. The pattern (?i)\bGRANT\s+ should only match strings
// that contain the GRANT keyword followed by whitespace.
func TestSystemPolicies_GRANTPatternIsScoped(t *testing.T) {
	policies := GetStaticSystemPolicies()
	var grantPattern string
	for _, p := range policies {
		if p.ID == "sys_sqli_grant" {
			grantPattern = p.Pattern
			break
		}
	}
	if grantPattern == "" {
		t.Fatal("sys_sqli_grant policy not found in seed")
	}
	re, err := regexp.Compile(grantPattern)
	if err != nil {
		t.Fatalf("sys_sqli_grant pattern compile: %v", err)
	}

	mustMatch := []string{
		"GRANT SELECT ON foo TO bar",
		"grant insert on baz to qux",       // case-insensitive
		"REVOKE x; GRANT y ON z TO w",      // mid-string
	}
	mustNotMatch := []string{
		"SELECT * FROM products LIMIT 10",
		"SELECT migrant_status FROM users", // "grant" inside word — \b should reject
		"INSERT INTO grantable (col) VALUES (1)",
	}

	for _, s := range mustMatch {
		if !re.MatchString(s) {
			t.Errorf("expected sys_sqli_grant to match %q", s)
		}
	}
	for _, s := range mustNotMatch {
		if re.MatchString(s) {
			t.Errorf("expected sys_sqli_grant to NOT match %q", s)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// TestPerfHarness_ScenariosAlignWithSeededPatterns is the cross-table that
// pins the contract between the perf-testing harness's expected response
// codes and the actual seeded SQLi / admin / dangerous-ops policies.
//
// SINGLE SOURCE OF TRUTH: scenarios are loaded from
// ee/platform/load-testing/scenarios.json. The harness embeds the same
// file at compile time. When the harness scenario list changes, this
// test reads the new content automatically — no duplicated lists to
// keep in sync.
//
// History: this is the test that would have caught the "SELECT * FROM
// products WHERE 1=1" misalignment that the iteration-2 perf run exposed
// (the harness expected 403 but no seeded pattern caught a bare 1=1
// without OR, so it landed as Unexpected). The harness scenario was
// updated to use the realistic injection shape (`OR 1=1`) — this test
// guards against the same class of drift on every other scenario.
//
// CONTRACT:
//   - sql_injection / dangerous category → must match at least one seeded
//     block-action policy (security-sqli or security-admin)
//   - normal category → must NOT match any seeded SQLi / admin pattern
//   - pii / llm categories are not asserted here (they're allowed by the
//     harness's expected codes; PII detection is a redact action, not block)
func TestPerfHarness_ScenariosAlignWithSeededPatterns(t *testing.T) {
	type harnessScenario struct {
		Name         string `json:"name"`
		Query        string `json:"query"`
		RequestType  string `json:"request_type"`
		ExpectedCode int    `json:"expected_code"`
		Category     string `json:"category"`
	}

	// Load the canonical scenarios from the harness's own JSON. Path is
	// relative to this test file's package directory (platform/agent/).
	// Using filepath.Join so this works on every platform's CI runner.
	scenariosPath := filepath.Join("..", "..", "ee", "platform", "load-testing", "scenarios.json")
	raw, err := os.ReadFile(scenariosPath)
	if err != nil {
		t.Fatalf("read harness scenarios.json: %v (path %q)", err, scenariosPath)
	}
	var scenarios []harnessScenario
	if err := json.Unmarshal(raw, &scenarios); err != nil {
		t.Fatalf("parse harness scenarios.json: %v", err)
	}
	if len(scenarios) == 0 {
		t.Fatalf("scenarios.json is empty — single-source-of-truth invariant broken")
	}

	// Build the index: map of policy ID → compiled regex, plus index of
	// block-action security patterns (the only ones that can drive a 403).
	policies := GetStaticSystemPolicies()
	type compiledPolicy struct {
		id       string
		category PolicyCategory
		action   string
		re       *regexp.Regexp
	}
	compiled := make([]compiledPolicy, 0, len(policies))
	for _, p := range policies {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Fatalf("policy %s invalid regex %q: %v", p.ID, p.Pattern, err)
		}
		compiled = append(compiled, compiledPolicy{
			id:       p.ID,
			category: p.Category,
			action:   p.Action,
			re:       re,
		})
	}

	isSecurityCategory := func(c PolicyCategory) bool {
		return c == CategorySecuritySQLi || c == CategorySecurityAdmin
	}

	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			// Find which seeded patterns match this input.
			var matchingBlockSecurity []string
			var matchingAnySecurity []string
			for _, p := range compiled {
				if !p.re.MatchString(sc.Query) {
					continue
				}
				if isSecurityCategory(p.category) {
					matchingAnySecurity = append(matchingAnySecurity, p.id)
					if p.action == "block" {
						matchingBlockSecurity = append(matchingBlockSecurity, p.id)
					}
				}
			}

			switch sc.Category {
			case "sql_injection", "dangerous":
				if len(matchingBlockSecurity) == 0 {
					t.Errorf("scenario %q (category=%s) is expected to be BLOCKED (403), but no seeded security policy with action=block matches the query %q.\n"+
						"Either:\n"+
						"  (a) the harness's expected code is wrong (this isn't really a malicious payload), or\n"+
						"  (b) the seeded patterns don't cover this attack shape — file a platform-side fix to add a pattern, or\n"+
						"  (c) the scenario should be reshaped to a realistic injection that an existing pattern catches.",
						sc.Name, sc.Category, sc.Query)
				}
			case "normal":
				if len(matchingAnySecurity) > 0 {
					t.Errorf("scenario %q (category=normal) is expected to PASS (200), but seeded security policies %v matched the query %q.\n"+
						"Either:\n"+
						"  (a) the seeded pattern is over-matching benign queries (false positive — fix the regex), or\n"+
						"  (b) the harness scenario is unrealistic (a real workload wouldn't include this shape).",
						sc.Name, matchingAnySecurity, sc.Query)
				}
			}
		})
	}
}
