// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import "testing"

// TestNormalize_RealWrittenValues pins the mapping for every value an actual
// writer emits to audit_logs.policy_decision today (the census in ADR-058 and
// issue #2638). If any of these regress, a real decision becomes mislabeled —
// so this is the table the hostile review cross-checks for exhaustiveness.
func TestNormalize_RealWrittenValues(t *testing.T) {
	cases := []struct {
		raw    string
		want   string
		writer string
	}{
		// allow/deny: NO forward audit writer emits these anymore — they are the
		// wire-only Decision-API verdicts (VerdictAllow/Deny), converted to
		// allowed/blocked at every audit-write boundary, plus historical rows
		// (migration 122 backfilled them). Kept as aliases for stragglers/raw-SQL.
		{"allow", DecisionAllowed, "wire verdict + historical (mig 122)"},
		{"deny", DecisionBlocked, "wire verdict + historical (mig 122)"},
		{"needs_approval", DecisionNeedsApproval, "agent /decide + gateway (already canonical)"},
		// allowed/blocked: every forward plane emits canonical now —
		// decision #2643, MCP #2641/#2651, gateway #2642, orchestrator, EE HITL.
		{"allowed", DecisionAllowed, "decision/MCP/gateway/orchestrator/HITL (canonical)"},
		{"blocked", DecisionBlocked, "decision/MCP/gateway/orchestrator/HITL (canonical)"},
		{"redacted", DecisionRedacted, "orchestrator response"},
		{"error", DecisionError, "orchestrator plan/tool failed"},
		{"pending_approval", DecisionNeedsApproval, "orchestrator workflow gate"},
		// orchestrator — override_audit.go (non-verdict marker, passes through)
		{"override_lifecycle", DecisionOverrideLifecycle, "orchestrator override audit"},
	}
	for _, c := range cases {
		if got := Normalize(c.raw); got != c.want {
			t.Errorf("Normalize(%q) [written by %s] = %q, want %q", c.raw, c.writer, got, c.want)
		}
	}
}

// TestNormalize_ReaderAndLegacyValues covers spellings that appear in reader
// filters / exporters / the frontend display vocab but that no writer emits —
// the divergence this package exists to reconcile.
func TestNormalize_ReaderAndLegacyValues(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"require_approval", DecisionNeedsApproval}, // decisions_list_handler filter + euaiact/sebi exporters
		{"denied", DecisionBlocked},                 // audit_summary_handler switch
		{"modified", DecisionRedacted},              // frontend AuditAction display vocab
	}
	for _, c := range cases {
		if got := Normalize(c.raw); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// TestNormalize_DefensiveAliases covers spellings no surface emits today but
// that are mapped for robustness. Kept in their own test so the "real written
// set" stays honestly separated from defensive coverage.
func TestNormalize_DefensiveAliases(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"block", DecisionBlocked},
		{"redact", DecisionRedacted},
		{"masked", DecisionRedacted},
		{"need_approval", DecisionNeedsApproval},
		{"needs-approval", DecisionNeedsApproval},
		{"requires_approval", DecisionNeedsApproval},
		{"requires-approval", DecisionNeedsApproval},
		{"pending-approval", DecisionNeedsApproval},
		{"awaiting_approval", DecisionNeedsApproval},
		{"errored", DecisionError},
		{"failed", DecisionError},
	}
	for _, c := range cases {
		if got := Normalize(c.raw); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// TestNormalize_CanonicalValuesAreStable asserts every canonical value
// normalizes to itself (idempotence) — Normalize(Normalize(x)) == Normalize(x).
func TestNormalize_CanonicalValuesAreStable(t *testing.T) {
	for _, v := range All() {
		got := Normalize(v)
		if got != v {
			t.Errorf("Normalize(%q) = %q, canonical value must map to itself", v, got)
		}
		if again := Normalize(got); again != v {
			t.Errorf("Normalize is not idempotent for %q", v)
		}
	}
	// The non-verdict marker is likewise stable.
	if got := Normalize(DecisionOverrideLifecycle); got != DecisionOverrideLifecycle {
		t.Errorf("Normalize(%q) = %q, marker must pass through", DecisionOverrideLifecycle, got)
	}
}

// TestNormalize_CaseAndWhitespaceInsensitive — a raw value with stray casing or
// surrounding whitespace must still normalize.
func TestNormalize_CaseAndWhitespaceInsensitive(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"ALLOW", DecisionAllowed},
		{"Deny", DecisionBlocked},
		{"  redacted  ", DecisionRedacted},
		{"\tNeeds_Approval\n", DecisionNeedsApproval},
		{"REQUIRE_APPROVAL", DecisionNeedsApproval},
	}
	for _, c := range cases {
		if got := Normalize(c.raw); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// TestNormalize_UnknownNeverFailsOpen is the precondition-absent test the whole
// package exists for: an unrecognized value (the precondition "this is a known
// verdict" is ABSENT) must resolve to the explicit fail-safe DecisionError and
// MUST NEVER silently become DecisionAllowed. The fail-safe class is "error" to
// match the merged writer-side helper (#2643 canonicalAuditVerdict), so the
// shared normalizer and the writer never disagree on an unknown verdict. If this
// ever returns "allowed", the fail-open bug this package prevents has returned.
func TestNormalize_UnknownNeverFailsOpen(t *testing.T) {
	unknowns := []string{
		"",
		"   ",
		"bogus",
		"approve",        // export OUTPUT vocab, not a policy_decision input
		"approved",       // ditto
		"pending_review", // ditto
		"logged",         // frontend phantom — no writer, not a verdict
		"alerted",        // frontend phantom
		"warn",
		"42",
		"allow ed",
		"need approval",
	}
	for _, raw := range unknowns {
		got := Normalize(raw)
		if got == DecisionAllowed {
			t.Fatalf("FAIL-OPEN: Normalize(%q) = %q (must never be %q)", raw, got, DecisionAllowed)
		}
		if got != DecisionError {
			t.Errorf("Normalize(%q) = %q, want fail-safe %q", raw, got, DecisionError)
		}
		// An unrecognized value must NOT be reported as known, even though it
		// fail-safes to the same string as a genuine "error" verdict.
		if IsKnown(raw) {
			t.Errorf("IsKnown(%q) = true, want false (unrecognized value)", raw)
		}
	}
	// A genuine "error" verdict, by contrast, IS known and normalizes to itself.
	if !IsKnown("error") || Normalize("error") != DecisionError {
		t.Errorf("genuine error verdict must be known and normalize to %q", DecisionError)
	}
}

func TestIsCanonical(t *testing.T) {
	for _, v := range All() {
		if !IsCanonical(v) {
			t.Errorf("IsCanonical(%q) = false, want true", v)
		}
	}
	// case-insensitive
	if !IsCanonical("ALLOWED") {
		t.Errorf("IsCanonical(%q) = false, want true (case-insensitive)", "ALLOWED")
	}
	// legacy spellings are NOT canonical (they need normalizing first)
	for _, v := range []string{"allow", "deny", "require_approval", "pending_approval", "modified"} {
		if IsCanonical(v) {
			t.Errorf("IsCanonical(%q) = true, want false (legacy, not canonical)", v)
		}
	}
	// the non-verdict marker and unrecognized values are not canonical verdicts
	for _, v := range []string{DecisionOverrideLifecycle, "", "bogus"} {
		if IsCanonical(v) {
			t.Errorf("IsCanonical(%q) = true, want false", v)
		}
	}
}

func TestIsKnown(t *testing.T) {
	known := append(All(),
		"allow", "deny", "needs_approval", "pending_approval", "require_approval",
		"denied", "modified", "block", DecisionOverrideLifecycle, "ALLOW",
	)
	for _, v := range known {
		if !IsKnown(v) {
			t.Errorf("IsKnown(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "bogus", "approved", "pending_review", "logged", "alerted"} {
		if IsKnown(v) {
			t.Errorf("IsKnown(%q) = true, want false", v)
		}
	}
}

// TestAll_ShapeAndContract guards the canonical set's size and contents so a
// future edit to the constants can't silently add/drop a verdict without this
// test (and the ADR mapping table it mirrors) being updated.
func TestAll_ShapeAndContract(t *testing.T) {
	all := All()
	if len(all) != 5 {
		t.Fatalf("All() has %d entries, want 5 (allowed, blocked, redacted, needs_approval, error)", len(all))
	}
	want := map[string]bool{
		DecisionAllowed:       true,
		DecisionBlocked:       true,
		DecisionRedacted:      true,
		DecisionNeedsApproval: true,
		DecisionError:         true,
	}
	for _, v := range all {
		if !want[v] {
			t.Errorf("All() contains unexpected value %q", v)
		}
		delete(want, v)
	}
	if len(want) != 0 {
		t.Errorf("All() is missing canonical values: %v", want)
	}
	// Every element of All() must itself be canonical and known.
	for _, v := range all {
		if !IsCanonical(v) || !IsKnown(v) {
			t.Errorf("All() member %q must be canonical and known", v)
		}
	}
	// The non-verdict marker must NOT leak into All().
	for _, v := range all {
		if v == DecisionOverrideLifecycle {
			t.Errorf("All() must not contain %q", v)
		}
	}
}

// TestAll_ReturnsCopy ensures a caller mutating the returned slice cannot
// corrupt the canonical set for other callers.
func TestAll_ReturnsCopy(t *testing.T) {
	a := All()
	if len(a) == 0 {
		t.Fatal("All() returned empty")
	}
	a[0] = "tampered"
	b := All()
	if b[0] == "tampered" {
		t.Error("All() returned a shared backing array; mutation leaked across calls")
	}
}
