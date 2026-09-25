// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package retiredenv

import (
	"strings"
	"testing"
)

// clearAll unsets every retired variable for the test, so an operator's shell
// cannot decide the outcome.
func clearAll(t *testing.T) {
	t.Helper()
	for _, name := range retiredNames() {
		t.Setenv(name, "")
	}
}

func TestEveryRetiredVariableRefusesBootByName(t *testing.T) {
	for _, name := range DecisionMode {
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			t.Setenv(name, "shadow")
			err := Refuse()
			if err == nil {
				t.Fatalf("%s=shadow booted; a set retired variable must refuse, not be ignored", name)
			}
			for _, want := range []string{name + `="shadow"`, PRD, "§5.1"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

func TestAnUnsetOrEmptyRetiredVariableBoots(t *testing.T) {
	clearAll(t)
	if err := Refuse(); err != nil {
		t.Fatalf("nothing is set and boot was refused: %v", err)
	}
	// Every release before v11 passes these through empty
	// (`${AXONFLOW_DECISION_SHADOW_MODE:-}`); an empty value chose nothing.
	for _, blank := range []string{"", " ", "\t"} {
		t.Setenv("AXONFLOW_DECISION_SHADOW_MODE", blank)
		if err := Refuse(); err != nil {
			t.Fatalf("AXONFLOW_DECISION_SHADOW_MODE=%q refused boot: %v", blank, err)
		}
	}
}

func TestSeveralRetiredVariablesAreNamedTogether(t *testing.T) {
	clearAll(t)
	t.Setenv("AXONFLOW_DECISION_SHADOW_MODE", "enforce")
	t.Setenv("AXONFLOW_DECISION_SHADOW_SAMPLE_RATE", "0.5")
	err := Refuse()
	if err == nil {
		t.Fatal("two retired variables set and boot was not refused")
	}
	for _, want := range []string{`AXONFLOW_DECISION_SHADOW_MODE="enforce"`, `AXONFLOW_DECISION_SHADOW_SAMPLE_RATE="0.5"`, "Remove them"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
}

func TestEveryRetiredMCPDynamicPolicyVariableRefusesBootByName(t *testing.T) {
	for _, name := range MCPDynamicPolicies {
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			// "false" too: a pre-v11 compose default was a non-empty "false",
			// and a set variable is refused whatever it says.
			t.Setenv(name, "false")
			err := Refuse()
			if err == nil {
				t.Fatalf("%s=false booted; a set retired variable must refuse, not be ignored", name)
			}
			for _, want := range []string{name + `="false"`, PRD, "§1.2", "MCP dynamic-policy plane"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), "decision mode") {
				t.Fatalf("an MCP dynamic-policy variable was refused with the decision mode's reason: %v", err)
			}
		})
	}
}

func TestAnEmptyMCPDynamicPolicyVariableBoots(t *testing.T) {
	clearAll(t)
	for _, blank := range []string{"", " ", "\t"} {
		t.Setenv("MCP_DYNAMIC_POLICIES_ENABLED", blank)
		if err := Refuse(); err != nil {
			t.Fatalf("MCP_DYNAMIC_POLICIES_ENABLED=%q refused boot: %v", blank, err)
		}
	}
}

func TestEveryRetiredFinCrimeScorerVariableRefusesBootByName(t *testing.T) {
	for _, name := range FinCrimeScorer {
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			// "100" is the v10 enterprise compose file's default for the
			// timeout, so an upgrade that keeps that file must be refused.
			t.Setenv(name, "100")
			err := Refuse()
			if err == nil {
				t.Fatalf("%s=100 booted; a set retired variable must refuse, not be ignored", name)
			}
			want := append([]string{name + `="100"`, PRD, "§1.2", "FinCrime Engine B scorer"}, FinCrimeRiskFactReplacements...)
			for _, want := range want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
			for _, other := range []string{"decision mode", "MCP dynamic-policy plane"} {
				if strings.Contains(err.Error(), other) {
					t.Fatalf("a FinCrime scorer variable was refused with another family's reason (%q): %v", other, err)
				}
			}
		})
	}
}

// TestTheV10FinCrimeScorerNamesStayRetired pins the retired set BY VALUE
// (#3330): the Engine B score came back in v11.1.0 as a fact under new names,
// and un-retiring a v10 name - which carried "the scorer's threshold decides" -
// by deleting it here would boot a v10 environment into a meaning its
// configuration misdescribes. Removing one fails this test on purpose.
func TestTheV10FinCrimeScorerNamesStayRetired(t *testing.T) {
	want := []string{"AXONFLOW_FINCRIME_SCORER_URL", "AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS"}
	if strings.Join(FinCrimeScorer, ",") != strings.Join(want, ",") {
		t.Fatalf("the retired v10 FinCrime scorer set is %v; want exactly %v", FinCrimeScorer, want)
	}
}

// TestTheFinCrimeRiskFactNamesAreNotRetired holds the replacement names out of
// every retired family, so a process configuring the v11.1.0 fact boots, and
// the refusal of a v10 name points at a name that is accepted.
func TestTheFinCrimeRiskFactNamesAreNotRetired(t *testing.T) {
	if len(FinCrimeRiskFactReplacements) != len(FinCrimeScorer) {
		t.Fatalf("%d replacements for %d retired names; each v10 name has one", len(FinCrimeRiskFactReplacements), len(FinCrimeScorer))
	}
	retired := map[string]bool{}
	for _, name := range retiredNames() {
		retired[name] = true
	}
	for _, name := range FinCrimeRiskFactReplacements {
		if retired[name] {
			t.Fatalf("%s is in a retired family", name)
		}
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			t.Setenv(name, "100")
			if err := Refuse(); err != nil {
				t.Fatalf("%s=100 refused boot: %v", name, err)
			}
		})
	}
}

func TestAnEmptyFinCrimeScorerVariableBoots(t *testing.T) {
	clearAll(t)
	// The v10 enterprise compose file passed the URL through empty.
	for _, blank := range []string{"", " ", "\t"} {
		t.Setenv("AXONFLOW_FINCRIME_SCORER_URL", blank)
		if err := Refuse(); err != nil {
			t.Fatalf("AXONFLOW_FINCRIME_SCORER_URL=%q refused boot: %v", blank, err)
		}
	}
}

func TestEveryRetiredIdentityCompatVariableRefusesBootByName(t *testing.T) {
	for _, name := range IdentityCompat {
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			// "off" too: it was the identity-compat mode's pre-v11 default, and a
			// set variable is refused whatever it says.
			t.Setenv(name, "off")
			err := Refuse()
			if err == nil {
				t.Fatalf("%s=off booted; a set retired variable must refuse, not be ignored", name)
			}
			for _, want := range []string{name + `="off"`, PRD, "§1.3", "identity-compat mode", IdentityCompatNotes} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
			for _, other := range []string{"decision mode", "MCP dynamic-policy plane", "FinCrime Engine B scorer"} {
				if strings.Contains(err.Error(), other) {
					t.Fatalf("an identity-compat variable was refused with another family's reason (%q): %v", other, err)
				}
			}
		})
	}
}

func TestAnEmptyIdentityCompatVariableBoots(t *testing.T) {
	clearAll(t)
	// Every pre-v11 compose file passed the mode through empty.
	for _, blank := range []string{"", " ", "\t"} {
		t.Setenv("AXONFLOW_IDENTITY_COMPAT_MODE", blank)
		if err := Refuse(); err != nil {
			t.Fatalf("AXONFLOW_IDENTITY_COMPAT_MODE=%q refused boot: %v", blank, err)
		}
	}
}

func TestEveryRetiredHITLGrantVariableRefusesBootByName(t *testing.T) {
	for _, name := range HITLGrant {
		t.Run(name, func(t *testing.T) {
			clearAll(t)
			// "900" is a value the agent accepted until #4254: a set variable is
			// refused whatever it says, a well-formed one included.
			t.Setenv(name, "900")
			err := Refuse()
			if err == nil {
				t.Fatalf("%s=900 booted; a set retired variable must refuse, not be ignored", name)
			}
			for _, want := range []string{name + `="900"`, PRD, "§1.13", "single-use approval grant"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
			for _, other := range []string{"decision mode", "MCP dynamic-policy plane", "FinCrime Engine B scorer", "identity-compat mode"} {
				if strings.Contains(err.Error(), other) {
					t.Fatalf("a HITL grant variable was refused with another family's reason (%q): %v", other, err)
				}
			}
		})
	}
}

func TestAnEmptyHITLGrantVariableBoots(t *testing.T) {
	clearAll(t)
	for _, blank := range []string{"", " ", "\t"} {
		t.Setenv("AXONFLOW_HITL_GRANT_TTL_SECONDS", blank)
		if err := Refuse(); err != nil {
			t.Fatalf("AXONFLOW_HITL_GRANT_TTL_SECONDS=%q refused boot: %v", blank, err)
		}
	}
}

func TestEveryRetiredFamilyIsNamedTogether(t *testing.T) {
	clearAll(t)
	t.Setenv("AXONFLOW_DECISION_SHADOW_MODE", "shadow")
	t.Setenv("MCP_DYNAMIC_POLICIES_GRACEFUL", "true")
	t.Setenv("AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS", "100")
	t.Setenv("AXONFLOW_IDENTITY_COMPAT_MODE", "off")
	t.Setenv("AXONFLOW_HITL_GRANT_TTL_SECONDS", "900")
	err := Refuse()
	if err == nil {
		t.Fatal("a variable from each retired family is set and boot was not refused")
	}
	for _, want := range []string{
		`AXONFLOW_DECISION_SHADOW_MODE="shadow"`, `MCP_DYNAMIC_POLICIES_GRACEFUL="true"`, `AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS="100"`,
		`AXONFLOW_IDENTITY_COMPAT_MODE="off"`, `AXONFLOW_HITL_GRANT_TTL_SECONDS="900"`,
		"decision mode", "MCP dynamic-policy plane", "FinCrime Engine B scorer", "identity-compat mode",
		"single-use approval grant",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %q: %v", want, err)
		}
	}
}
