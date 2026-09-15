// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

// TestTheBatchRefusalRendersWhatACallerNeeds asserts the STRINGS, which nothing
// else does.
//
// #3973 folded two facts into the refusal - the policy that crossed the ceiling
// and the size of the batch that was refused - because Decision.Message()
// renders the ledger count BEFORE the call and knows nothing about the
// submission, so a fresh organization sending 21 under a ceiling of 20 read
// "...and 0 are already admitted": true, and useless.
//
// Every existing test asserts the CODE or the decision. A refusal can carry the
// right code and still tell an operator nothing, and that is exactly what this
// change was for, so the rendered text is what gets pinned here.
func TestTheBatchRefusalRendersWhatACallerNeeds(t *testing.T) {
	restore := wireTestTierAdmitter(t, license.TierCommunity)
	defer restore()

	limit := license.GetTierLimits(license.TierCommunity).OrgPolicies
	if limit <= 0 {
		t.Fatalf("the Community ceiling reads %d; this test needs a positive ceiling to overflow", limit)
	}

	// One past the ceiling, from a FRESH organization, which is the shape that
	// produced the useless message: nothing is admitted yet, so the ledger count
	// is 0 and only the batch size carries any information.
	names := make([]string, 0, limit+1)
	for i := 1; i <= limit+1; i++ {
		names = append(names, fmt.Sprintf("p%03d", i))
	}
	overflow := names[len(names)-1]

	err := admitOrgRootPolicies(context.Background(), "org-render", names)
	if err == nil {
		t.Fatalf("a batch of %d was admitted under a ceiling of %d", len(names), limit)
	}

	var tierErr *TierValidationError
	if !errors.As(err, &tierErr) {
		t.Fatalf("the refusal is not a *TierValidationError: %v", err)
	}

	t.Run("it names the policy that crossed the boundary", func(t *testing.T) {
		if tierErr.Policy != overflow {
			t.Fatalf("Policy = %q, want %q - an author told only \"too many\" has a document to bisect", tierErr.Policy, overflow)
		}
		if !strings.Contains(tierErr.Message, overflow) {
			t.Fatalf("the message does not name the policy that crossed: %q", tierErr.Message)
		}
	})

	t.Run("it states the size of what was refused", func(t *testing.T) {
		if !strings.Contains(tierErr.Message, fmt.Sprintf("%d", len(names))) {
			t.Fatalf("the message does not state the batch size %d, so a caller cannot tell how much was refused: %q",
				len(names), tierErr.Message)
		}
	})

	t.Run("it says the refusal cost nothing", func(t *testing.T) {
		// The whole point of #3973: retrying with fewer policies is free. A
		// refusal that does not say so leaves an operator assuming they have
		// burned capacity, which is what the old behaviour actually did.
		if !strings.Contains(tierErr.Message, "nothing was admitted") {
			t.Fatalf("the message does not tell the caller the refusal spent nothing: %q", tierErr.Message)
		}
	})

	t.Run("it does not read as the outage refusal", func(t *testing.T) {
		// A ceiling refusal and an outage refusal on this dimension carry the
		// same status and the same code. Only the outage is worth repeating
		// unchanged, and only it says so (TestTheOutageRefusalSaysToRetry is
		// the other half), so a ceiling that invites a retry sends an author
		// back with the same document. The real-Postgres tests assert the same
		// thing on the route, in a job no pull request runs (#4160).
		if strings.Contains(strings.ToLower(tierErr.Message), "retry") {
			t.Fatalf("the ceiling refusal reads as retryable, which is the outage refusal on this dimension: %q",
				tierErr.Message)
		}
		if tierErr.RetryAfter != 0 {
			t.Fatalf("the ceiling refusal carries RetryAfter=%v, which only the outage refusal sets", tierErr.RetryAfter)
		}
	})

	t.Run("Error() carries the policy, replacing the per-row prefix the loop removed", func(t *testing.T) {
		// The legacy import used to prefix "policy %d: " from its loop index.
		// The loop is gone, so without this the LOGS lost the identity of the
		// offending policy entirely.
		got := tierErr.Error()
		if !strings.Contains(got, "[policy "+overflow+"]") {
			t.Fatalf("Error() = %q, want it to carry [policy %s]", got, overflow)
		}
		if !strings.Contains(got, tierErr.Code) {
			t.Fatalf("Error() = %q, want it to carry the code %q", got, tierErr.Code)
		}
	})
}

// TestErrorRendersThePolicyOnlyWhenThereIsOne is the negative half.
//
// An OUTAGE refusal names no policy - no particular one is at fault - and a
// renderer that always emitted the bracket would print an empty "[policy ]" on
// every dependency failure.
func TestErrorRendersThePolicyOnlyWhenThereIsOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   bool
	}{
		{"a ceiling refusal names the policy", "p021", true},
		{"an outage refusal names none", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewTierValidationError("refused", "ERR_TIER_LIMIT_ORG_ROOT_POLICY")
			e.Policy = tc.policy
			got := e.Error()
			if strings.Contains(got, "[policy ") != tc.want {
				t.Fatalf("Error() = %q; carrying a policy should be %v", got, tc.want)
			}
			if strings.Contains(got, "[policy ]") {
				t.Fatalf("Error() rendered an empty policy bracket: %q", got)
			}
		})
	}
}

// TestTheOutageRefusalSaysToRetry is the other half of the discriminator the
// ceiling assertions rely on, here and in typed_authoring_limit_realpg_test.go.
// "Reads as retryable" separates the two refusals only while the outage one
// actually says it, and both come through admitOrgRootPolicies with one code.
func TestTheOutageRefusalSaysToRetry(t *testing.T) {
	restore := installTestTierAdmitter(t, admission.New(unreachableLedger{},
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: license.TierCommunity}
		})))
	defer restore()

	err := admitOrgRootPolicies(context.Background(), "org-outage-render", []string{"p001"})
	var tierErr *TierValidationError
	if !errors.As(err, &tierErr) {
		t.Fatalf("an unreachable ledger did not refuse with a *TierValidationError: %v", err)
	}
	if tierErr.Code != admission.OrgRootPolicy.Code() {
		t.Fatalf("code = %q, want the ceiling's own %q: the two refusals share it, which is why the message must differ",
			tierErr.Code, admission.OrgRootPolicy.Code())
	}
	if !strings.Contains(strings.ToLower(tierErr.Message), "retry") {
		t.Fatalf("the outage refusal does not say to retry, so nothing in the message separates it from the ceiling: %q",
			tierErr.Message)
	}
	if tierErr.RetryAfter <= 0 {
		t.Fatalf("the outage refusal carries RetryAfter=%v; it is the one refusal a caller should repeat", tierErr.RetryAfter)
	}
	if tierErr.Policy != "" {
		t.Fatalf("the outage refusal names policy %q; no particular policy is at fault", tierErr.Policy)
	}
}

// unreachableLedger is an admission ledger whose database cannot be reached:
// every call fails the way a refused connection does.
type unreachableLedger struct{}

var errLedgerUnreachable = errors.New("simulated outage: connection refused")

func (unreachableLedger) Exists(context.Context, admission.Key) (bool, error) {
	return false, errLedgerUnreachable
}

func (unreachableLedger) AdmitUnderLimit(context.Context, admission.Key, int, string) (admission.Outcome, error) {
	return admission.Outcome{}, errLedgerUnreachable
}

func (unreachableLedger) AdmitAllUnderLimit(context.Context, []admission.Key, int, string) (admission.BatchOutcome, error) {
	return admission.BatchOutcome{}, errLedgerUnreachable
}

func (unreachableLedger) Recent(context.Context, string, int) ([]admission.Key, error) {
	return nil, errLedgerUnreachable
}

func (unreachableLedger) Record(context.Context, admission.Key, string) error {
	return errLedgerUnreachable
}
