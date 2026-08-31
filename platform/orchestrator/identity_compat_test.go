// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// The orchestrator's half of the ADR-065 compat adapters (#3550).
//
// This plane had NO test coverage at all in the first two revisions, and it is
// the plane whose behaviour changed most: it went from clearing the actor on a
// refusal to recording and doing nothing. The runtime suite cannot cover it -
// it collects only the agent container's log - so the properties are pinned
// here.

// recordingCompatRecorder captures what the orchestrator's call site produced.
type recordingCompatRecorder struct {
	records []sharedidentity.Counterfactual
}

func (r *recordingCompatRecorder) RecordCounterfactual(_ context.Context, rec sharedidentity.Counterfactual) {
	r.records = append(r.records, rec)
}

// installOrchestratorCompat wires a process adapter for the duration of a test.
func installOrchestratorCompat(t *testing.T, mode sharedidentity.CompatMode) *recordingCompatRecorder {
	t.Helper()
	prior := sharedidentity.ProcessCompatAdapter()
	t.Cleanup(func() { sharedidentity.SetProcessCompatAdapter(prior) })

	registry := sharedidentity.NewRealmRegistry()
	source, err := sharedidentity.NewBuiltinRealmSource(registry, sharedidentity.BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	rec := &recordingCompatRecorder{}
	adapter, err := sharedidentity.NewCompatAdapter(mode, registry, source, rec,
		sharedidentity.WithCompatComponent("orchestrator"))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}
	sharedidentity.SetProcessCompatAdapter(adapter)
	return rec
}

func compatRequest(email, userID, orgID string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/process", nil)
	if userID != "" {
		r.Header.Set("X-User-ID", userID)
	}
	if orgID != "" {
		r.Header.Set("X-Org-ID", orgID)
	}
	_ = email
	return r
}

// TestObserveCompatPrincipalNeverActs is the property the fix commit changed
// this plane to have, and it is the one a later edit is most likely to undo.
//
// Clearing the actor looks like the fail-closed answer and is not: a shipped
// default declares {user.role equals "evaluation"} -> modify_risk, and
// db_dynamic_policies resolves user.role from req.User.Role, so clearing it
// stops the risk modifier applying and the request is scored LOWER. An empty
// actor is fail-closed for allowlist-shaped conditions and fail-OPEN for the
// deny-on-role shape, and both ship.
func TestObserveCompatPrincipalNeverActs(t *testing.T) {
	for _, mode := range []sharedidentity.CompatMode{
		sharedidentity.CompatModeShadow, sharedidentity.CompatModeEnforce,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			installOrchestratorCompat(t, mode)

			// An email-only assertion, which the identity plane REFUSES
			// (SUBJECT_MISSING: an alias is never an identifier).
			u := &UserContext{Email: "dev@corp.example", Role: "evaluation"}
			observeCompatPrincipal(compatRequest("", "", "acme-org"), u, "acme-org")

			if u.Email != "dev@corp.example" {
				t.Fatalf("the actor's email was cleared; on this plane that is a widening for every equals-shaped condition")
			}
			if u.Role != "evaluation" {
				t.Fatalf("the actor's ROLE was cleared. It arrives on X-Axonflow-User-Role, which is set only from a validated per-user token, so a refusal about the trusted-header credential destroyed an identity fact established by a stronger one")
			}
		})
	}
}

// TestObserveCompatPrincipalRecordsWhatThisPlaneActedOn: not acting is only
// acceptable because the counterfactual is still recorded. If it were not,
// this plane would simply be unadapted.
func TestObserveCompatPrincipalRecordsWhatThisPlaneActedOn(t *testing.T) {
	rec := installOrchestratorCompat(t, sharedidentity.CompatModeShadow)

	u := &UserContext{Email: "dev@corp.example"}
	observeCompatPrincipal(compatRequest("", "", "acme-org"), u, "acme-org")

	if len(rec.records) != 1 {
		t.Fatalf("the orchestrator plane recorded %d counterfactuals, want 1", len(rec.records))
	}
	got := rec.records[0]
	if got.Path != sharedidentity.LegacyPathTrustedHeader {
		t.Fatalf("path = %s, want trusted_header", got.Path)
	}
	if got.Component != "orchestrator" {
		t.Fatalf("component = %q; two processes log under one prefix, so a record that does not name its plane cannot be attributed to one", got.Component)
	}
	if got.IdentityReason != sharedidentity.ReasonSubjectMissing {
		t.Fatalf("reason = %s, want SUBJECT_MISSING for an email-only assertion", got.IdentityReason)
	}
	if got.Enforced {
		t.Fatalf("this plane recorded a refusal as ENFORCED, which it never applies")
	}
}

// TestObserveCompatPrincipalSkipsWithoutAnOrganization: the identity plane is
// organization-scoped by construction, so a request with no X-Org-ID is a
// question that cannot be asked. Recording it as an adapter DEFECT would fire
// once per governed request on any hop that does not stamp the header, and
// send an operator to fix a wiring bug that is not one.
func TestObserveCompatPrincipalSkipsWithoutAnOrganization(t *testing.T) {
	rec := installOrchestratorCompat(t, sharedidentity.CompatModeShadow)

	u := &UserContext{Email: "dev@corp.example"}
	observeCompatPrincipal(compatRequest("", "", ""), u, "")
	observeCompatPrincipal(compatRequest("", "", "  "), u, "  ")

	if len(rec.records) != 0 {
		t.Fatalf("an org-less request recorded %d counterfactuals: %+v", len(rec.records), rec.records)
	}
}

// TestObserveCompatPrincipalOffRecordsNothing is this plane's half of the
// flag-off guarantee. The runtime suite asserts it for the agent only.
func TestObserveCompatPrincipalOffRecordsNothing(t *testing.T) {
	rec := installOrchestratorCompat(t, sharedidentity.CompatModeOff)

	u := &UserContext{Email: "dev@corp.example", Role: "evaluation"}
	observeCompatPrincipal(compatRequest("", "", "acme-org"), u, "acme-org")

	if len(rec.records) != 0 {
		t.Fatalf("mode off recorded %d counterfactuals on the orchestrator plane", len(rec.records))
	}
	if u.Email == "" || u.Role == "" {
		t.Fatalf("mode off changed the actor")
	}
}

// TestObserveCompatPrincipalAdmitsAStableSubject is the control for
// TestObserveCompatPrincipalRecordsWhatThisPlaneActedOn: without it, a
// SUBJECT_MISSING assertion would also pass against an adapter that refuses
// everything.
func TestObserveCompatPrincipalAdmitsAStableSubject(t *testing.T) {
	rec := installOrchestratorCompat(t, sharedidentity.CompatModeShadow)

	u := &UserContext{Email: "dev@corp.example"}
	observeCompatPrincipal(compatRequest("", "u-42", "acme-org"), u, "acme-org")

	if len(rec.records) != 1 {
		t.Fatalf("recorded %d counterfactuals, want 1", len(rec.records))
	}
	if got := rec.records[0]; got.Divergence != sharedidentity.DivergenceNone {
		t.Fatalf("an upstream asserting a stable subject id diverged: %s (%s)", got.Divergence, got.IdentityReason)
	}
}
