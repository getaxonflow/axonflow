// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/anchoredenforcer"
)

// TestAdmittedFactsAreNotAskedForAnUnadmittedSubject holds the enforcer's
// order (#3330): Call.AdmittedFacts runs only after the identity plane admitted
// the subject, and is handed that ADMITTED principal. A subject the plane
// cannot admit fails the request closed with the hook never called, so nothing
// about such a caller leaves the process for an external scorer.
func TestAdmittedFactsAreNotAskedForAnUnadmittedSubject(t *testing.T) {
	enfSetup(t)
	enforcer, _ := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	e := enforcer(t)
	action, ok := decideActionForStage(DecisionStageLLM)
	if !ok {
		t.Fatal("PREMISE: the llm stage names no action")
	}
	var asked []anchoredenforcer.AdmittedFactsInput
	hook := func(_ context.Context, in anchoredenforcer.AdmittedFactsInput) contract.AttributeSet {
		asked = append(asked, in)
		return nil
	}
	call := func(subject func(time.Time) (decisionSubject, bool)) anchoredVerdict {
		return e.evaluate(context.Background(), anchoredCall{
			scope: decideSeamScope, orgID: enfOrgImplicit, requestID: "admitted-facts", action: action,
			subject: subject, emptyContent: true, admittedFacts: hook,
		})
	}

	v := call(func(time.Time) (decisionSubject, bool) { return decisionSubject{}, false })
	if v.unavailable == "" || v.decision != nil {
		t.Fatalf("an unverifiable subject was decided (unavailable %q)", v.unavailable)
	}
	if len(asked) != 0 {
		t.Fatalf("the hook was asked %d time(s) for a subject the identity plane did not admit", len(asked))
	}

	// POSITIVE CONTROL: the same call with a credential the plane admits asks
	// the hook once, with the principal it admitted.
	auth := &AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgImplicit, TenantID: enfOrgImplicit, ClientID: "admitted-facts-client"}
	v = call(requestSubject(enfOrgImplicit, auth, nil, userAbsent))
	if v.decision == nil || len(asked) != 1 {
		t.Fatalf("an admitted subject: decision %v, hook asked %d time(s); want a decision and one ask", v.decision, len(asked))
	}
	if asked[0].Principal != v.principal || !strings.HasPrefix(asked[0].Principal, "Client::") || asked[0].SubjectType != v.subjectType ||
		asked[0].Reads == nil || asked[0].Act == nil {
		t.Fatalf("asked with %+v; want the admitted principal %q, its type %q, and the activation", asked[0], v.principal, v.subjectType)
	}
}
