// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/agent"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// THE ORCHESTRATOR RESPONSE PASS, DECIDED BY THE ANCHORED ENGINE.
//
// Each test drives decideResponse (or ProcessResponse over it) with a real shared
// enforcer, a real shared engine loading every shipped global row a migrated
// database carries, and the request's subject built from the headers the agent
// forwards. What is asserted is what the pass RECORDS and RELEASES - the verdict,
// the engine, the subject type, the bundle, the content and the counter - never a
// helper's return in isolation.

const (
	respOrg    = "org-response-plane"
	respClient = "client-response-plane"
	// respSSN is a structurally valid SSN (area, group and serial all admitted by
	// the validator), so the shipped sys_pii_ssn detector's match survives it.
	respSSN = "536-22-4811"
)

// respDocuments serves no active document for every organization - the
// implicit bundle decides - except one whose tables cannot be read.
type respDocuments struct{ broken bool }

func (d respDocuments) ActiveTip(context.Context, string) (string, int64, error) {
	if d.broken {
		return "", 0, errors.New("the typed-authoring tables are unreachable")
	}
	return "", 0, nil
}

func (respDocuments) Load(context.Context, string, string) (*authoring.Artifact, *pdp.TrustStore, error) {
	return nil, nil, errors.New("no document is active, so none is loaded")
}

// respShippedRow is one enabled row of the 'global' scope a migrated database
// carries, as the shared engine's loader reads it.
type respShippedRow struct {
	tier, policyID, category, severity, requestAction, responseAction string
}

// respShippedRows is every enabled system row the census carries and the
// organization template's tenant-tier rows, with the request action decide's
// restriction binds and the response action this scope's restriction binds -
// the rows a migrated database stores, read from the corpus rather than restated.
func respShippedRows(t *testing.T) []respShippedRow {
	t.Helper()
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	templatePaths := map[string]bool{}
	for _, p := range template.Policies {
		for _, path := range p.ReferencedPaths() {
			templatePaths[path] = true
		}
	}
	requestActions := respPhaseActions(t, legacycompile.MustScopeFor(legacycompile.PlaneDecide, ""))
	responseActions := respPhaseActions(t, orchestratorResponseScope)
	var out []respShippedRow
	for _, r := range census {
		isTemplate := r.Tier != "system" && templatePaths[registry.DetectorID(r.PolicyID).SignalPath()]
		if (r.Tier != "system" && !isTemplate) || !r.Enabled {
			continue
		}
		action := r.LegacyAction
		if requested, split := requestActions[r.PolicyID]; split {
			action = requested
		}
		if action == "" {
			action = "warn"
		}
		severity := r.Severity
		if severity == "" {
			severity = "medium"
		}
		out = append(out, respShippedRow{
			tier: r.Tier, policyID: r.PolicyID, category: r.Category, severity: severity,
			requestAction: action, responseAction: responseActions[r.PolicyID],
		})
	}
	if len(out) == 0 {
		t.Fatal("the census carries no enabled row, so the fixture serves nothing")
	}
	return out
}

// respPhaseActions is the action each row the corpus split by scope is bound to
// on scope, read from its restriction.
func respPhaseActions(t *testing.T, scope legacycompile.EnforcementScope) map[string]string {
	t.Helper()
	doc, _, err := activation.RestrictToScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]string{}
	for _, r := range rows {
		byPath[registry.DetectorID(r.PolicyID).SignalPath()] = r.PolicyID
	}
	out := map[string]string{}
	for _, p := range doc.Policies {
		for _, path := range p.ReferencedPaths() {
			if policyID, ok := byPath[path]; ok {
				if _, action, _ := legacycompile.CorpusControlOf(p.ID); action != "" {
					out[policyID] = action
				}
				break
			}
		}
	}
	return out
}

// installResponseDetectors installs the shared engine over every shipped row,
// each never matching except a row in probes, which matches its probe text;
// storedResponse replaces a row's stored response action, to plant a legacy
// verdict the anchored engine must ignore.
func installResponseDetectors(t *testing.T, probes, storedResponse map[string]string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	shipped := respShippedRows(t)
	for i := 0; i < 64; i++ {
		rows := sqlmock.NewRows(policytest.LoaderCols())
		for n, r := range shipped {
			pattern := "ZZ_NEVER_MATCHES_" + r.policyID
			if probe, ok := probes[r.policyID]; ok {
				pattern = regexp.QuoteMeta(probe)
			}
			response := r.responseAction
			if planted, ok := storedResponse[r.policyID]; ok {
				response = planted
			}
			var stored interface{}
			if response != "" {
				stored = response
			}
			rows = rows.AddRow(policytest.GlobalPolicyValues(r.tier, fmt.Sprintf("00000000-0000-0000-0000-%012d", n+1),
				r.policyID, r.category, pattern, r.severity, "both", r.requestAction, stored, 100)...)
		}
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 64)
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{CacheTTL: time.Hour}, nil)
	prev := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prev); engine.Stop() })
}

// installResponseEnforcer installs a real shared enforcer over docs and a
// recorded-override store serving overrides (nil records none), restored at
// cleanup.
func installResponseEnforcer(t *testing.T, docs anchoredenforcer.ActiveDocumentSource, overrides func(context.Context, string) (map[string]agent.DetectionAction, error)) {
	t.Helper()
	isolateOrchestratorEnforcer(t)
	if overrides == nil {
		overrides = noOverrides
	}
	setDetectionOverrideCacheForTest(testOverrideCache(overrides))
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil || snap == nil {
		t.Fatalf("resolving the deployment vocabulary: %v", err)
	}
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := anchoredenforcer.New(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch,
		anchoredenforcer.Options{Overrides: orchestratorRecordedOverrides, Delivers: orchestratorSeamDelivers, EditionBoundary: orchestratorEditionBoundary})
	if err != nil {
		t.Fatal(err)
	}
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: e})
}

// respHeaders are the credential headers the agent's forward stamps.
func respHeaders() http.Header {
	h := http.Header{}
	h.Set("X-Org-ID", respOrg)
	h.Set("X-Client-ID", respClient)
	return h
}

func respContext(h http.Header) context.Context {
	return withResponsePlaneSeam(context.Background(), "req-response-plane", headerCredentialSubject(h))
}

var respUser = UserContext{ID: 7, OrgID: respOrg, TenantID: "tenant-response-plane"}

func respCounter(verdict, reason string) float64 {
	return testutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(orchestratorResponseScope.String(), anchoredenforcer.EngineAnchored, verdict, reason))
}

// TestTheOrchestratorResponseScopeActivatesOnBothEditions: the scope this binary
// registers is activated against the shipped corpus on both editions, with the
// delivery its seam declares, under the implicit bundle - so a restriction it
// cannot discharge reds here rather than withholding every response.
func TestTheOrchestratorResponseScopeActivatesOnBothEditions(t *testing.T) {
	registered := false
	for _, s := range orchestratorEnforcingScopes {
		registered = registered || s == orchestratorResponseScope
	}
	if !registered {
		t.Fatalf("%s is not in orchestratorEnforcingScopes, so /health does not report it and activation is not told its delivery", orchestratorResponseScope)
	}
	for _, mode := range []string{"community", "enterprise"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
			if err != nil {
				t.Fatal(err)
			}
			_, sysPriv, _ := ed25519.GenerateKey(nil)
			system, err := authoring.NewSystemAuthority(sysPriv)
			if err != nil {
				t.Fatal(err)
			}
			_, compPriv, _ := ed25519.GenerateKey(nil)
			composition, err := authoring.NewCompositionAuthority(compPriv)
			if err != nil {
				t.Fatal(err)
			}
			restricted, _, err := activation.RestrictToScope(orchestratorResponseScope)
			if err != nil || restricted == nil || len(restricted.Policies) == 0 {
				t.Fatalf("PREMISE: no shipped control binds on %s (%v), so its activation proves nothing", orchestratorResponseScope, err)
			}
			act, err := activation.Activate(context.Background(), activation.Inputs{
				Snapshot: snap, Trust: pdp.NewTrustStore(), System: system, Composition: composition,
				Plane: string(orchestratorResponseScope.Plane), Phase: orchestratorResponseScope.Phase,
				Delivers: orchestratorSeamDelivers(orchestratorResponseScope), OrganizationID: respOrg,
			})
			if err != nil {
				t.Fatalf("%s did not activate on the %s edition (%d shipped controls bind there): %v", orchestratorResponseScope, mode, len(restricted.Policies), err)
			}
			if act.Scope != orchestratorResponseScope {
				t.Fatalf("activating %s built an engine for %s", orchestratorResponseScope, act.Scope)
			}
		})
	}
}

// TestACleanResponseIsAllowedByTheAnchoredEngine: a response no detector matches
// is released as sent, recorded allowed under the anchored engine for the client
// credential, with the bundle that decided it, and counted once under the plane.
func TestACleanResponseIsAllowedByTheAnchoredEngine(t *testing.T) {
	installResponseDetectors(t, nil, nil)
	installResponseEnforcer(t, respDocuments{}, nil)
	before := respCounter(agent.VerdictAllow, "permitted")

	content := "The quarterly report shows steady growth."
	got, info := decideResponse(respContext(respHeaders()), respUser, content)

	if info.Verdict != responseVerdictAllowed || got != content {
		t.Fatalf("a clean response: verdict %q content %v (%s), want allowed and the content as sent", info.Verdict, got, info.ValidationError)
	}
	if info.Engine != anchoredenforcer.EngineAnchored || info.SubjectType != string(sharedidentity.SubjectClient) || info.PolicyBundle == "" {
		t.Fatalf("the record names engine %q subject %q bundle %q; want anchored, Client and a bundle", info.Engine, info.SubjectType, info.PolicyBundle)
	}
	if after := respCounter(agent.VerdictAllow, "permitted"); after != before+1 {
		t.Fatalf("the allow was counted %v times under plane=%s, want once", after-before, orchestratorResponseScope)
	}
}

// TestAResponseCarryingAnSSNIsReleasedMasked: the shipped sys_pii_ssn control
// redacts on this scope, so the permit composes a field_redact the pass
// discharges by masking - the response is released, recorded redacted, and the
// SSN is not in what is released.
func TestAResponseCarryingAnSSNIsReleasedMasked(t *testing.T) {
	installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
	installResponseEnforcer(t, respDocuments{}, nil)

	got, info := decideResponse(respContext(respHeaders()), respUser, "Customer SSN is "+respSSN+".")

	released := fmt.Sprint(got)
	if info.Verdict != responseVerdictRedacted || strings.Contains(released, respSSN) {
		t.Fatalf("an SSN response: verdict %q (%s) released %q; want redacted with the SSN masked", info.Verdict, info.ValidationError, released)
	}
	if !info.HasRedactions || len(info.RedactedFields) == 0 || info.Engine != anchoredenforcer.EngineAnchored {
		t.Fatalf("the record says redactions %v fields %v engine %q; want the masking recorded under the anchored engine", info.HasRedactions, info.RedactedFields, info.Engine)
	}
}

// TestAPlantedSharedEngineVerdictChangesNothing: the shared engine is told the
// SSN row's stored response action is block, which its verdict would enforce.
// The anchored engine decides from the corpus and the organization's record,
// not the stored column, so the response is masked and released, never blocked.
func TestAPlantedSharedEngineVerdictChangesNothing(t *testing.T) {
	installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, map[string]string{"sys_pii_ssn": "block"})
	installResponseEnforcer(t, respDocuments{}, nil)

	got, info := decideResponse(respContext(respHeaders()), respUser, "Customer SSN is "+respSSN+".")

	if info.Verdict != responseVerdictRedacted || strings.Contains(fmt.Sprint(got), respSSN) {
		t.Fatalf("with a planted legacy block the response is %q (%s); the anchored engine's redaction must decide", info.Verdict, info.ValidationError)
	}
}

// TestARecordedPIIBlockWithholdsTheResponseNamingTheConstraint: an organization's
// recorded pii=block override replaces the shipped control in its root, so the
// response is withheld, recorded blocked, naming the replacement constraint, and
// counted as a deny.
func TestARecordedPIIBlockWithholdsTheResponseNamingTheConstraint(t *testing.T) {
	installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
	installResponseEnforcer(t, respDocuments{}, func(context.Context, string) (map[string]agent.DetectionAction, error) {
		return map[string]agent.DetectionAction{agent.DetectionCategoryPII: agent.DetectionAction("block")}, nil
	})

	_, info := decideResponse(respContext(respHeaders()), respUser, "Customer SSN is "+respSSN+".")

	if info.Verdict != responseVerdictBlocked {
		t.Fatalf("under a recorded pii=block the response is %q (%s), want blocked", info.Verdict, info.ValidationError)
	}
	if !strings.HasPrefix(info.BlockingPolicyID, activation.OverridePolicyIDPrefix) || !strings.Contains(info.BlockingPolicyID, "sys__pii__ssn") {
		t.Fatalf("the refusal names %q as blocking; want the organization's override of the shipped SSN control", info.BlockingPolicyID)
	}
	if info.Engine != anchoredenforcer.EngineAnchored || info.DecisionReason == "" {
		t.Fatalf("the refusal records engine %q reason %q; want the anchored engine and its reason", info.Engine, info.DecisionReason)
	}
}

// TestTheResponsePassFailsClosedNamingEachCause: every way the pass cannot
// decide withholds the response, records the cause it names, and counts it as
// unavailable under the plane. None releases the content.
func TestTheResponsePassFailsClosedNamingEachCause(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T) context.Context
		cause string
	}{
		{"no enforcer wired", func(t *testing.T) context.Context {
			installResponseDetectors(t, nil, nil)
			isolateOrchestratorEnforcer(t)
			orchestratorEnforcerInstance.Store(nil)
			return respContext(respHeaders())
		}, anchoredenforcer.CauseNotWired},
		{"no subject installed", func(t *testing.T) context.Context {
			installResponseDetectors(t, nil, nil)
			installResponseEnforcer(t, respDocuments{}, nil)
			return context.Background()
		}, anchoredenforcer.CauseSubjectUnverifiable},
		{"a forwarded request with no client header", func(t *testing.T) context.Context {
			installResponseDetectors(t, nil, nil)
			installResponseEnforcer(t, respDocuments{}, nil)
			h := respHeaders()
			h.Del("X-Client-ID")
			return respContext(h)
		}, anchoredenforcer.CauseSubjectUnverifiable},
		{"an active document that cannot be read", func(t *testing.T) context.Context {
			installResponseDetectors(t, nil, nil)
			installResponseEnforcer(t, respDocuments{broken: true}, nil)
			return respContext(respHeaders())
		}, anchoredenforcer.CauseActiveDocument},
		{"recorded overrides that cannot be read", func(t *testing.T) context.Context {
			installResponseDetectors(t, nil, nil)
			installResponseEnforcer(t, respDocuments{}, func(context.Context, string) (map[string]agent.DetectionAction, error) {
				return nil, errors.New("detection_action_overrides is unreachable")
			})
			return respContext(respHeaders())
		}, anchoredenforcer.CauseOverrides},
		{"a redaction nothing can discharge", func(t *testing.T) context.Context {
			installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
			installResponseEnforcer(t, respDocuments{}, nil)
			prev := responseRedactor
			responseRedactor = func(context.Context, *sharedpolicy.UnifiedPolicyEngine, interface{}, sharedpolicy.EvalOptions, []string) (*sharedpolicy.ResponseResult, error) {
				return nil, errors.New("planted: the redactor cannot mask this content")
			}
			t.Cleanup(func() { responseRedactor = prev })
			return respContext(respHeaders())
		}, anchoredenforcer.CauseObligation},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := c.setup(t)
			before := respCounter("unavailable", c.cause)
			content := "Customer SSN is " + respSSN + "."
			got, info := decideResponse(ctx, respUser, content)
			if info.Verdict != responseVerdictBlocked || info.DecisionReason != c.cause {
				t.Fatalf("verdict %q reason %q (%s); want blocked naming %s", info.Verdict, info.DecisionReason, info.ValidationError, c.cause)
			}
			if !strings.Contains(info.ValidationError, anchoredenforcer.CauseMessages[c.cause]) {
				t.Fatalf("the withheld response says %q; want the cause's message %q", info.ValidationError, anchoredenforcer.CauseMessages[c.cause])
			}
			if after := respCounter("unavailable", c.cause); after != before+1 {
				t.Fatalf("the refusal was counted %v times as unavailable/%s, want once", after-before, c.cause)
			}
			if got != content {
				t.Fatalf("the pass returned %v; a withheld response is returned unchanged for the processor to replace, never masked or rewritten", got)
			}
		})
	}
}

// TestAnEmptyResponseIsDecidedNotWithheld: a response with no content gives the
// detectors nothing to scan, and a content detector over no content has a
// determined answer, so the empty response is decided - allowed - rather than
// withheld because nothing ran.
func TestAnEmptyResponseIsDecidedNotWithheld(t *testing.T) {
	installResponseDetectors(t, nil, nil)
	installResponseEnforcer(t, respDocuments{}, nil)

	_, info := decideResponse(respContext(respHeaders()), respUser, "")

	if info.Verdict != responseVerdictAllowed || info.Engine != anchoredenforcer.EngineAnchored {
		t.Fatalf("an empty response is %q (%s) under engine %q; want allowed by the anchored engine", info.Verdict, info.ValidationError, info.Engine)
	}
}

// TestProcessResponseAppliesTheDecisionThenValidation: through the processor, a
// masked response is enriched and recorded redacted; a withheld one is replaced
// by the error without running validation; and a response the engine released
// but a validation rule refuses is withheld keeping the engine's decision and
// saying the rule withheld it.
func TestProcessResponseAppliesTheDecisionThenValidation(t *testing.T) {
	t.Run("masked", func(t *testing.T) {
		installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
		installResponseEnforcer(t, respDocuments{}, nil)
		out, info := NewResponseProcessor().ProcessResponse(respContext(respHeaders()), respUser, &LLMResponse{Content: "Customer SSN is " + respSSN + "."})
		wrapped, ok := out.(map[string]interface{})
		if !ok || info.Verdict != responseVerdictRedacted || strings.Contains(fmt.Sprint(wrapped["data"]), respSSN) {
			t.Fatalf("processed %v (verdict %q); want the masked content enriched and recorded redacted", out, info.Verdict)
		}
	})
	t.Run("withheld", func(t *testing.T) {
		installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
		installResponseEnforcer(t, respDocuments{}, func(context.Context, string) (map[string]agent.DetectionAction, error) {
			return map[string]agent.DetectionAction{agent.DetectionCategoryPII: agent.DetectionAction("block")}, nil
		})
		out, info := NewResponseProcessor().ProcessResponse(respContext(respHeaders()), respUser, &LLMResponse{Content: "Customer SSN is " + respSSN + "."})
		body, ok := out.(map[string]string)
		if !ok || body["error"] != "Response blocked by policy" || info.Verdict != responseVerdictBlocked || info.WithheldByValidation {
			t.Fatalf("processed %v (verdict %q, by validation %v); want the policy error and a blocked record the engine authored", out, info.Verdict, info.WithheldByValidation)
		}
		if strings.Contains(fmt.Sprint(out), respSSN) {
			t.Fatal("the withheld response's replacement carries the SSN")
		}
	})
	t.Run("validation", func(t *testing.T) {
		installResponseDetectors(t, nil, nil)
		installResponseEnforcer(t, respDocuments{}, nil)
		out, info := NewResponseProcessor().ProcessResponse(respContext(respHeaders()), respUser, &LLMResponse{Content: "error: the upstream call failed"})
		body, ok := out.(map[string]string)
		if !ok || body["error"] != "Response validation failed" || info.Verdict != responseVerdictBlocked {
			t.Fatalf("processed %v (verdict %q); want the validation error and a blocked record", out, info.Verdict)
		}
		if !info.WithheldByValidation || info.DecisionReason != "permitted" || info.Engine != anchoredenforcer.EngineAnchored {
			t.Fatalf("the record says by-validation %v reason %q engine %q; want the engine's permit kept and the rule named as the withholder", info.WithheldByValidation, info.DecisionReason, info.Engine)
		}
	})
}
