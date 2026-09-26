// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"errors"
	"fmt"

	sharedpolicy "axonflow/platform/shared/policy"
)

// ScanScope is the organization a PII scan of extracted text runs under: the
// shared engine loads the organization's policy rows by it (RLS scope and the
// loader's org predicate), and a scan with no organization would read the
// wrong rule set. The request carries it to the analyzers on the context
// (WithScanScope), because the MediaAnalyzer interface takes only the content.
type ScanScope struct {
	OrgID    string
	TenantID string
	UserID   string
}

type scanScopeKey struct{}

// WithScanScope returns ctx carrying the organization a media analysis scans
// extracted text under.
func WithScanScope(ctx context.Context, scope ScanScope) context.Context {
	return context.WithValue(ctx, scanScopeKey{}, scope)
}

// ScanScopeFrom returns the scope WithScanScope put on ctx, and false when none
// is there or it names no organization.
func ScanScopeFrom(ctx context.Context) (ScanScope, bool) {
	scope, ok := ctx.Value(scanScopeKey{}).(ScanScope)
	if !ok || scope.OrgID == "" {
		return ScanScope{}, false
	}
	return scope, true
}

// PIIEngine is the part of the shared policy engine a text PII scan uses.
type PIIEngine interface {
	EvaluateRequest(ctx context.Context, input string, opts sharedpolicy.EvalOptions) *sharedpolicy.RequestResult
	EnabledPIICategories(ctx context.Context, tenantID string, orgID *string, phase sharedpolicy.Phase) []sharedpolicy.PolicyCategory
}

// ErrPIIScanNotRun reports that extracted text was NOT scanned. A caller must
// read it as "unknown", never as "no PII".
var ErrPIIScanNotRun = errors.New("media: extracted text was not scanned for PII")

// globalPIIEngine resolves the engine a scan runs on at scan time rather than
// when the analyzer is built, so an engine installed, replaced or absent is read
// as it is when the text is scanned. Tests replace it.
var globalPIIEngine = func() PIIEngine {
	if e := sharedpolicy.GetGlobalEngine(); e != nil {
		return e
	}
	return nil
}

// NewEnginePIIDetector returns the PIIDetectorFunc that scans extracted text
// with the platform's own PII detectors (#4300): the shared engine's
// request-phase evaluation restricted to the text PII categories
// (sharedpolicy.AllTextPIICategories), so the detector SET is the policy
// rows' - the eighteen sys_pii_* rows and any organization row in those
// categories - and no pattern or validator is copied here.
//
// It produces a media signal; it is not a decision call site. The engine's own
// verdict (Blocked, BlockedBy) is ignored: whether a request carrying PII in an
// image proceeds is the anchored decision's, over signal.media.has_pii
// (sys_media_pii_block). Each match becomes a PIIFinding typed by its policy id.
//
// The scan does not run - ErrPIIScanNotRun, which the analyzer records as "not
// scanned" - when ctx carries no organization, when no engine is installed, when
// the organization has no enabled text PII category (the response seam reads
// that as no facts too, response_enforcing_seam.go responseDetectorPass), when
// the engine could not load the policies (EvaluationError), or when no detector
// reports that it ran. None of those may read as "scanned, found nothing": a
// scan with an empty detector set would state has_pii false that no detector
// measured.
//
// analyzerName marks the evaluation's ConnectorName as "media:<analyzer>", the
// field a recorded violation carries (sharedpolicy MetricsCollector) so a
// violation from image text names its source.
func NewEnginePIIDetector(engine func() PIIEngine, analyzerName string) PIIDetectorFunc {
	return func(ctx context.Context, text string) ([]PIIFinding, error) {
		scope, ok := ScanScopeFrom(ctx)
		if !ok {
			return nil, fmt.Errorf("%w: no organization scope on the analysis", ErrPIIScanNotRun)
		}
		var e PIIEngine
		if engine != nil {
			e = engine()
		}
		if e == nil {
			return nil, fmt.Errorf("%w: no policy engine is installed", ErrPIIScanNotRun)
		}
		orgScope := scope.OrgID
		if len(e.EnabledPIICategories(ctx, scope.TenantID, &orgScope, sharedpolicy.PhaseRequest)) == 0 {
			return nil, fmt.Errorf("%w: the organization has no enabled text PII detector", ErrPIIScanNotRun)
		}
		res := e.EvaluateRequest(ctx, text, sharedpolicy.EvalOptions{
			TenantID:      scope.TenantID,
			OrgID:         scope.OrgID,
			OrgScope:      &orgScope,
			UserID:        scope.UserID,
			ConnectorName: "media:" + analyzerName,
			Categories:    sharedpolicy.AllTextPIICategories(),
		})
		if res == nil {
			return nil, fmt.Errorf("%w: the policy engine returned no result", ErrPIIScanNotRun)
		}
		if res.EvaluationError {
			return nil, fmt.Errorf("%w: the policy engine could not load the PII policies", ErrPIIScanNotRun)
		}
		// Only the text PII categories pass the engine's filter and no tool
		// identity is given, so any detector reported as run is a PII detector.
		ran := false
		if res.Observation != nil {
			for _, row := range res.Observation.Rows {
				if row.Ran {
					ran = true
					break
				}
			}
		}
		if !ran {
			return nil, fmt.Errorf("%w: no PII detector ran on the text", ErrPIIScanNotRun)
		}
		findings := make([]PIIFinding, 0, len(res.MatchedPolicies))
		for _, m := range res.MatchedPolicies {
			if !sharedpolicy.IsPIIPolicyCategory(m.Category) {
				continue
			}
			findings = append(findings, PIIFinding{
				Type:       m.PolicyID,
				Value:      m.MatchText,
				Redacted:   "[redacted]",
				Confidence: m.Confidence,
				StartIndex: m.StartIndex,
				EndIndex:   m.EndIndex,
			})
		}
		return findings, nil
	}
}
