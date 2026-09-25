// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"

	"axonflow/platform/agent/fincrime"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE ENGINE B RISK SCORE IS A FACT, NEVER A VERDICT (#3330, PRD v11 §1.2
// ruling R2, PRD_V11_POLICY_DECISION_PLANE.md:126).
//
// An external fraud model scores the transaction a request declares
// (`fincrime_transaction`, ee/docs/fincrime/CONTEXT_SCHEMA.md), and its number
// reaches the anchored engine as the attribute `signal.scorer.fincrime__fraud`.
// The FinCrime pack's score control (policypack.ScoreThreshold) is the typed
// constraint that reads it: at or above the pack's threshold the request is
// HELD for a person; below it nothing happens. The scorer's own threshold and
// its above_threshold flag are ignored - a threshold is the policy's.
//
// # WHERE IT IS ASKED
//
// Only where a control reads the answer (anchoredenforcer.AdmittedFactsInput.
// Reads): the pack binds on decide and mcp:request, the two scopes whose request
// pass carries the pack's documented objects, and an organization without the
// pack sends nothing out and waits for nothing. And only once the identity
// plane has ADMITTED the caller: the scorer's identity input is the admitted
// principal (anchoredenforcer.Call.AdmittedFacts).
//
// # A MISSING SCORE IS ABSENT, AND WHY IT IS MISSING IS RECORDED
//
// Every outcome that yields no score states the fact ABSENT, which the pack's
// control reads as no match (on_absent no_match over an optional attribute):
// a scorer that is down, slow, misconfigured or unconfigured never refuses a
// request, because a probabilistic control must not be able to take the
// gateway down (pdp combine.go Step 4). The engine's trace cannot say why a
// score is absent, so the reason is recorded beside the decision on four
// channels: the decision's audit record (`fincrime_risk_score.status`), a
// counter by outcome, a log line, and /health. A failure is never stated as
// a number.

// riskScoreSignal is the scorer output the FinCrime pack's control reads.
const riskScoreSignal = "fincrime_fraud"

// riskScorePath is where that output arrives on the request.
var riskScorePath = policypack.ScorerSignalPath(riskScoreSignal)

// riskScoreAuditKey is the policy_details member a decision's score record is
// written under. Not `risk_score`: that name is the platform's own content risk
// floor (signal.risk_score) on the orchestrator, a different claim.
const riskScoreAuditKey = "fincrime_risk_score"

// The reason a decision has the score it has, one code per case, so an audit
// reader can answer "was this transaction scored, and if not, why" from the
// row alone.
const (
	// riskScoreScored: the scorer answered 200 with a valid score.
	riskScoreScored = "scored"
	// The four ways a configured scorer fails to answer - timeout,
	// auth_rejected, unavailable, malformed_response - are produced only by
	// the Enterprise client and are declared beside it
	// (risk_score_fact_enterprise.go).
	//
	// riskScoreUnconfigured: this deployment configures no scorer.
	riskScoreUnconfigured = "unconfigured"
	// riskScoreNoTransaction: the request declares no fincrime_transaction, so
	// there is nothing to score and the scorer is not called.
	riskScoreNoTransaction = "no_transaction"
)

// riskScoreRecord is what a decision records about its score.
type riskScoreRecord struct {
	// Status is one of the riskScore* codes above.
	Status string `json:"status"`
	// Signal is the attribute path the score was stated at.
	Signal string `json:"signal"`
	// Score is the stated score; nil whenever the fact was ABSENT.
	Score           *float64           `json:"score,omitempty"`
	ModelID         string             `json:"model_id,omitempty"`
	ModelVersion    string             `json:"model_version,omitempty"`
	FeatureCoverage *float64           `json:"feature_coverage,omitempty"`
	TopFeatures     []riskScoreFeature `json:"top_features,omitempty"`
	// Controls are the controls that read the score on this decision, with the
	// threshold each compares it against.
	Controls []riskScoreControl `json:"controls,omitempty"`
}

// riskScoreFeature is one feature the scorer says contributed to the score.
type riskScoreFeature struct {
	Feature      string  `json:"feature"`
	Value        string  `json:"value"`
	Contribution float64 `json:"contribution"`
	Direction    string  `json:"direction"`
}

// riskScoreControl is one control that read the score.
type riskScoreControl struct {
	ID        string   `json:"id"`
	Threshold *float64 `json:"threshold,omitempty"`
}

// riskScoreRequest is what the scorer is asked about one decision.
type riskScoreRequest struct {
	decisionID  string
	plane       string
	principal   string
	subjectType string
	transaction interface{}
	cohort      interface{}
}

// riskScoreResult is the scorer's answer: a status, and the score only when
// the status is riskScoreScored.
type riskScoreResult struct {
	status          string
	score           float64
	modelID         string
	modelVersion    string
	featureCoverage *float64
	topFeatures     []riskScoreFeature
}

// riskScorer asks the configured scorer. A nil riskScorer is a deployment that
// configures none. Only the Enterprise build carries one
// (risk_score_fact_enterprise.go); the Community build's is always nil.
type riskScorer interface {
	score(ctx context.Context, req riskScoreRequest) riskScoreResult
}

// riskScorePlane is the scorer contract's name for the scope a request pass
// runs on (the scorer's `plane`: decide or mcp).
func riskScorePlane(scopePlane string) string {
	if scopePlane == "decide" {
		return "decide"
	}
	return "mcp"
}

// riskScoreFacts builds the call's AdmittedFacts for one request pass. It
// states the score fact, and writes what it did to rec, which the pass carries
// to its audit record. It states nothing, and records nothing, where no control
// on this activation reads the score.
func riskScoreFacts(scorer riskScorer, in requestPassInput, plane string, rec *riskScoreRecord) func(context.Context, anchoredenforcer.AdmittedFactsInput) contract.AttributeSet {
	return func(ctx context.Context, admitted anchoredenforcer.AdmittedFactsInput) contract.AttributeSet {
		if admitted.Reads == nil || !admitted.Reads(riskScorePath) {
			return nil
		}
		*rec = riskScoreRecord{Signal: riskScorePath, Controls: riskScoreControls(admitted)}
		absent := contract.AttributeSet{riskScorePath: contract.Absent(contract.ProvDetector, 1, admitted.Now)}
		transaction, declared := in.finCrime[fincrime.TransactionContextKey]
		switch {
		case scorer == nil:
			rec.Status = riskScoreUnconfigured
			return absent
		case !declared || transaction == nil:
			rec.Status = riskScoreNoTransaction
			return absent
		}
		result := scorer.score(ctx, riskScoreRequest{
			decisionID: in.decisionID, plane: plane,
			principal: admitted.Principal, subjectType: admitted.SubjectType,
			transaction: transaction, cohort: in.finCrime[fincrime.CohortContextKey],
		})
		rec.Status = result.status
		if result.status != riskScoreScored {
			return absent
		}
		score := result.score
		rec.Score, rec.ModelID, rec.ModelVersion = &score, result.modelID, result.modelVersion
		rec.FeatureCoverage, rec.TopFeatures = result.featureCoverage, result.topFeatures
		return contract.AttributeSet{riskScorePath: contract.Known(score, contract.ProvDetector, 1, admitted.Now)}
	}
}

// riskScoreControls names each control that reads the score, with the
// threshold it compares against when it is a plain comparison.
func riskScoreControls(in anchoredenforcer.AdmittedFactsInput) []riskScoreControl {
	if in.Act == nil {
		return nil
	}
	var out []riskScoreControl
	for _, p := range in.Act.PoliciesReading(riskScorePath) {
		c := riskScoreControl{ID: p.ID}
		if p.Where.Kind == pdp.CondCompare && p.Where.Path == riskScorePath {
			if n, ok := numericLiteral(p.Where.Literal); ok {
				c.Threshold = &n
			}
		}
		out = append(out, c)
	}
	return out
}

// numericLiteral reads a comparison's literal as a number. A control compiled
// in process carries a float64; one an organization PUBLISHED carries a
// json.Number, because documents are decoded with UseNumber
// (authoring/decode_strict.go) - and a published control under the pack's id is
// how an organization moves the threshold, so it must be read as well.
func numericLiteral(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// auditDetail is the record as a decision's audit row carries it, or nil for a
// decision on which no control read the score.
func (r riskScoreRecord) auditDetail() *riskScoreRecord {
	if r.Status == "" {
		return nil
	}
	return &r
}

// The configuration of the Engine B risk-score fact (#3330). New names rather
// than the v10 AXONFLOW_FINCRIME_SCORER_* pair, which stays retired
// (retiredenv.FinCrimeScorer): under v10 the scorer's own threshold decided,
// and a v10 environment booting into fact-producer semantics would change what
// its configuration means without saying so. Enterprise only; the Community
// build refuses to boot with either set (risk_score_fact_community.go).
const (
	envRiskFactURL       = "AXONFLOW_FINCRIME_RISK_FACT_URL"
	envRiskFactTimeoutMS = "AXONFLOW_FINCRIME_RISK_FACT_TIMEOUT_MS"
)
