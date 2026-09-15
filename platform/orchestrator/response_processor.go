// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/agent/indonesia"
	sharedaudit "axonflow/platform/shared/audit"
)

// ResponseProcessor applies the response plane to an LLM response: the anchored
// engine's decision (decideResponse), the Indonesia checksum validator, the
// response validation rules and the enrichment metadata.
type ResponseProcessor struct {
	enricher        *ResponseEnricher
	validationRules []ValidationRule
}

// Canonical response-plane verdicts (#2626). Now ALIASES onto the single shared
// vocabulary in platform/shared/audit (#2638 S-WRITERS const-swap) — the same
// audit_logs.policy_decision set every plane converges on (enforced by the
// migration-123 CHECK), so the portal decisions/audit feed and the lineage
// exporters classify response-plane rows identically to every other row. The
// response-plane names are retained; the VALUES come from the shared package so
// they can never drift.
const (
	responseVerdictAllowed  = sharedaudit.DecisionAllowed
	responseVerdictRedacted = sharedaudit.DecisionRedacted
	responseVerdictBlocked  = sharedaudit.DecisionBlocked
)

// RedactionInfo is the response plane's record of one response: what it
// decided, who decided it, and what it masked.
type RedactionInfo struct {
	HasRedactions  bool     `json:"has_redactions"`
	RedactedFields []string `json:"redacted_fields"`
	RedactionCount int      `json:"redaction_count"`
	// Verdict is the canonical response-plane decision (#2626): "allowed",
	// "redacted", or "blocked". It drives the audit row's policy_decision AND
	// the HTTP outcome.
	Verdict string `json:"verdict,omitempty"`
	// ValidationError carries the reason a response was withheld when Verdict
	// == "blocked": the anchored refusal's text, the cause a response could not
	// be decided for, or the validation rule that failed; surfaced in the audit
	// row's policy_details.
	ValidationError string `json:"validation_error,omitempty"`
	// Engine, SubjectType and PolicyBundle are the response pass's decision
	// (decideResponse): the engine that authored the verdict, always anchored;
	// the type of principal it was decided for; and the digest of the policy
	// set that decided. SubjectType and PolicyBundle are empty on a response
	// withheld before a subject was admitted.
	Engine       string `json:"engine,omitempty"`
	SubjectType  string `json:"subject_type,omitempty"`
	PolicyBundle string `json:"policy_bundle,omitempty"`
	// DecisionReason is the anchored decision's reason code, or the cause a
	// response was withheld for when no decision could be taken.
	DecisionReason string `json:"decision_reason,omitempty"`
	// BlockingPolicyID names the constraint a refusal names as blocking, empty
	// when no constraint decided.
	BlockingPolicyID string `json:"blocking_policy_id,omitempty"`
	// WithheldByValidation says a response the anchored engine released was
	// withheld by a response validation rule, which is not a policy verdict:
	// the record keeps the engine's decision and names the rule in
	// ValidationError, and never presents the withholding as the engine's.
	WithheldByValidation bool `json:"withheld_by_validation,omitempty"`
	// LegacyValidators names a checksum validator that acted on the response
	// outside the anchored engine: the Indonesia validator's masking.
	LegacyValidators []agent.LegacyValidatorAction `json:"legacy_validators,omitempty"`
}

// ResponseEnricher adds metadata to responses
type ResponseEnricher struct {
	enrichmentRules []EnrichmentRule
}

// ValidationRule checks if a response is valid
type ValidationRule struct {
	Name      string
	Validator func(response interface{}) error
}

// EnrichmentRule adds metadata to responses
type EnrichmentRule struct {
	Name     string
	Enricher func(ctx context.Context, response interface{}) map[string]interface{}
}

// NewResponseProcessor creates a new response processor
func NewResponseProcessor() *ResponseProcessor {
	return &ResponseProcessor{
		enricher:        NewResponseEnricher(),
		validationRules: getDefaultValidationRules(),
	}
}

// ProcessResponse applies the response plane to an LLM response. The anchored
// engine decides it (decideResponse); a response it withholds is replaced by an
// error. A released response then passes the Indonesia checksum validator, which
// is not a policy verdict, and the validation and enrichment pipeline.
func (p *ResponseProcessor) ProcessResponse(ctx context.Context, user UserContext, response *LLMResponse) (interface{}, *RedactionInfo) {
	// Parse response content
	var responseData interface{}
	if err := json.Unmarshal([]byte(response.Content), &responseData); err != nil {
		// If not JSON, treat as plain text
		responseData = response.Content
	}

	processedData, redactionInfo := decideResponse(ctx, user, responseData)

	// A WITHHELD response: replace the content with an error and keep
	// Verdict=blocked, so run.go writes a canonical blocked row and answers
	// forbidden. Nothing below runs on content the engine refused.
	if redactionInfo.Verdict == responseVerdictBlocked {
		reason := redactionInfo.ValidationError
		if reason == "" {
			reason = "Response withheld by policy"
		}
		logResponsePlaneDecision(user.OrgID, redactionInfo)
		return map[string]string{
			"error":   "Response blocked by policy",
			"details": reason,
		}, redactionInfo
	}

	// Indonesia (OJK/UU PDP) checksum-validated NIK/NPWP governance. Neither the
	// shipped corpus nor the shared engine's validators carry a NIK checksum
	// detector on this plane, so without this NIK/NPWP leak on the LLM response
	// path (#2566 — mirrors the agent check-output fix #2565). It is not a
	// policy-engine verdict, as on the agent's MCP response pass: it runs on the
	// content the anchored engine released, and it is recorded as the legacy
	// validator it is.
	processedData, redactionInfo = p.applyIndonesiaResponseGovernance(processedData, redactionInfo)
	if redactionInfo.HasRedactions {
		redactionInfo.Verdict = responseVerdictRedacted
	}

	// Validate response (always runs)
	if err := p.validateResponse(processedData); err != nil {
		log.Printf("Response validation failed: %v", err)
		// The response is WITHHELD and replaced with an error: record it as
		// "blocked" (#2626 ORCH-RESP-VALIDATE-DENY-AS-ALLOWED), keeping the
		// anchored decision that released it and naming the rule that did not.
		redactionInfo.Verdict = responseVerdictBlocked
		redactionInfo.ValidationError = err.Error()
		redactionInfo.WithheldByValidation = true
		logResponsePlaneDecision(user.OrgID, redactionInfo)
		return map[string]string{
			"error":   "Response validation failed",
			"details": err.Error(),
		}, redactionInfo
	}

	logResponsePlaneDecision(user.OrgID, redactionInfo)
	// Enrich response with metadata (always runs)
	return p.enrichResponse(ctx, processedData), redactionInfo
}

var (
	orchestratorIndonesiaDetector     *indonesia.IndonesiaPIIDetector
	orchestratorIndonesiaDetectorOnce sync.Once
)

// getOrchestratorIndonesiaDetector lazily builds the Indonesia PII detector
// (NIK/NPWP/+62/bank). Same detector the agent uses. Returns nil only when
// Indonesia detection is disabled (indonesia.IsEnabled() == false); note both
// the enterprise and community builds currently enable it (the enterprise build
// adds checksum/province validation strictness — community is pattern-based).
func getOrchestratorIndonesiaDetector() *indonesia.IndonesiaPIIDetector {
	orchestratorIndonesiaDetectorOnce.Do(func() {
		if indonesia.IsEnabled() {
			orchestratorIndonesiaDetector = indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
			log.Printf("🇮🇩 [OJK] Orchestrator Indonesia PII response detector initialized")
		}
	})
	return orchestratorIndonesiaDetector
}

// applyIndonesiaResponseGovernance masks checksum-validated Indonesia PII in an
// LLM response (any JSON shape — string, object, array), folds the detected
// types into redactionInfo and records the validator's masking. Returns the
// input unchanged when the detector is disabled or finds nothing.
func (p *ResponseProcessor) applyIndonesiaResponseGovernance(data interface{}, info *RedactionInfo) (interface{}, *RedactionInfo) {
	detector := getOrchestratorIndonesiaDetector()
	if detector == nil {
		return data, info
	}
	masked, types := maskIndonesiaPIIDeep(detector, data)
	if len(types) == 0 {
		return data, info
	}
	if info == nil {
		info = &RedactionInfo{}
	}
	info.HasRedactions = true
	info.RedactionCount += len(types)
	info.RedactedFields = append(info.RedactedFields, types...)
	info.LegacyValidators = append(info.LegacyValidators, agent.LegacyValidatorAction{
		Validator: agent.LegacyValidatorIndonesia, Action: agent.LegacyActionMasked,
	})
	return masked, info
}

// maskIndonesiaPIIDeep walks an arbitrary decoded-JSON value and returns a copy
// with every Indonesia PII occurrence in string leaves replaced by its
// per-detection MaskedValue, plus the distinct-per-leaf detected type names.
//
// It is SIDE-EFFECT-FREE: maps/slices are rebuilt into fresh containers rather
// than mutated in place, because the input can alias the content the anchored
// engine released, which the caller still holds.
func maskIndonesiaPIIDeep(d *indonesia.IndonesiaPIIDetector, v interface{}) (interface{}, []string) {
	switch t := v.(type) {
	case string:
		out := t
		var types []string
		for _, det := range d.DetectAll(t) {
			if det.Value != "" && det.MaskedValue != "" && det.MaskedValue != det.Value {
				out = strings.ReplaceAll(out, det.Value, det.MaskedValue)
				types = append(types, string(det.Type))
			}
		}
		return out, types
	case map[string]interface{}:
		cp := make(map[string]interface{}, len(t))
		var types []string
		for k, val := range t {
			nv, ts := maskIndonesiaPIIDeep(d, val)
			cp[k] = nv
			types = append(types, ts...)
		}
		return cp, types
	case []interface{}:
		cp := make([]interface{}, len(t))
		var types []string
		for i, val := range t {
			nv, ts := maskIndonesiaPIIDeep(d, val)
			cp[i] = nv
			types = append(types, ts...)
		}
		return cp, types
	default:
		// Primitives (numbers, bools, nil) pass through unchanged. NOTE: this
		// covers the json.Unmarshal-derived shapes ProcessResponse actually
		// feeds (objects → map[string]interface{}, arrays → []interface{}); a
		// []map[string]interface{} "rows" value would fall here unwalked, but
		// that type is never produced on the response path (the redactor never
		// converts type).
		return v, nil
	}
}

// validateResponse validates the response against rules
func (p *ResponseProcessor) validateResponse(data interface{}) error {
	for _, rule := range p.validationRules {
		if err := rule.Validator(data); err != nil {
			return fmt.Errorf("%s: %w", rule.Name, err)
		}
	}
	return nil
}

// enrichResponse adds metadata to the response
func (p *ResponseProcessor) enrichResponse(ctx context.Context, data interface{}) interface{} {
	enrichments := make(map[string]interface{})

	for _, rule := range p.enricher.enrichmentRules {
		metadata := rule.Enricher(ctx, data)
		for k, v := range metadata {
			enrichments[k] = v
		}
	}

	// Wrap response with enrichments
	return map[string]interface{}{
		"data":     data,
		"metadata": enrichments,
	}
}

// IsHealthy checks if the response processor is healthy
func (p *ResponseProcessor) IsHealthy() bool {
	return true
}

// NewResponseEnricher creates a new response enricher
func NewResponseEnricher() *ResponseEnricher {
	return &ResponseEnricher{
		enrichmentRules: []EnrichmentRule{
			{
				Name: "timestamp",
				Enricher: func(ctx context.Context, response interface{}) map[string]interface{} {
					return map[string]interface{}{
						"processed_at": time.Now().UTC().Format(time.RFC3339),
					}
				},
			},
			{
				Name: "request_context",
				Enricher: func(ctx context.Context, response interface{}) map[string]interface{} {
					metadata := make(map[string]interface{})
					if reqID := ctx.Value("request_id"); reqID != nil {
						metadata["request_id"] = reqID
					}
					if user := ctx.Value("user"); user != nil {
						if u, ok := user.(UserContext); ok {
							metadata["processed_for_role"] = u.Role
						}
					}
					return metadata
				},
			},
		},
	}
}

// getDefaultValidationRules returns default validation rules
func getDefaultValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Name: "no_empty_response",
			Validator: func(response interface{}) error {
				if response == nil || response == "" {
					return fmt.Errorf("empty response")
				}
				return nil
			},
		},
		{
			Name: "no_error_messages",
			Validator: func(response interface{}) error {
				// Check for common error patterns
				respStr := fmt.Sprint(response)
				errorPatterns := []string{"error:", "exception:", "failed:", "denied:"}
				for _, pattern := range errorPatterns {
					if strings.Contains(strings.ToLower(respStr), pattern) {
						return fmt.Errorf("response contains error message")
					}
				}
				return nil
			},
		},
		{
			Name: "reasonable_size",
			Validator: func(response interface{}) error {
				respStr := fmt.Sprint(response)
				if len(respStr) > 1000000 { // 1MB limit
					return fmt.Errorf("response too large")
				}
				return nil
			},
		},
	}
}

// NOTE (#3015): a local isElevatedRole helper used to live here, returning
// role == "admin" || role == "owner". It is gone: shipping a fresh hardcoded
// role-literal pair in the very file whose purpose is removing them is
// self-defeating, and a second definition of "administrative role" is exactly
// the drift this PR exists to close. The one definition is
// platform/shared/identity.RoleIsAdministrative, which normalizes through the
// closed role vocabulary (so an unrecognized string fails closed) and is the
// single place to edit when the tier changes.
