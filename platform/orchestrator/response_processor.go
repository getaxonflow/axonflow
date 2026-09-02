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

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/agent/indonesia"
	"axonflow/platform/decision/legacycompile"
	sharedaudit "axonflow/platform/shared/audit"
	sharedpolicy "axonflow/platform/shared/policy"
)

// ResponseProcessor handles PII detection and redaction in LLM responses
type ResponseProcessor struct {
	piiDetector         *PIIDetector
	enhancedPIIDetector *EnhancedPIIDetector
	sharedPolicyEngine  *sharedpolicy.UnifiedPolicyEngine // Unified policy engine (Issues #963, #975)
	redactor            *Redactor
	enricher            *ResponseEnricher
	validationRules     []ValidationRule
	useEnhancedDetector bool
	useSharedEngine     bool // Use shared policy engine for PII detection/redaction
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

// RedactionInfo contains information about redactions made
type RedactionInfo struct {
	HasRedactions  bool     `json:"has_redactions"`
	RedactedFields []string `json:"redacted_fields"`
	RedactionCount int      `json:"redaction_count"`
	// Verdict is the canonical response-plane decision (#2626): "allowed",
	// "redacted", or "blocked". It drives the audit row's policy_decision AND
	// the HTTP outcome. Kept distinct from HasRedactions so warn/log
	// (detect-don't-modify) is recorded truthfully as "allowed" — never
	// mislabeled "redacted" — while a withheld/validation-denied response is
	// recorded as "blocked" rather than the success it used to masquerade as.
	Verdict string `json:"verdict,omitempty"`
	// ValidationError carries the response-plane validation-failure reason when
	// Verdict == "blocked"; surfaced in the audit row's policy_details.
	ValidationError string `json:"validation_error,omitempty"`
}

// PIIDetector detects various types of PII in text
type PIIDetector struct {
	patterns map[string]*regexp.Regexp
}

// Redactor handles the actual redaction of sensitive data
type Redactor struct {
	redactionStrategies map[string]RedactionStrategy
}

// RedactionStrategy defines how to redact specific types of data
type RedactionStrategy interface {
	Redact(value string) string
	GetPlaceholder() string
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
	rp := &ResponseProcessor{
		piiDetector:         NewPIIDetector(),
		enhancedPIIDetector: NewEnhancedPIIDetector(DefaultPIIDetectorConfig()),
		redactor:            NewRedactor(),
		enricher:            NewResponseEnricher(),
		validationRules:     getDefaultValidationRules(),
		useEnhancedDetector: true, // Use enhanced detector by default
	}

	// Try to use shared policy engine if available (Issues #963, #975)
	if engine := sharedpolicy.GetGlobalEngine(); engine != nil {
		rp.sharedPolicyEngine = engine
		rp.useSharedEngine = true
		log.Println("[ResponseProcessor] Using shared policy engine for PII detection")
	}

	return rp
}

// NewResponseProcessorWithConfig creates a response processor with custom configuration
func NewResponseProcessorWithConfig(useEnhanced bool, piiConfig PIIDetectorConfig) *ResponseProcessor {
	rp := &ResponseProcessor{
		piiDetector:         NewPIIDetector(),
		enhancedPIIDetector: NewEnhancedPIIDetector(piiConfig),
		redactor:            NewRedactor(),
		enricher:            NewResponseEnricher(),
		validationRules:     getDefaultValidationRules(),
		useEnhancedDetector: useEnhanced,
	}

	// Try to use shared policy engine if available (Issues #963, #975)
	if engine := sharedpolicy.GetGlobalEngine(); engine != nil {
		rp.sharedPolicyEngine = engine
		rp.useSharedEngine = true
	}

	return rp
}

// SetSharedPolicyEngine sets the shared policy engine for unified PII detection.
// This enables phase-aware policy enforcement per ADR-022.
func (p *ResponseProcessor) SetSharedPolicyEngine(engine *sharedpolicy.UnifiedPolicyEngine) {
	p.sharedPolicyEngine = engine
	p.useSharedEngine = engine != nil
}

// SetUseSharedEngine enables or disables the shared policy engine
func (p *ResponseProcessor) SetUseSharedEngine(enabled bool) {
	p.useSharedEngine = enabled && p.sharedPolicyEngine != nil
}

// SetUseEnhancedDetector enables or disables the enhanced PII detector
func (p *ResponseProcessor) SetUseEnhancedDetector(enabled bool) {
	p.useEnhancedDetector = enabled
}

// IsUsingSharedEngine returns true if the shared policy engine is active
func (p *ResponseProcessor) IsUsingSharedEngine() bool {
	return p.useSharedEngine && p.sharedPolicyEngine != nil
}

// ProcessResponse processes an LLM response for PII and applies redactions.
// Respects PII_ACTION env var: "block"/"redact" = detect+redact, "warn"/"log" = skip redaction.
// The validate + enrich pipeline always runs regardless of PII_ACTION.
func (p *ResponseProcessor) ProcessResponse(ctx context.Context, user UserContext, response *LLMResponse) (interface{}, *RedactionInfo) {
	// Parse response content
	var responseData interface{}
	if err := json.Unmarshal([]byte(response.Content), &responseData); err != nil {
		// If not JSON, treat as plain text
		responseData = response.Content
	}

	var processedData interface{}
	var redactionInfo *RedactionInfo

	// PII_ACTION controls whether redaction runs on responses.
	// All modes run detection (for audit). Only block/redact actually modify the response.
	piiAction := os.Getenv("PII_ACTION")
	skipRedaction := piiAction == "warn" || piiAction == "log"

	// Per-org posture (#2612): when this org has an EXPLICIT PII override, it
	// governs the detect-don't-modify (warn/log) vs redact/block revert decision
	// for THIS org. Without this, a per-org redact/block set on the engine config
	// at processWithSharedEngine (below) would still be reverted by the
	// deployment-global warn/log baseline → the org's PII leaks. Layered ON TOP of
	// the global baseline: no override (empty org / no cache / no row) leaves the
	// baseline above untouched → byte-identical to the global-only behavior.
	if orgPIIAction, ok := ResolveGatewayPIIActionOverride(ctx, user.OrgID); ok {
		skipRedaction = orgPIIAction == agent.DetectionActionWarn || orgPIIAction == agent.DetectionActionLog
	}

	if p.useSharedEngine && p.sharedPolicyEngine != nil {
		// Use shared policy engine (database-driven, configurable)
		processedData, redactionInfo = p.processWithSharedEngine(ctx, user, responseData)
	} else {
		// Fallback to legacy PII detection (hardcoded regexes)
		detectedPII := p.detectPII(responseData)
		processedData, redactionInfo = p.applyRedactions(user, responseData, detectedPII)
	}

	// Engine-level governance BLOCK (sensitive-data under strict/compliance, #2705):
	// WITHHOLD the LLM response entirely and return early — BEFORE the warn/log
	// skipRedaction revert (which would otherwise restore the original secret-
	// bearing response) and BEFORE the redacted/allowed verdict overwrite below.
	// Mirrors the validation-deny path: replace the content with an error and keep
	// Verdict=blocked so run.go writes a canonical blocked row + returns forbidden.
	if redactionInfo != nil && redactionInfo.Verdict == responseVerdictBlocked {
		reason := redactionInfo.ValidationError
		if reason == "" {
			reason = "Response withheld by policy"
		}
		log.Printf("[ResponseProcessor] LLM response BLOCKED by policy: %s", reason)
		return map[string]string{
			"error":   "Response blocked by policy",
			"details": reason,
		}, redactionInfo
	}

	// Indonesia (OJK/UU PDP) checksum-validated NIK/NPWP governance. Neither the
	// shared engine's PII validators nor the EnhancedPIIDetector carry a NIK
	// checksum detector, so without this NIK/NPWP leak on the orchestrator/LLM-
	// gateway response path (#2566 — mirrors the agent check-output fix #2565).
	// Runs on the post-engine content; the skipRedaction revert below gives
	// warn/log detect-don't-modify for free (block/redact keep the masked content).
	processedData, redactionInfo = p.applyIndonesiaResponseGovernance(processedData, redactionInfo)

	// warn/log: detection ran (redactionInfo populated for audit) but return original data
	if skipRedaction {
		processedData = responseData
	}

	// Canonical response-plane verdict (#2626). The audit row must reflect what
	// ACTUALLY happened to the response, not merely what detection matched:
	//   - warn/log (skipRedaction): detection may have fired, but the response is
	//     returned UNMODIFIED → "allowed" (detected fields stay in RedactedFields
	//     for audit visibility; never mislabeled "redacted").
	//   - block/redact that actually masked content → "redacted".
	//   - otherwise → "allowed".
	if redactionInfo == nil {
		redactionInfo = &RedactionInfo{}
	}
	if !skipRedaction && redactionInfo.HasRedactions {
		redactionInfo.Verdict = responseVerdictRedacted
	} else {
		redactionInfo.Verdict = responseVerdictAllowed
	}

	// Validate response (always runs regardless of PII_ACTION)
	if err := p.validateResponse(processedData); err != nil {
		log.Printf("Response validation failed: %v", err)
		// The original LLM response is WITHHELD and replaced with an error. This
		// is a response-plane denial: record it truthfully as "blocked" so it is
		// never persisted as the success the caller used to receive
		// (#2626 ORCH-RESP-VALIDATE-DENY-AS-ALLOWED).
		return map[string]string{
			"error":   "Response validation failed",
			"details": err.Error(),
		}, &RedactionInfo{Verdict: responseVerdictBlocked, ValidationError: err.Error()}
	}

	// Enrich response with metadata (always runs regardless of PII_ACTION)
	enrichedData := p.enrichResponse(ctx, processedData)

	return enrichedData, redactionInfo
}

// processWithSharedEngine uses the unified policy engine for PII detection and redaction.
// This provides comprehensive validators (Luhn, MOD97, Verhoeff, SSN, Aadhaar, PAN).
// Uses GATEWAY detection config since orchestrator processes LLM responses for proxy/gateway/MAP modes.
func (p *ResponseProcessor) processWithSharedEngine(ctx context.Context, user UserContext, data interface{}) (interface{}, *RedactionInfo) {
	// Per-org posture (#2612): resolve the gateway config with this org's
	// overrides layered on the deployment-global config (fail-safe to global).
	// Drives BuildActionOverrides below so the engine redacts/blocks/warns per the
	// org's posture, not just the deployment-wide one.
	gwCfg := ResolveGatewayDetectionConfig(ctx, user.OrgID)

	// Skip shared engine processing if gateway static policies are disabled
	if !gwCfg.Enabled {
		log.Printf("[ResponseProcessor] Gateway static policies disabled, skipping shared engine")
		return data, &RedactionInfo{}
	}

	// #2820: fail closed on a policy-LOAD error. EnabledPIICategories below
	// returns nil on BOTH "no enabled category" and a load error, so a transient
	// load failure would leave evalCats empty and return the LLM response
	// unredacted (fail-OPEN). Withhold the response instead — a redactor must
	// never forward content it could not scan.
	if err := p.sharedPolicyEngine.PoliciesLoadable(ctx, user.TenantID, sharedpolicy.OrgScopePtr(user.OrgID), sharedpolicy.PhaseResponse); err != nil {
		log.Printf("[ResponseProcessor] Response withheld: could not load response-phase policies (fail-closed, #2820): %v", err)
		return data, &RedactionInfo{
			Verdict:         responseVerdictBlocked,
			ValidationError: "response withheld: policy engine could not evaluate (fail-closed)",
		}
	}

	// Policy-derived evaluation categories: every enabled PII-category system
	// policy (so a newly-seeded pii-* like pii-indonesia is auto-covered) PLUS the
	// sensitive-data (secrets) category, so the SENSITIVE_DATA_ACTION / profile
	// lever reaches the response plane too (#2705) — previously only PII was
	// evaluated, so a credential-shaped LLM response was never warn/block-enforced.
	// nil+nil = nothing enabled → skip; must NOT fall through to EvaluateResponse
	// with empty Categories (that evaluates ALL policies — the whitelist footgun).
	piiCats := p.sharedPolicyEngine.EnabledPIICategories(ctx, user.TenantID, sharedpolicy.OrgScopePtr(user.OrgID), sharedpolicy.PhaseResponse)
	sensCats := p.sharedPolicyEngine.EnabledSensitiveDataCategories(ctx, user.TenantID, sharedpolicy.OrgScopePtr(user.OrgID), sharedpolicy.PhaseResponse)
	evalCats := append(append([]sharedpolicy.PolicyCategory{}, piiCats...), sensCats...)
	if len(evalCats) == 0 {
		log.Printf("[ResponseProcessor] No enabled PII/sensitive-data policies, skipping shared engine")
		return data, &RedactionInfo{}
	}

	result := p.sharedPolicyEngine.EvaluateResponse(ctx, data, sharedpolicy.EvalOptions{
		Plane: legacycompile.PlaneOrchestratorResponse,
		// v9 Phase 8 #2384 PR-C1: OrgID propagation for RLS-aware audit writes.
		// #3048 R3 HIGH-3: OrganizationID scopes the loader's tenant pass.
		TenantID:        user.TenantID,
		OrgID:           user.OrgID,
		OrgScope:        sharedpolicy.OrgScopePtr(user.OrgID),
		UserID:          fmt.Sprintf("%d", user.ID),
		Categories:      evalCats,
		SkipCategories:  gwCfg.SkipCategories,
		ActionOverrides: gwCfg.BuildActionOverrides(),
		MaxRedactions:   100, // Reasonable limit for LLM responses
		// #3266: no resolved governance-segment set on this plane — nil
		// excludes segment-scoped static_policies rows (fail-closed, leak
		// closed). This response plane evaluates org-level PII/sensitive-data
		// detection config, not segment-scoped policy; deliberately out of
		// scope here (not tracked under #3280/#3281/#3297).
		Segments: nil,
	})

	// #2820: second line of defense — a load race between PoliciesLoadable and
	// here (cache expiry mid-request) leaves EvaluationError set; withhold the
	// response rather than forward it unscanned.
	if result.EvaluationError {
		log.Printf("[ResponseProcessor] Response withheld: response-phase scan could not complete (fail-closed, #2820)")
		return data, &RedactionInfo{
			Verdict:         responseVerdictBlocked,
			ValidationError: "response withheld: policy engine could not evaluate (fail-closed)",
		}
	}

	redactionInfo := &RedactionInfo{
		HasRedactions:  result.Redacted,
		RedactionCount: len(result.RedactedFields),
	}
	// A policy whose EFFECTIVE response-phase action is `block` (sensitive-data
	// under strict/compliance) WITHHOLDS the LLM response: propagate the engine's
	// block verdict so ProcessResponse replaces the content and run.go writes a
	// canonical blocked row (#2705). Independent of the PII warn/log skipRedaction
	// path below — block is enforcement, not redaction, so it is NOT reverted.
	if result.Blocked {
		redactionInfo.Verdict = responseVerdictBlocked
		redactionInfo.ValidationError = result.BlockReason
	}

	// Convert redacted field paths to slice
	for _, field := range result.RedactedFields {
		redactionInfo.RedactedFields = append(redactionInfo.RedactedFields, field.Path)
	}

	log.Printf("[ResponseProcessor] Shared engine evaluated %d policies in %dms, redactions=%d",
		result.PoliciesEvaluated, result.ProcessingTimeMs, len(result.RedactedFields))

	return result.Content, redactionInfo
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
// LLM response (any JSON shape — string, object, array) and folds the detected
// types into redactionInfo. Detect-don't-modify under warn/log is handled by the
// caller's skipRedaction revert (this always masks; the revert discards it for
// warn/log). Returns the input unchanged when the detector is disabled or finds
// nothing.
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
	return masked, info
}

// maskIndonesiaPIIDeep walks an arbitrary decoded-JSON value and returns a copy
// with every Indonesia PII occurrence in string leaves replaced by its
// per-detection MaskedValue, plus the distinct-per-leaf detected type names.
//
// It is SIDE-EFFECT-FREE: maps/slices are rebuilt into fresh containers rather
// than mutated in place. This is load-bearing for the warn/log "detect-don't-
// modify" contract: on the shared-engine path the input often aliases the
// caller's original responseData (the engine returns content unchanged when no
// redaction plans fire), so an in-place mutation here would also mutate the
// "original" that ProcessResponse's skipRedaction revert restores — silently
// masking NIK under warn/log for JSON-object/array responses.
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
		// that type is never produced on the response path (the shared-engine
		// redactor never converts type).
		return v, nil
	}
}

// detectPII detects PII in the response data
func (p *ResponseProcessor) detectPII(data interface{}) map[string][]string {
	detected := make(map[string][]string)

	// Convert to string for analysis
	dataStr := fmt.Sprint(data)

	// Use enhanced detector if enabled
	if p.useEnhancedDetector && p.enhancedPIIDetector != nil {
		// DetectAll already filters by the detector's configured minConfidence
		results := p.enhancedPIIDetector.DetectAll(dataStr)
		for _, result := range results {
			detected[string(result.Type)] = append(detected[string(result.Type)], result.Value)
		}
	} else {
		// Fallback to legacy detector
		for piiType, pattern := range p.piiDetector.patterns {
			matches := pattern.FindAllString(dataStr, -1)
			if len(matches) > 0 {
				detected[piiType] = matches
			}
		}
	}

	// Deep scan for structured data (field names)
	if mapData, ok := data.(map[string]interface{}); ok {
		p.deepScanForPII(mapData, detected)
	}

	return detected
}

// detectPIIEnhanced returns detailed PII detection results with confidence scores
//
//nolint:unused // Used in tests only
func (p *ResponseProcessor) detectPIIEnhanced(data interface{}) []PIIDetectionResult {
	if p.enhancedPIIDetector == nil {
		return nil
	}

	dataStr := fmt.Sprint(data)
	return p.enhancedPIIDetector.DetectAll(dataStr)
}

// deepScanForPII recursively scans structured data for PII
func (p *ResponseProcessor) deepScanForPII(data map[string]interface{}, detected map[string][]string) {
	for key, value := range data {
		// Check if key name suggests PII
		lowerKey := strings.ToLower(key)
		if contains([]string{"ssn", "social_security", "email", "phone", "credit_card", "account_number"}, lowerKey) {
			detected["field_name_pii"] = append(detected["field_name_pii"], key)
		}

		// Recursively check nested structures
		switch v := value.(type) {
		case map[string]interface{}:
			p.deepScanForPII(v, detected)
		case []interface{}:
			for _, item := range v {
				if mapItem, ok := item.(map[string]interface{}); ok {
					p.deepScanForPII(mapItem, detected)
				}
			}
		case string:
			// Check string values for PII patterns
			for piiType, pattern := range p.piiDetector.patterns {
				if pattern.MatchString(v) {
					detected[piiType] = append(detected[piiType], v)
				}
			}
		}
	}
}

// applyRedactions applies redactions based on user permissions
func (p *ResponseProcessor) applyRedactions(user UserContext, data interface{}, detectedPII map[string][]string) (interface{}, *RedactionInfo) {
	redactionInfo := &RedactionInfo{
		HasRedactions:  false,
		RedactedFields: []string{},
		RedactionCount: 0,
	}

	// Check user permissions
	allowedPII := p.getAllowedPIITypes(user)

	// Apply redactions
	redactedData := p.redactData(data, detectedPII, allowedPII, redactionInfo)

	return redactedData, redactionInfo
}

// getAllowedPIITypes returns PII types the user is allowed to see.
//
// PERMISSION-DRIVEN ONLY (#3001). This used to end with
//
//	if user.Role == "admin" { return []string{"*"} }
//
// which made an admin-role caller receive LLM responses completely unredacted.
// Two things were wrong with it:
//
//  1. It was a literal string compare on the role, so `owner` did NOT match.
//     After #2993 made owner a strict superset of admin everywhere else, this
//     one site INVERTED the relationship — an owner got LESS (redacted) than an
//     admin (raw). Any role-literal here re-introduces that class of drift.
//  2. Whether a role bypasses PII redaction on response content at all is a
//     compliance decision, not something to inherit. On a regulated deployment
//     "the admin sees raw customer PII" must be claimed deliberately.
//
// So allowance now derives ONLY from explicit permissions, and NO role — admin
// or owner — is auto-granted view_full_pii. Seeing raw PII is an opt-in an
// operator makes by putting the permission on a role. Behavior change,
// documented in the CHANGELOG.
//
// NOTE ON TRUST: UserContext (including Permissions) arrives on the request, so
// these permissions are only as trustworthy as the caller — exactly as the
// role literal was. This change does not alter that trust model; it makes the
// grant explicit and role-agnostic. Tightening the plane's identity trust is
// separate work.
func (p *ResponseProcessor) getAllowedPIITypes(user UserContext) []string {
	allowed := []string{}

	// Map permissions to PII types. view_full_pii is the "see everything this
	// map covers" grant; it is intentionally NOT part of any seeded system role.
	permissionMap := map[string][]string{
		"view_full_pii":  {"ssn", "credit_card", "bank_account", "email", "phone", "address"},
		"view_basic_pii": {"email", "phone"},
		"view_financial": {"credit_card", "bank_account"},
		"view_medical":   {"medical_record", "diagnosis"},
	}

	for _, permission := range user.Permissions {
		if piiTypes, exists := permissionMap[permission]; exists {
			allowed = append(allowed, piiTypes...)
		}
	}

	return allowed
}

// redactData performs the actual redaction
func (p *ResponseProcessor) redactData(data interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) interface{} {
	// Handle different data types
	switch v := data.(type) {
	case string:
		return p.redactString(v, detectedPII, allowedPII, info)
	case map[string]interface{}:
		return p.redactMap(v, detectedPII, allowedPII, info)
	case []interface{}:
		return p.redactSlice(v, detectedPII, allowedPII, info)
	default:
		return data
	}
}

// redactString redacts PII from a string
func (p *ResponseProcessor) redactString(s string, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) string {
	redacted := s

	for piiType, values := range detectedPII {
		if !p.isAllowed(piiType, allowedPII) {
			strategy := p.redactor.getStrategy(piiType)
			for _, value := range values {
				if strings.Contains(redacted, value) {
					redacted = strings.ReplaceAll(redacted, value, strategy.Redact(value))
					info.RedactionCount++
					info.HasRedactions = true
					if !contains(info.RedactedFields, piiType) {
						info.RedactedFields = append(info.RedactedFields, piiType)
					}
				}
			}
		}
	}

	return redacted
}

// redactMap redacts PII from a map
func (p *ResponseProcessor) redactMap(m map[string]interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) map[string]interface{} {
	redacted := make(map[string]interface{})

	for key, value := range m {
		// Check if the key itself suggests PII
		if p.shouldRedactField(key, allowedPII) {
			redacted[key] = "[REDACTED]"
			info.RedactionCount++
			info.HasRedactions = true
			info.RedactedFields = append(info.RedactedFields, key)
		} else {
			redacted[key] = p.redactData(value, detectedPII, allowedPII, info)
		}
	}

	return redacted
}

// redactSlice redacts PII from a slice
func (p *ResponseProcessor) redactSlice(s []interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) []interface{} {
	redacted := make([]interface{}, len(s))

	for i, item := range s {
		redacted[i] = p.redactData(item, detectedPII, allowedPII, info)
	}

	return redacted
}

// isAllowed checks if a PII type is allowed for the user
func (p *ResponseProcessor) isAllowed(piiType string, allowedPII []string) bool {
	// NOTE (#3001): there is deliberately no `contains(allowedPII, "*")`
	// blanket-allow short-circuit here any more. getAllowedPIITypes used to
	// return []string{"*"} for the admin role; removing that producer while
	// leaving this consumer would mean the moment anything else feeds a
	// permission list in here — a stored `admin` role literally holds
	// Permissions: ["*"] — allow-all would silently come back.
	return contains(allowedPII, piiType)
}

// shouldRedactField checks if a field name suggests PII that should be redacted
func (p *ResponseProcessor) shouldRedactField(fieldName string, allowedPII []string) bool {
	sensitiveFields := map[string]string{
		"ssn":             "ssn",
		"social_security": "ssn",
		"credit_card":     "credit_card",
		"card_number":     "credit_card",
		"account_number":  "bank_account",
		"routing_number":  "bank_account",
		"medical_record":  "medical_record",
		"diagnosis":       "diagnosis",
	}

	lowerField := strings.ToLower(fieldName)
	for field, piiType := range sensitiveFields {
		if strings.Contains(lowerField, field) && !p.isAllowed(piiType, allowedPII) {
			return true
		}
	}

	return false
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

// NewPIIDetector creates a new PII detector
func NewPIIDetector() *PIIDetector {
	return &PIIDetector{
		patterns: map[string]*regexp.Regexp{
			"ssn":          regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`),
			"credit_card":  regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
			"email":        regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			"phone":        regexp.MustCompile(`\b(\+?1[- .]?)?\(?\d{3}\)?[- ]\d{3}[- ]\d{4}\b|\b\d{3}\.\d{3}\.\d{4}\b`),
			"ip_address":   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"bank_account": regexp.MustCompile(`\b\d{10,17}\b`), // 10+ digits — avoids false positives on 9-digit timestamps, phone numbers, zip codes
		},
	}
}

// NewRedactor creates a new redactor
func NewRedactor() *Redactor {
	return &Redactor{
		redactionStrategies: map[string]RedactionStrategy{
			"ssn":          &MaskingStrategy{keepLast: 4, placeholder: "XXX-XX-"},
			"credit_card":  &MaskingStrategy{keepLast: 4, placeholder: "****-****-****-"},
			"email":        &HashingStrategy{},
			"phone":        &MaskingStrategy{keepLast: 4, placeholder: "***-***-"},
			"ip_address":   &MaskingStrategy{keepLast: 0, placeholder: "***.***.***.***"},
			"bank_account": &MaskingStrategy{keepLast: 4, placeholder: "****"},
			"default":      &DefaultStrategy{},
		},
	}
}

func (r *Redactor) getStrategy(piiType string) RedactionStrategy {
	if strategy, exists := r.redactionStrategies[piiType]; exists {
		return strategy
	}
	return r.redactionStrategies["default"]
}

// Redaction strategies

type MaskingStrategy struct {
	keepLast    int
	placeholder string
}

func (m *MaskingStrategy) Redact(value string) string {
	if m.keepLast > 0 && len(value) > m.keepLast {
		return m.placeholder + value[len(value)-m.keepLast:]
	}
	return m.placeholder
}

func (m *MaskingStrategy) GetPlaceholder() string {
	return m.placeholder
}

type HashingStrategy struct{}

func (h *HashingStrategy) Redact(value string) string {
	// In production, use a proper hash
	return fmt.Sprintf("[HASHED_%d]", len(value))
}

func (h *HashingStrategy) GetPlaceholder() string {
	return "[HASHED]"
}

type DefaultStrategy struct{}

func (d *DefaultStrategy) Redact(value string) string {
	return "[REDACTED]"
}

func (d *DefaultStrategy) GetPlaceholder() string {
	return "[REDACTED]"
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

// contains reports whether item is present in slice, which may be a
// []string or a []interface{} (the two shapes policy condition values and
// PII allow-lists arrive in). Non-string items in a []interface{} are
// stringified before comparison.
//
// #3319: relocated from dynamic_policy_engine.go, which was deleted along
// with the retired in-memory DynamicPolicyEngine. This is the only
// remaining caller (deepScanForPII, isAllowed, redactString above) — grep
// confirmed no other reference outside this file and its test.
func contains(slice interface{}, item interface{}) bool {
	switch s := slice.(type) {
	case []string:
		for _, v := range s {
			if v == fmt.Sprint(item) {
				return true
			}
		}
	case []interface{}:
		for _, v := range s {
			if fmt.Sprint(v) == fmt.Sprint(item) {
				return true
			}
		}
	}
	return false
}
