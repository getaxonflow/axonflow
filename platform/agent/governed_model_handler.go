// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"axonflow/platform/orchestrator/cost"
	"axonflow/platform/shared/serviceauth"
	"github.com/google/uuid"
)

const governedModelQueryLimit = 100_000
const governedModelBodyLimit = 1_000_000
const governedModelUsageCommitTimeout = 5 * time.Second
const governedModelForwardStaleAfter = 30 * time.Second
const governedModelDisableFailoverContextKey = "_axonflow_disable_llm_failover"

var governedModelReservedPlatformContextKeys = []string{
	"policy_preferred_provider",
	"policy_allowed_providers",
	"policy_routing_reason",
	governedModelDisableFailoverContextKey,
}

type governedModelContextKey struct{}
type governedModelCorrelationContextKey struct{}

var governedModelSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var governedModelTraceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type GovernedModelCorrelation struct {
	RequestID        string `json:"request_id"`
	TraceID          string `json:"trace_id"`
	Module           string `json:"module"`
	CaseID           string `json:"case_id"`
	EvidenceVersion  string `json:"evidence_version"`
	InvestigationKey string `json:"investigation_key"`
}

// GovernedModelRequest is the identity-free request accepted by the internal
// governed model seam. Identity is deliberately absent: the route accepts only
// the existing subject-bound internal-service credential and derives
// organization, tenant and service principal from that verified credential.
type GovernedModelRequest struct {
	Query       string                    `json:"query"`
	Context     map[string]any            `json:"context,omitempty"`
	Correlation *GovernedModelCorrelation `json:"correlation"`
}

type AuthenticatedPrincipalInfo struct {
	Kind           string `json:"kind"`
	PrincipalID    string `json:"principal_id"`
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
}

type ModelUsageReceipt struct {
	Attempted bool   `json:"attempted"`
	Recorded  bool   `json:"recorded"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

func modelUsageReceiptMap(receipt ModelUsageReceipt) map[string]any {
	return map[string]any{"attempted": receipt.Attempted, "recorded": receipt.Recorded,
		"request_id": receipt.RequestID, "status": receipt.Status}
}

func principalPointer(principal AuthenticatedPrincipalInfo) *AuthenticatedPrincipalInfo {
	return &principal
}

func isGovernedModelRequest(ctx context.Context) bool {
	value, _ := ctx.Value(governedModelContextKey{}).(bool)
	return value
}

func governedModelCorrelation(ctx context.Context) (GovernedModelCorrelation, bool) {
	value, ok := ctx.Value(governedModelCorrelationContextKey{}).(GovernedModelCorrelation)
	return value, ok
}

func validateGovernedModelCorrelation(value *GovernedModelCorrelation) error {
	if value == nil {
		return fmt.Errorf("correlation is required")
	}
	if _, err := uuid.Parse(value.RequestID); err != nil {
		return fmt.Errorf("correlation request_id must be a UUID")
	}
	if !governedModelTraceID.MatchString(value.TraceID) {
		return fmt.Errorf("correlation trace_id must be 32 lowercase hex characters")
	}
	if strings.TrimSpace(value.Module) == "" || len(value.Module) > 64 ||
		strings.TrimSpace(value.CaseID) == "" || len(value.CaseID) > 255 {
		return fmt.Errorf("correlation module and case_id are required")
	}
	if !governedModelSHA256.MatchString(value.EvidenceVersion) ||
		!governedModelSHA256.MatchString(value.InvestigationKey) {
		return fmt.Errorf("correlation evidence_version and investigation_key must be SHA-256 values")
	}
	return nil
}

var governedModelReservedContextKeys = map[string]struct{}{
	"client": {}, "client_id": {}, "org_id": {}, "organization_id": {},
	"principal_id": {}, "service_principal": {}, "tenant_id": {}, "user": {}, "user_id": {}, "user_token": {},
	"clientid": {}, "organizationid": {}, "orgid": {}, "principalid": {}, "serviceprincipal": {}, "tenantid": {}, "userid": {},
}

func init() {
	for _, key := range governedModelReservedPlatformContextKeys {
		governedModelReservedContextKeys[key] = struct{}{}
	}
}

func governedModelIdentityKey(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	_, reserved := governedModelReservedContextKeys[value]
	return reserved
}

func governedModelContextCarriesIdentity(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if governedModelIdentityKey(key) {
				return key, true
			}
			if key, found := governedModelContextCarriesIdentity(nested); found {
				return key, true
			}
		}
	case []any:
		for _, nested := range typed {
			if key, found := governedModelContextCarriesIdentity(nested); found {
				return key, true
			}
		}
	}
	return "", false
}

// governedModelRequestHandler is a narrow authenticated adapter over the
// existing /api/request governance pipeline. It does not add a provider path,
// policy engine, budget store or usage ledger. It removes body-carried identity,
// admits only the existing subject-bound internal-service credential, fixes the
// request type to llm_chat, and lets clientRequestHandler perform the canonical
// request/response decisions, budget check, Orchestrator call and usage write.
func governedModelRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(serviceauth.SubjectHeader) == "" || internalServiceHints(r) == nil {
		writeJSONError(w, "Subject-bound internal service authentication is required", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, governedModelBodyLimit+1))
	if err != nil {
		writeJSONError(w, "Invalid governed model request", http.StatusBadRequest)
		return
	}
	if len(body) > governedModelBodyLimit {
		writeJSONError(w, "Governed model request body exceeds 1000000 bytes", http.StatusRequestEntityTooLarge)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var input GovernedModelRequest
	if err := decoder.Decode(&input); err != nil {
		writeJSONError(w, "Invalid governed model request", http.StatusBadRequest)
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		writeJSONError(w, "Invalid governed model request", http.StatusBadRequest)
		return
	}
	input.Query = strings.TrimSpace(input.Query)
	if input.Query == "" || utf8.RuneCountInString(input.Query) > governedModelQueryLimit {
		writeJSONError(w, "query is required and must not exceed 100000 characters", http.StatusBadRequest)
		return
	}
	if key, found := governedModelContextCarriesIdentity(input.Context); found {
		writeJSONError(w, fmt.Sprintf("context key %q is reserved for authenticated identity", key), http.StatusBadRequest)
		return
	}
	if err := validateGovernedModelCorrelation(input.Correlation); err != nil {
		writeJSONError(w, "Invalid governed model correlation: "+err.Error(), http.StatusBadRequest)
		return
	}

	encoded, err := json.Marshal(ClientRequest{
		Query: input.Query, RequestType: "llm_chat", Context: input.Context,
	})
	if err != nil {
		writeJSONError(w, "Invalid governed model request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	r.ContentLength = int64(len(encoded))
	ctx := context.WithValue(r.Context(), governedModelContextKey{}, true)
	ctx = context.WithValue(ctx, governedModelCorrelationContextKey{}, *input.Correlation)
	r = r.WithContext(ctx)
	clientRequestHandler(w, r)
}

// governedModelStatusHandler exposes only the authenticated tenant's durable
// receipt. It also reconciles stale pre-forward intents to outcome_unknown so a
// restarted Hosted worker can freeze the attempt instead of spending twice.
func governedModelStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(serviceauth.SubjectHeader) == "" || internalServiceHints(r) == nil {
		writeJSONError(w, "Subject-bound internal service authentication is required", http.StatusUnauthorized)
		return
	}
	values := r.URL.Query()
	requestID := values.Get("request_id")
	if len(values) != 1 || len(values["request_id"]) != 1 {
		writeJSONError(w, "request_id is required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(requestID); err != nil {
		writeJSONError(w, "request_id must be a UUID", http.StatusBadRequest)
		return
	}
	auth, authErr := Authenticate(r, internalServiceHints(r))
	if authErr != nil || auth == nil || auth.Client == nil {
		writeJSONError(w, "Valid internal service authentication is required", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))
	client := auth.Client
	if costService == nil {
		writeJSONError(w, "Governed model attempt journal unavailable", http.StatusServiceUnavailable)
		return
	}
	lookupContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), governedModelUsageCommitTimeout)
	defer cancel()
	attempt, err := costService.GetGovernedModelAttempt(
		lookupContext, client.OrgID, client.TenantID, requestID, governedModelForwardStaleAfter)
	if err != nil {
		// The scoped lookup deliberately does not distinguish missing from another
		// tenant's row; this route must not become an existence oracle.
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, "Governed model attempt not found", http.StatusNotFound)
		} else {
			writeJSONError(w, "Governed model attempt journal unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	principal := authenticatedPrincipalFor(auth, client, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_id": attempt.RequestID, "trace_id": attempt.TraceID, "status": attempt.Status,
		"module": attempt.Module, "case_id": attempt.CaseID,
		"evidence_version": attempt.EvidenceVersion, "investigation_key": attempt.InvestigationKey,
		"provider_info": attempt.ProviderInfo, "usage_receipt": attempt.UsageReceipt,
		"authenticated_principal": principal,
	})
}

// governedModelReadinessHandler proves the authenticated client-to-Agent seam
// and its durable tenant-scoped recovery journal without forwarding to the
// Orchestrator or provider. It is read-only, non-spending, and restart-safe.
func governedModelReadinessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(serviceauth.SubjectHeader) == "" || internalServiceHints(r) == nil {
		writeJSONError(w, "Subject-bound internal service authentication is required", http.StatusUnauthorized)
		return
	}
	values := r.URL.Query()
	module := values.Get("module")
	if len(values) != 1 || len(values["module"]) != 1 ||
		(module != "payment_exception" && module != "support_refund") {
		writeJSONError(w, "module must be payment_exception or support_refund", http.StatusBadRequest)
		return
	}
	auth, authErr := Authenticate(r, internalServiceHints(r))
	if authErr != nil || auth == nil || auth.Client == nil {
		writeJSONError(w, "Valid internal service authentication is required", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))
	if costService == nil {
		writeJSONError(w, "Governed model attempt journal unavailable", http.StatusServiceUnavailable)
		return
	}
	checkContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), governedModelUsageCommitTimeout)
	defer cancel()
	if err := costService.CheckGovernedModelAttemptJournal(
		checkContext, auth.Client.OrgID, auth.Client.TenantID); err != nil {
		writeJSONError(w, "Governed model attempt journal unavailable", http.StatusServiceUnavailable)
		return
	}
	principal := authenticatedPrincipalFor(auth, auth.Client, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"operational": true, "spending": false, "journal_ready": true,
		"contract": "agent-governed-model-v1", "route": "/api/v1/governed/model",
		"module": module, "authenticated_principal": principal,
	})
}

func authenticatedPrincipalFor(auth *AuthResult, client *Client, r *http.Request) AuthenticatedPrincipalInfo {
	principal := AuthenticatedPrincipalInfo{}
	if auth != nil {
		principal.Kind = auth.Kind.String()
	}
	if client != nil {
		principal.PrincipalID = client.ClientID
		principal.OrganizationID = client.OrgID
		principal.TenantID = client.TenantID
	}
	// A successful subject-bearing internal-service authentication can only be
	// authenticateHostedOutcomeDelegation. Parse the already verified canonical
	// subject to expose the actual service identity, never a context/body claim.
	if auth != nil && auth.Kind == AuthKindInternalService && r.Header.Get(serviceauth.SubjectHeader) != "" {
		if delegated, err := parseHostedOutcomeDelegation(r.Header.Get(serviceauth.SubjectHeader)); err == nil {
			principal.PrincipalID = delegated.Service
		}
	}
	return principal
}

func modelProviderInfo(response map[string]any) (map[string]any, string, string, int, float64, bool) {
	if response == nil {
		return nil, "", "", 0, 0, false
	}
	raw, exists := response["provider_info"]
	if !exists || raw == nil {
		return nil, "", "", 0, 0, false
	}
	info, ok := raw.(map[string]any)
	if !ok {
		return nil, "", "", 0, 0, true
	}
	provider, _ := info["provider"].(string)
	model, _ := info["model"].(string)
	tokens := 0
	switch value := info["tokens_used"].(type) {
	case float64:
		tokens = int(value)
	case int:
		tokens = value
	case json.Number:
		parsed, _ := value.Int64()
		tokens = int(parsed)
	}
	costUSD := 0.0
	switch value := info["cost"].(type) {
	case float64:
		costUSD = value
	case json.Number:
		costUSD, _ = value.Float64()
	}
	copyInfo := make(map[string]any, len(info))
	for key, value := range info {
		copyInfo[key] = value
	}
	return copyInfo, provider, model, tokens, costUSD, true
}

// recordCanonicalModelUsage writes the existing cost ledger. In strict mode a
// provider attempt is recorded even when tokens/cost are zero and even when the
// Orchestrator reports a post-provider governance/shape failure. This is an
// extension of the canonical ledger, not a module-specific parallel receipt.
func recordCanonicalModelUsage(ctx context.Context, response map[string]any, requestID string,
	client *Client, user *User, strict bool) (map[string]any, ModelUsageReceipt, error) {
	info, provider, model, tokens, costUSD, attempted := modelProviderInfo(response)
	receipt := ModelUsageReceipt{Attempted: attempted, RequestID: requestID, Status: "not_attempted"}
	if !attempted {
		return nil, receipt, nil
	}
	receipt.Status = "attempted_unrecorded"
	if strict && (provider == "" || model == "" || tokens < 0 || costUSD < 0) {
		return info, receipt, fmt.Errorf("provider attempt metadata is incomplete")
	}
	if costService == nil {
		if strict {
			return info, receipt, fmt.Errorf("canonical usage ledger is unavailable")
		}
		return info, receipt, nil
	}
	if !strict && tokens == 0 && costUSD == 0 {
		return info, receipt, nil
	}
	userID := ""
	tenantID := ""
	orgID := ""
	if user != nil {
		userID = fmt.Sprintf("%d", user.ID)
		tenantID = user.TenantID
	}
	if client != nil {
		orgID = client.OrgID
		if tenantID == "" {
			tenantID = client.TenantID
		}
	}
	record := &cost.UsageRecord{
		RequestID: requestID, Timestamp: time.Now().UTC(), OrgID: orgID, TenantID: tenantID, UserID: userID,
		Provider: provider, Model: model, TokensIn: tokens / 2,
		TokensOut: tokens - tokens/2, CostUSD: costUSD, RequestType: "completion",
	}
	// Provider spend exists even if the caller disconnects after the provider
	// answers. Preserve auth/RLS values while detaching cancellation, and keep
	// the synchronous commit bounded so the route cannot hang indefinitely.
	commitContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), governedModelUsageCommitTimeout)
	defer cancel()
	if err := costService.RecordUsage(commitContext, record); err != nil {
		receipt.Status = "record_failed"
		return info, receipt, fmt.Errorf("record canonical model usage: %w", err)
	}
	receipt.Recorded = true
	receipt.Status = "recorded"
	return info, receipt, nil
}
