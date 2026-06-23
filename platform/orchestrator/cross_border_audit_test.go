//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// ---------------------------------------------------------------------------
// Precedence: per-request > per-org > global default; invalid rejected.
// ---------------------------------------------------------------------------

func TestTransferBasisConfig_Resolve_Precedence(t *testing.T) {
	cfg := &transferBasisConfig{
		defaultBasis: "adequacy",
		orgOverrides: map[string]string{"org-buku": "pasal_56b_dpa"},
	}

	cases := []struct {
		name       string
		perRequest string
		orgID      string
		want       string
	}{
		{"global default applied", "", "org-none", "adequacy"},
		{"per-org override beats global", "", "org-buku", "pasal_56b_dpa"},
		{"per-request beats per-org", "consent", "org-buku", "consent"},
		{"per-request beats global", "safeguards", "org-none", "safeguards"},
		{"invalid per-request rejected (no fallthrough)", "not-a-basis", "org-buku", ""},
		{"empty everything", "", "", "adequacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.resolve(tc.perRequest, tc.orgID); got != tc.want {
				t.Errorf("resolve(%q, %q) = %q, want %q", tc.perRequest, tc.orgID, got, tc.want)
			}
		})
	}
}

func TestTransferBasisConfig_Resolve_NoConfigUnset(t *testing.T) {
	cfg := &transferBasisConfig{orgOverrides: map[string]string{}}
	if got := cfg.resolve("", "org-x"); got != "" {
		t.Errorf("with no config the resolver must return \"\" (unstamped), got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Config loading: invalid values are dropped so they cannot shadow a valid
// lower-precedence source.
// ---------------------------------------------------------------------------

func TestLoadTransferBasisConfig_DropsInvalid(t *testing.T) {
	t.Setenv(EnvDefaultTransferBasis, "bogus")                                  // invalid → dropped
	t.Setenv(EnvOrgTransferBasis, "org-good:consent,org-bad:nope,malformed,:x") // mix
	cfg := loadTransferBasisConfig()

	if cfg.defaultBasis != "" {
		t.Errorf("invalid global default should be dropped, got %q", cfg.defaultBasis)
	}
	if cfg.orgOverrides["org-good"] != "consent" {
		t.Errorf("valid org override should load, got %q", cfg.orgOverrides["org-good"])
	}
	if _, ok := cfg.orgOverrides["org-bad"]; ok {
		t.Error("invalid org override (nope) must be dropped")
	}
	if len(cfg.orgOverrides) != 1 {
		t.Errorf("expected exactly 1 valid override, got %d (%v)", len(cfg.orgOverrides), cfg.orgOverrides)
	}
}

func TestLoadTransferBasisConfig_ValidGlobal(t *testing.T) {
	t.Setenv(EnvDefaultTransferBasis, "pasal_56b_dpa")
	t.Setenv(EnvOrgTransferBasis, "")
	cfg := loadTransferBasisConfig()
	if cfg.defaultBasis != "pasal_56b_dpa" {
		t.Errorf("global default = %q, want pasal_56b_dpa", cfg.defaultBasis)
	}
}

// ---------------------------------------------------------------------------
// data_residency derivation per provider.
// ---------------------------------------------------------------------------

func TestResolveDataResidency(t *testing.T) {
	cases := []struct {
		provider string
		want     string
	}{
		{"anthropic", "US"},
		{"anthropic-primary", "US"}, // custom instance name embeds the type
		{"openai", "US"},
		{"gemini", "US"},
		{"google", "US"},
		{"ollama", ""},       // self-hosted → no cross-border residency
		{"mock", ""},         // hourly-test mock
		{"azure-openai", ""}, // region not reliably known at audit time
		{"mistral", ""},      // not fabricated
		{"", ""},
		{"custom-thing", ""},
	}
	for _, tc := range cases {
		if got := resolveDataResidency(tc.provider); got != tc.want {
			t.Errorf("resolveDataResidency(%q) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

func TestResolveDataResidency_BedrockUsesRegion(t *testing.T) {
	t.Setenv("BEDROCK_REGION", "ap-southeast-3") // Jakarta
	if got := resolveDataResidency("bedrock"); got != "ID" {
		t.Errorf("bedrock ap-southeast-3 = %q, want ID", got)
	}
	t.Setenv("BEDROCK_REGION", "us-east-1")
	if got := resolveDataResidency("bedrock"); got != "US" {
		t.Errorf("bedrock us-east-1 = %q, want US", got)
	}
	t.Setenv("BEDROCK_REGION", "")
	if got := resolveDataResidency("bedrock"); got != "" {
		t.Errorf("bedrock with no region = %q, want \"\"", got)
	}
}

func TestAwsRegionCountry(t *testing.T) {
	cases := map[string]string{
		"us-east-1":      "US",
		"us-east-2":      "US",
		"us-west-1":      "US",
		"us-west-2":      "US",
		"us-gov-east-1":  "US",
		"us-gov-west-1":  "US",
		"ca-central-1":   "CA",
		"ca-west-1":      "CA",
		"sa-east-1":      "BR",
		"eu-west-1":      "IE",
		"eu-west-2":      "GB",
		"eu-west-3":      "FR",
		"eu-central-1":   "DE",
		"eu-central-2":   "DE",
		"eu-north-1":     "SE",
		"eu-south-1":     "IT",
		"eu-south-2":     "IT",
		"ap-south-1":     "IN",
		"ap-south-2":     "IN",
		"ap-southeast-1": "SG",
		"ap-southeast-2": "AU",
		"ap-southeast-3": "ID",
		"ap-northeast-1": "JP",
		"ap-northeast-2": "KR",
		"ap-northeast-3": "JP",
		"ap-east-1":      "HK",
		"me-south-1":     "BH",
		"me-central-1":   "AE",
		"af-south-1":     "ZA",
		"US-EAST-1":      "US", // case-insensitive
		"":               "",
		"made-up-region": "",
	}
	for region, want := range cases {
		if got := awsRegionCountry(region); got != want {
			t.Errorf("awsRegionCountry(%q) = %q, want %q", region, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// perRequestTransferBasis extraction from request context.
// ---------------------------------------------------------------------------

func TestPerRequestTransferBasis(t *testing.T) {
	if got := perRequestTransferBasis(OrchestratorRequest{}); got != "" {
		t.Errorf("nil context = %q, want \"\"", got)
	}
	req := OrchestratorRequest{Context: map[string]interface{}{"transfer_basis": "consent"}}
	if got := perRequestTransferBasis(req); got != "consent" {
		t.Errorf("context value = %q, want consent", got)
	}
	reqNonString := OrchestratorRequest{Context: map[string]interface{}{"transfer_basis": 42}}
	if got := perRequestTransferBasis(reqNonString); got != "" {
		t.Errorf("non-string context value = %q, want \"\"", got)
	}
}

// ---------------------------------------------------------------------------
// stampCrossBorderTransferImpl: sets both fields when a basis resolves, leaves
// them empty otherwise.
// ---------------------------------------------------------------------------

func TestStampCrossBorderTransferImpl(t *testing.T) {
	t.Cleanup(resetTransferBasisConfigForTest)
	setTransferBasisConfigForTest(&transferBasisConfig{
		defaultBasis: "pasal_56b_dpa",
		orgOverrides: map[string]string{},
	})

	entry := &AuditEntry{}
	req := OrchestratorRequest{Client: ClientContext{OrgID: "org-x"}}
	stampCrossBorderTransferImpl(entry, req, &ProviderInfo{Provider: "anthropic"})
	if entry.TransferBasis != "pasal_56b_dpa" {
		t.Errorf("transfer_basis = %q, want pasal_56b_dpa", entry.TransferBasis)
	}
	if entry.DataResidency != "US" {
		t.Errorf("data_residency = %q, want US", entry.DataResidency)
	}

	// No declared basis → both left empty (row not a tracked transfer).
	setTransferBasisConfigForTest(&transferBasisConfig{orgOverrides: map[string]string{}})
	entry2 := &AuditEntry{}
	stampCrossBorderTransferImpl(entry2, req, &ProviderInfo{Provider: "anthropic"})
	if entry2.TransferBasis != "" || entry2.DataResidency != "" {
		t.Errorf("unset config must leave both empty, got basis=%q residency=%q", entry2.TransferBasis, entry2.DataResidency)
	}
}

// TestStampCrossBorderTransferImpl_SkipLLMNotStamped: the synthetic hourly-test
// path (SkipLLM, mock provider, no real forward) must never be stamped as a
// cross-border transfer, even with a basis configured.
func TestStampCrossBorderTransferImpl_SkipLLMNotStamped(t *testing.T) {
	t.Cleanup(resetTransferBasisConfigForTest)
	setTransferBasisConfigForTest(&transferBasisConfig{
		defaultBasis: "pasal_56b_dpa",
		orgOverrides: map[string]string{},
	})
	entry := &AuditEntry{}
	req := OrchestratorRequest{SkipLLM: true, Client: ClientContext{OrgID: "org-x"}}
	stampCrossBorderTransferImpl(entry, req, &ProviderInfo{Provider: "mock"})
	if entry.TransferBasis != "" || entry.DataResidency != "" {
		t.Errorf("SkipLLM must not be stamped, got basis=%q residency=%q", entry.TransferBasis, entry.DataResidency)
	}
}

// TestLogBlockedResponse_AutoStampsCrossBorder proves the response-plane block
// path (a completed forward whose response is withheld) also carries the
// cross-border stamp, so a blocked-response transfer is not under-reported.
func TestLogBlockedResponse_AutoStampsCrossBorder(t *testing.T) {
	t.Cleanup(resetTransferBasisConfigForTest)
	setTransferBasisConfigForTest(&transferBasisConfig{
		defaultBasis: "pasal_56b_dpa",
		orgOverrides: map[string]string{},
	})

	l := &AuditLogger{auditQueue: make(chan *AuditEntry, 10)}
	req := OrchestratorRequest{
		RequestID:   "req-blk-cb",
		RequestType: "completion",
		Query:       "hi",
		User:        UserContext{ID: 1, Email: "u@example.com", Role: "user", TenantID: "tenant-1"},
		Client:      ClientContext{ID: "client-1", OrgID: "org-x"},
	}
	pr := &PolicyEvaluationResult{Allowed: false, AppliedPolicies: []string{"resp_validation"}}
	info := &RedactionInfo{Verdict: responseVerdictBlocked, ValidationError: "blocked"}
	pi := &ProviderInfo{Provider: "anthropic"}

	entry := l.LogBlockedResponse(context.Background(), req, pr, info, pi)
	if entry == nil {
		t.Fatal("nil entry")
	}
	if entry.TransferBasis != "pasal_56b_dpa" {
		t.Errorf("blocked-response transfer_basis = %q, want pasal_56b_dpa", entry.TransferBasis)
	}
	if entry.DataResidency != "US" {
		t.Errorf("blocked-response data_residency = %q, want US", entry.DataResidency)
	}
}

// TestLogSuccessfulRequest_AutoStampsCrossBorder proves the stamp hook is wired
// into the real LLM-forward call site: LogSuccessfulRequest returns an entry
// carrying the resolved basis + derived residency.
func TestLogSuccessfulRequest_AutoStampsCrossBorder(t *testing.T) {
	t.Cleanup(resetTransferBasisConfigForTest)
	setTransferBasisConfigForTest(&transferBasisConfig{
		defaultBasis: "pasal_56b_dpa",
		orgOverrides: map[string]string{},
	})

	l := &AuditLogger{auditQueue: make(chan *AuditEntry, 10)}
	req := OrchestratorRequest{
		RequestID:   "req-cb-1",
		RequestType: "completion",
		Query:       "hello",
		User:        UserContext{ID: 1, Email: "u@example.com", Role: "user", TenantID: "tenant-1"},
		Client:      ClientContext{ID: "client-1", OrgID: "org-x"},
	}
	pr := &PolicyEvaluationResult{Allowed: true, AppliedPolicies: []string{}}
	pi := &ProviderInfo{Provider: "anthropic", Model: "claude-opus-4-8"}

	entry := l.LogSuccessfulRequest(context.Background(), req, "ok", pr, pi)
	if entry == nil {
		t.Fatal("nil entry")
	}
	if entry.TransferBasis != "pasal_56b_dpa" {
		t.Errorf("forward-path transfer_basis = %q, want pasal_56b_dpa", entry.TransferBasis)
	}
	if entry.DataResidency != "US" {
		t.Errorf("forward-path data_residency = %q, want US", entry.DataResidency)
	}
}

// TestBatchWriter_WritesCrossBorderColumns is a red-on-revert guard on the
// INSERT column wiring: the stamped transfer_basis + data_residency must be the
// 28th + 29th bind args. If a refactor drops the columns from the INSERT, the
// arg count (or the matched values) no longer line up and this fails.
func TestBatchWriter_WritesCrossBorderColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	any := sqlmock.AnyArg()
	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO audit_logs")
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			any, any, any, any, any, any, any, any, any, // 1-9
			any, any, any, any, any, any, any, any, any, // 10-18
			any, any, any, any, any, any, any, any, any, // 19-27 (incl decision_id, plane, correlation_id)
			"pasal_56b_dpa", "US", // 28 transfer_basis, 29 data_residency
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	bw := &BatchWriter{db: db, batchSize: 1}
	entry := &AuditEntry{
		ID: "a1", RequestID: "r1", Timestamp: time.Now().UTC(),
		UserID: 1, UserEmail: "u@example.com", UserRole: "user",
		ClientID: "c1", TenantID: "t1", OrgID: "org-x",
		RequestType: "completion", Query: "q", QueryHash: "h",
		PolicyDecision: "allowed",
		TransferBasis:  "pasal_56b_dpa",
		DataResidency:  "US",
	}
	if err := bw.Write([]*AuditEntry{entry}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
