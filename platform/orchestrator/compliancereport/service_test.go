// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/tenantscope"
)

// -----------------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------------

func TestCreateReport_CompletesAndStoresAChecksummedArtifact(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	if job.Status != StatusCompleted {
		t.Fatalf("status = %s (error=%q), want completed", job.Status, job.Error)
	}
	if job.ReportState != ReportStatePopulated {
		t.Errorf("report_state = %q, want populated", job.ReportState)
	}
	if job.Progress != 100 {
		t.Errorf("progress = %d, want 100", job.Progress)
	}
	if job.Checksum == "" {
		t.Error("completed job carries no checksum")
	}
	if job.StorageKey == "" {
		t.Fatal("completed job carries no storage key")
	}
	artifact, ok := h.storage.object(job.StorageKey)
	if !ok {
		t.Fatalf("no artifact stored at %s", job.StorageKey)
	}
	if job.SizeBytes != int64(len(artifact)) {
		t.Errorf("size_bytes = %d, stored artifact is %d bytes", job.SizeBytes, len(artifact))
	}
	if !strings.Contains(string(artifact), "axonflow.compliance-report/v1") {
		t.Errorf("stored artifact is not the JSON report envelope: %s", truncate(string(artifact)))
	}
}

// TestCreateReport_EmptyPeriodIsATruthfulReport pins that an org with no
// activity gets a real, downloadable artifact carrying `enabled_empty` - not a
// failure and not an empty 200. A "no governed activity in range" attestation
// is a valid regulatory artifact.
func TestCreateReport_EmptyPeriodIsATruthfulReport(t *testing.T) {
	h := newHarness(t, emptyProvider(RegulatorSEBI))

	job := h.runToCompletion(t, validRequest(RegulatorSEBI, FormatCSV))

	if job.Status != StatusCompleted {
		t.Fatalf("status = %s (error=%q), want completed", job.Status, job.Error)
	}
	if job.ReportState != ReportStateEnabledEmpty {
		t.Errorf("report_state = %q, want enabled_empty", job.ReportState)
	}
	if job.RecordCount != 0 {
		t.Errorf("record_count = %d, want 0", job.RecordCount)
	}
	if _, ok := h.storage.object(job.StorageKey); !ok {
		t.Error("an empty report must still be downloadable")
	}
}

// TestCreateReport_ReportStateIsUndeterminedUntilTerminal pins the field's
// meaning at create time: the data state is genuinely unknown, and guessing one
// of the three real values would be a claim about whether the org has data.
func TestCreateReport_ReportStateIsUndeterminedUntilTerminal(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorRBI))

	created, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorRBI, FormatJSON), "tester")
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	if created.Status != StatusPending {
		t.Errorf("create response status = %s, want pending", created.Status)
	}
	if created.ReportState != ReportStateUndetermined {
		t.Errorf("create response report_state = %q, want the undetermined (empty) value", created.ReportState)
	}
	h.svc.WaitForProcessing()
}

// TestTerminalJobNeverCarriesUndeterminedState is the invariant named in the
// ReportStateUndetermined doc comment, and the one migration 136's
// compliance_report_jobs_completed_is_complete CHECK enforces in the database.
func TestTerminalJobNeverCarriesUndeterminedState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider *fakeProvider
	}{
		{"populated", populatedProvider(RegulatorMASFEAT)},
		{"empty", emptyProvider(RegulatorMASFEAT)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.provider)
			job := h.runToCompletion(t, validRequest(RegulatorMASFEAT, FormatJSON))
			if job.Status != StatusCompleted {
				t.Fatalf("status = %s, want completed", job.Status)
			}
			if !job.ReportState.Valid() {
				t.Errorf("completed job carries report_state %q, which is not one of the three terminal states", job.ReportState)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// The storage-failure invariant
// -----------------------------------------------------------------------------

// TestProcessJob_NoStorageBackendFailsTheJob is the trap the EU AI Act export
// precedent falls into: it marks an export `completed` with no storage backend
// configured, leaving a permanently undownloadable success
// (euaiact/export_service.go finalizeExportPayload returns nil when
// storageBackend == nil). A completed report MUST mean a stored artifact.
func TestProcessJob_NoStorageBackendFailsTheJob(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorOJK))
	h.svc.storage = nil

	job := h.runToCompletion(t, validRequest(RegulatorOJK, FormatJSON))

	if job.Status != StatusFailed {
		t.Fatalf("status = %s, want failed when no storage backend is configured", job.Status)
	}
	// The error must name a cause this process can actually observe and act on.
	for _, want := range []string{"storage backend", "AUDIT_EXPORT_STORAGE_TYPE"} {
		if !strings.Contains(job.Error, want) {
			t.Errorf("failure message does not mention %q: %s", want, job.Error)
		}
	}
	if job.StorageKey != "" || job.Checksum != "" {
		t.Errorf("failed job claims an artifact: storage_key=%q checksum=%q", job.StorageKey, job.Checksum)
	}
}

// TestProcessJob_UploadFailureFailsTheJob is the same invariant for a backend
// that exists but refuses the write.
func TestProcessJob_UploadFailureFailsTheJob(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorOJK))
	h.storage.uploadErr = errors.New("bucket policy denied PutObject")

	job := h.runToCompletion(t, validRequest(RegulatorOJK, FormatJSON))

	if job.Status != StatusFailed {
		t.Fatalf("status = %s, want failed when the artifact cannot be stored", job.Status)
	}
	// INVERTED in #3241 round 2 (M3). This used to require the backend's raw
	// error text in the caller-visible message, which is exactly the leak: the
	// real ones carry the bucket name, the object key, the region endpoint and
	// the SDK operation. The caller gets the stage; the log gets the cause.
	if strings.Contains(job.Error, "bucket policy denied PutObject") {
		t.Errorf("the caller-visible failure message carries the storage backend's raw error: %s", job.Error)
	}
	if !strings.Contains(job.Error, "could not be stored") {
		t.Errorf("failure message does not say what happened: %s", job.Error)
	}
	if job.StorageKey != "" {
		t.Errorf("failed job claims a storage key %q", job.StorageKey)
	}
}

// TestProcessJob_ProviderErrorFailsTheJob pins that a data-collection failure is
// a failure, never a silently empty report. An empty report is an assertion
// that the org had no activity.
func TestProcessJob_ProviderErrorFailsTheJob(t *testing.T) {
	p := populatedProvider(RegulatorSEBI)
	p.fetchErr = errors.New("audit_logs query timed out")
	h := newHarness(t, p)

	job := h.runToCompletion(t, validRequest(RegulatorSEBI, FormatJSON))

	if job.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", job.Status)
	}
	// INVERTED in #3241 round 2 (M3), same reason as the upload case above:
	// a provider's raw error is driver text and names tables.
	if strings.Contains(job.Error, "audit_logs") {
		t.Errorf("the caller-visible failure message names an internal table: %s", job.Error)
	}
	if !strings.Contains(job.Error, "collecting compliance data") {
		t.Errorf("failure message does not say what happened: %s", job.Error)
	}
	if _, ok := h.storage.object(StorageKeyFor(job, "json")); ok {
		t.Error("a failed job stored an artifact")
	}
}

// TestProcessJob_ProviderTurningUnavailableSetsNotAvailable pins the one
// failure mode that HAS a nameable data state.
func TestProcessJob_ProviderTurningUnavailableSetsNotAvailable(t *testing.T) {
	p := populatedProvider(RegulatorOJK)
	p.result = &ProviderResult{State: ReportStateNotAvailable}
	h := newHarness(t, p)

	job := h.runToCompletion(t, validRequest(RegulatorOJK, FormatJSON))

	if job.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", job.Status)
	}
	if job.ReportState != ReportStateNotAvailable {
		t.Errorf("report_state = %q, want not_available", job.ReportState)
	}
}

// -----------------------------------------------------------------------------
// Gates
// -----------------------------------------------------------------------------

func TestCreateReport_RefusesAnUnwiredRegulator(t *testing.T) {
	// Only EU AI Act is registered; OJK is not.
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorOJK, FormatJSON), "tester")

	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeNotAvailable {
		t.Fatalf("err = %v, want a RequestError with code %s", err, ErrCodeNotAvailable)
	}
	if len(h.repo.jobs) != 0 {
		t.Errorf("a refused create persisted %d job(s)", len(h.repo.jobs))
	}
}

func TestCreateReport_UnderTierIsRefusedWithADistinctCode(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.exportEnabled = false
	h.lic.tier = license.TierCommunity

	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester")

	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeLicenseRequired {
		t.Fatalf("err = %v, want a RequestError with code %s", err, ErrCodeLicenseRequired)
	}
	if reqErr.Code == ErrCodeRateLimitExceeded {
		t.Error("the tier refusal and the rate-limit refusal must not share a code")
	}
	if !strings.Contains(reqErr.Message, "evaluation-license") {
		t.Errorf("the upsell message has no way for the operator to act on it: %s", reqErr.Message)
	}
}

func TestCreateReport_OverRateLimitIsRefusedWithADistinctCode(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.maxPerDay = 1

	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester")
	h.svc.WaitForProcessing()

	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeRateLimitExceeded {
		t.Fatalf("second create err = %v, want a RequestError with code %s", err, ErrCodeRateLimitExceeded)
	}
	if !strings.Contains(reqErr.Message, "1/1") {
		t.Errorf("the limit message does not state the budget: %s", reqErr.Message)
	}
}

// TestCreateReport_ARefusalDoesNotBurnARateLimitSlot pins the ordering in
// CreateReport: a request refused for a BAD REQUEST, a TIER or an UNWIRED
// MODULE must not consume a slot, or a caller can exhaust its own daily budget
// on mistakes it has not yet learned to stop making.
func TestCreateReport_ARefusalDoesNotBurnARateLimitSlot(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.maxPerDay = 1

	// A malformed request, then an unwired regulator: neither should count.
	bad := validRequest(RegulatorEUAIAct, FormatJSON)
	bad.PeriodEnd = bad.PeriodStart
	if _, err := h.svc.CreateReport(context.Background(), testScope(), bad, "tester"); err == nil {
		t.Fatal("expected a validation refusal")
	}
	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorOJK, FormatJSON), "tester"); err == nil {
		t.Fatal("expected an unwired-regulator refusal")
	}

	// The one good request must still be allowed.
	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester"); err != nil {
		t.Fatalf("the refusals consumed the budget: %v", err)
	}
	h.svc.WaitForProcessing()
}

func TestCreateReport_RequiresABoundScope(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	for _, scope := range []tenantscope.Scope{
		{},
		{OrgID: "acme-org"},
		{TenantID: "acme-tenant"},
		{OrgID: tenantscope.UnownedOrgSentinel, TenantID: "acme-tenant"},
	} {
		_, err := h.svc.CreateReport(context.Background(), scope, validRequest(RegulatorEUAIAct, FormatJSON), "tester")
		if !errors.Is(err, tenantscope.ErrNoCallerScope) {
			t.Errorf("scope %+v: err = %v, want ErrNoCallerScope", scope, err)
		}
	}
	if len(h.repo.jobs) != 0 {
		t.Errorf("an unscoped create persisted %d job(s)", len(h.repo.jobs))
	}
}

// -----------------------------------------------------------------------------
// By-id authorization
// -----------------------------------------------------------------------------

// TestGetJob_CrossOrgIsRefused is the class this whole change also fixes in
// euaiact: naming another organization's job id must not resolve.
func TestGetJob_CrossOrgIsRefused(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	attacker := tenantscope.Scope{OrgID: "attacker-org", TenantID: "attacker-tenant"}
	got, err := h.svc.GetJob(context.Background(), attacker, job.ID)
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("cross-org GetJob: err = %v (job=%+v), want ErrJobNotFound", err, got)
	}
}

// TestGetJob_CrossTenantWithinTheSameOrgIsRefused is the SECOND dimension, and
// the reason the service calls tenantscope.Authorize on top of the repository's
// org predicate. Under a single enterprise license org_id and tenant_id are
// different values (#3071), so an org-only check is not a customer boundary.
func TestGetJob_CrossTenantWithinTheSameOrgIsRefused(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	sibling := tenantscope.Scope{OrgID: testScope().OrgID, TenantID: "other-tenant"}
	got, err := h.svc.GetJob(context.Background(), sibling, job.ID)
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("cross-tenant GetJob: err = %v (job=%+v), want ErrJobNotFound", err, got)
	}
}

// TestGetJob_OwnerSucceeds is the vacuity control for the two above.
func TestGetJob_OwnerSucceeds(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	got, err := h.svc.GetJob(context.Background(), testScope(), job.ID)
	if err != nil {
		t.Fatalf("owner GetJob: %v", err)
	}
	if got.ID != job.ID {
		t.Errorf("got job %s, want %s", got.ID, job.ID)
	}
}

// -----------------------------------------------------------------------------
// Download
// -----------------------------------------------------------------------------

func TestDownloadURL_PresignsACompletedJob(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	url, got, err := h.svc.DownloadURL(context.Background(), testScope(), job.ID)
	if err != nil {
		t.Fatalf("DownloadURL: %v", err)
	}
	if !strings.Contains(url, job.StorageKey) {
		t.Errorf("presigned URL %q does not reference the job's storage key %q", url, job.StorageKey)
	}
	if !strings.Contains(url, "1h0m0s") {
		t.Errorf("presigned URL does not carry the 1h TTL: %s", url)
	}
	if got.ID != job.ID {
		t.Errorf("DownloadURL returned job %s, want %s", got.ID, job.ID)
	}
}

func TestDownloadURL_RefusesAnIncompleteJob(t *testing.T) {
	p := populatedProvider(RegulatorEUAIAct)
	p.fetchErr = errors.New("boom")
	h := newHarness(t, p)
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	_, _, err := h.svc.DownloadURL(context.Background(), testScope(), job.ID)
	if !errors.Is(err, ErrNotCompleted) {
		t.Fatalf("err = %v, want ErrNotCompleted", err)
	}
}

func TestDownloadURL_CrossOrgIsRefused(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	attacker := tenantscope.Scope{OrgID: "attacker-org", TenantID: "attacker-tenant"}
	url, _, err := h.svc.DownloadURL(context.Background(), attacker, job.ID)
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("cross-org DownloadURL: err = %v url=%q, want ErrJobNotFound", err, url)
	}
	if url != "" {
		t.Errorf("cross-org DownloadURL minted a URL: %s", url)
	}
}

// -----------------------------------------------------------------------------
// Scope plumbing
// -----------------------------------------------------------------------------

// TestProviderReceivesBothTenancyKeys pins that the service hands the provider
// BOTH keys rather than deriving one from the other. The five modules disagree
// about which one they scope on - euaiact/rbi/masfeat take an orgID, sebi/ojk
// take a tenantID - and under a single enterprise license they are different
// values, so a provider given only one would read the wrong rows.
func TestProviderReceivesBothTenancyKeys(t *testing.T) {
	p := populatedProvider(RegulatorEUAIAct)
	h := newHarness(t, p)

	req := validRequest(RegulatorEUAIAct, FormatJSON)
	h.runToCompletion(t, req)

	got := p.lastRequest()
	if got.OrgID != testScope().OrgID {
		t.Errorf("provider got OrgID %q, want %q", got.OrgID, testScope().OrgID)
	}
	if got.TenantID != testScope().TenantID {
		t.Errorf("provider got TenantID %q, want %q", got.TenantID, testScope().TenantID)
	}
	if !got.PeriodStart.Equal(req.PeriodStart.UTC()) || !got.PeriodEnd.Equal(req.PeriodEnd.UTC()) {
		t.Errorf("provider got period %s..%s, want %s..%s",
			got.PeriodStart, got.PeriodEnd, req.PeriodStart.UTC(), req.PeriodEnd.UTC())
	}
}

// TestStorageKeyIsOrgPrefixedAndUnique pins the object key shape: a bucket
// policy can be written per organization, and a re-run never overwrites an
// artifact an auditor may already hold.
func TestStorageKeyIsOrgPrefixedAndUnique(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	first := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))
	second := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	if !strings.HasPrefix(first.StorageKey, "compliance-reports/"+testScope().OrgID+"/") {
		t.Errorf("storage key %q is not organization-prefixed", first.StorageKey)
	}
	if first.StorageKey == second.StorageKey {
		t.Errorf("two reports share the storage key %q - the second overwrote the first", first.StorageKey)
	}
}

// TestRenderedArtifactChecksumMatchesTheStoredBytes pins that the recorded
// digest is a digest OF THE STORED OBJECT, not of some intermediate value.
func TestRenderedArtifactChecksumMatchesTheStoredBytes(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	artifact, ok := h.storage.object(job.StorageKey)
	if !ok {
		t.Fatalf("no artifact at %s", job.StorageKey)
	}
	if got := sha256Hex(artifact); got != job.Checksum {
		t.Errorf("recorded checksum %s does not match the stored bytes (%s)", job.Checksum, got)
	}
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// -----------------------------------------------------------------------------
// Rate-limit accounting (R3 round 1)
// -----------------------------------------------------------------------------

// TestCreateReport_APersistFailureReleasesTheSlot pins that a consumed slot
// always corresponds to a job that exists.
//
// Without the release, a database blip during three creates would burn an
// Evaluation tenant's entire daily budget on three 500s and then answer
// "3/3 for this organization" for the rest of the UTC day - a lockout whose
// message is also a lie about what the tenant received.
func TestCreateReport_APersistFailureReleasesTheSlot(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.maxPerDay = 1
	h.repo.createErr = errors.New("connection refused")

	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester"); err == nil {
		t.Fatal("expected the persist failure to surface")
	}

	// The budget must be intact: the single allowed report is still available.
	h.repo.createErr = nil
	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester"); err != nil {
		t.Fatalf("the failed create consumed the daily budget: %v", err)
	}
	h.svc.WaitForProcessing()

	// ...and the budget is genuinely 1, so the assertion above is not vacuous.
	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester")
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeRateLimitExceeded {
		t.Fatalf("third create err = %v, want the limit to fire", err)
	}
}

// TestCreateReport_TheDurableCountIsAFloor pins the half of the budget that
// survives a restart. The in-process counter starts at zero on a fresh replica;
// the stored count must still refuse.
func TestCreateReport_TheDurableCountIsAFloor(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.maxPerDay = 2

	// Two jobs already recorded TODAY by some other replica, with this process
	// having counted none.
	for _, id := range []string{"creport-prior-1", "creport-prior-2"} {
		job := &ReportJob{
			ID: id, OrgID: testScope().OrgID, TenantID: testScope().TenantID,
			Regulator: RegulatorEUAIAct, Framework: FrameworkEUAIAct, Format: FormatJSON,
			PeriodStart: fixedNow.AddDate(0, -1, 0), PeriodEnd: fixedNow,
			Status: StatusCompleted, ReportState: ReportStatePopulated, CreatedAt: fixedNow,
		}
		if err := h.repo.Create(context.Background(), job); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester")
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeRateLimitExceeded {
		t.Fatalf("err = %v, want the durable count to refuse a fresh in-process counter", err)
	}
	if !strings.Contains(reqErr.Message, "2/2") {
		t.Errorf("the refusal does not report the durable count: %s", reqErr.Message)
	}
}

// TestCreateReport_ADurableCountReadFailureFailsClosed pins the direction of
// that failure, which an earlier revision had backwards.
//
// Falling back to the in-process counter looks kinder, but it fails open in
// exactly the case the durable count exists for: on a freshly started replica
// that counter is ZERO, so an unreadable count hands the tenant an entirely
// fresh daily budget. CountSince is a range scan over a growing table, so a
// statement timeout is a plausible steady state rather than a blip.
func TestCreateReport_ADurableCountReadFailureFailsClosed(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))
	h.lic.maxPerDay = 1
	h.repo.countErr = errors.New("statement timeout")

	_, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester")
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeInternal {
		t.Fatalf("err = %v, want a %s RequestError - an unreadable budget must refuse, not fall back to a zeroed counter", err, ErrCodeInternal)
	}
	if len(h.repo.jobs) != 0 {
		t.Errorf("a refused create persisted %d job(s)", len(h.repo.jobs))
	}
	// And no slot was consumed, so the tenant is not penalised for our outage.
	h.repo.countErr = nil
	if _, err := h.svc.CreateReport(context.Background(), testScope(), validRequest(RegulatorEUAIAct, FormatJSON), "tester"); err != nil {
		t.Fatalf("the refused create consumed the budget: %v", err)
	}
	h.svc.WaitForProcessing()
}

// -----------------------------------------------------------------------------
// Stranded jobs (R3 round 1)
// -----------------------------------------------------------------------------

// TestGetJob_ReapsAJobStrandedByARestart pins that a job abandoned by a dead
// process becomes an honest failure rather than polling `processing` forever.
//
// The async processor lives in a goroutine, so a restart between the
// `processing` write and the terminal write leaves the row untouched with
// nobody working on it: the portal polls it for ever and download answers 409
// for ever.
func TestGetJob_ReapsAJobStrandedByARestart(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	stranded := &ReportJob{
		ID: "creport-stranded", OrgID: testScope().OrgID, TenantID: testScope().TenantID,
		Regulator: RegulatorEUAIAct, Framework: FrameworkEUAIAct, Format: FormatJSON,
		PeriodStart: fixedNow.AddDate(0, -1, 0), PeriodEnd: fixedNow,
		Status: StatusProcessing, ReportState: ReportStateUndetermined, Progress: 5,
		// Older than staleAfter, so no live goroutine can still own it.
		CreatedAt: fixedNow.Add(-staleAfter - time.Minute),
	}
	if err := h.repo.Create(context.Background(), stranded); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := h.svc.GetJob(context.Background(), testScope(), stranded.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	if !strings.Contains(got.Error, "no terminal status was recorded") {
		t.Errorf("the failure does not say what happened: %q", got.Error)
	}
	// The stored row must be UNCHANGED. The status poll is exempt from the
	// admin-authority export gate, so a reader that wrote here would let any
	// non-admin caller in the tenancy mutate the compliance record of a report
	// someone else requested, on a GET. The answer is derived, not persisted.
	stored := h.repo.snapshot(stranded.ID)
	if stored == nil {
		t.Fatal("the job vanished")
	}
	if stored.Status != StatusProcessing || stored.Error != "" {
		t.Errorf("a read MUTATED the stored job: status=%s error=%q", stored.Status, stored.Error)
	}

	// Every reader must derive the SAME answer, or two replicas disagree.
	again, err := h.svc.GetJob(context.Background(), testScope(), stranded.ID)
	if err != nil {
		t.Fatalf("second GetJob: %v", err)
	}
	if again.Status != got.Status || again.Error != got.Error {
		t.Errorf("two reads derived different answers: %s/%q vs %s/%q", got.Status, got.Error, again.Status, again.Error)
	}

	// The message must not assert a cause the process cannot observe. An
	// expired processTimeout produces the identical row, so "a restart or a
	// deployment" would be a guess.
	for _, forbidden := range []string{"restart", "deployment"} {
		if strings.Contains(strings.ToLower(got.Error), forbidden) {
			t.Errorf("the failure message asserts an unobservable cause %q: %s", forbidden, got.Error)
		}
	}
}

// TestFailJob_RecordsTheTerminalStateEvenWhenTheJobContextExpired pins the root
// cause of the stranded rows: processJob runs under a 10-minute deadline, and
// reusing that context for the failure write means the write is refused by the
// cancellation that caused the failure - leaving the row at `processing`
// forever.
func TestFailJob_RecordsTheTerminalStateEvenWhenTheJobContextExpired(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	job := &ReportJob{
		ID: "creport-expired-ctx", OrgID: testScope().OrgID, TenantID: testScope().TenantID,
		Regulator: RegulatorEUAIAct, Framework: FrameworkEUAIAct, Format: FormatJSON,
		PeriodStart: fixedNow.AddDate(0, -1, 0), PeriodEnd: fixedNow,
		Status: StatusProcessing, ReportState: ReportStateUndetermined, CreatedAt: fixedNow,
	}
	if err := h.repo.Create(context.Background(), job); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The context processJob would be holding when its own deadline fired.
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	h.svc.failJob(expired, job, failureStageCollect, errors.New("provider query timed out"))

	stored := h.repo.snapshot(job.ID)
	if stored == nil || stored.Status != StatusFailed {
		t.Fatalf("the terminal state was not recorded on an expired context: %+v", stored)
	}
	// The recorded failure names the STAGE, not the raw cause. See M3 below.
	if !strings.Contains(stored.Error, "collecting compliance data") {
		t.Errorf("the recorded failure does not describe what happened: %q", stored.Error)
	}
}

// TestFailJobDoesNotLeakInternalsToTheCaller is M3 of the #3241 round-2 record.
//
// job.Error is persisted and handed straight back on the poll response and in
// the download 409, and the poll is reachable by a non-admin viewer by design.
// Before this it was cause.Error() verbatim, which carried the object-storage
// KEY (bucket layout plus the org id) and raw driver text from Postgres and the
// storage SDK.
func TestFailJobDoesNotLeakInternalsToTheCaller(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	job := &ReportJob{
		ID: "creport-leak", OrgID: testScope().OrgID, TenantID: testScope().TenantID,
		Regulator: RegulatorEUAIAct, Framework: FrameworkEUAIAct, Format: FormatJSON,
		PeriodStart: fixedNow.AddDate(0, -1, 0), PeriodEnd: fixedNow,
		Status: StatusProcessing, ReportState: ReportStateUndetermined, CreatedAt: fixedNow,
	}
	if err := h.repo.Create(context.Background(), job); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A cause shaped exactly like the real ones: a storage key, a bucket, a
	// hostname and raw driver text.
	cause := errors.New(`store report artifact at compliance-reports/acme-org/sebi/creport-leak.pdf: ` +
		`operation error S3: PutObject, https response error StatusCode: 403, ` +
		`api error AccessDenied, bucket axonflow-prod-artifacts.s3.eu-central-1.amazonaws.com; ` +
		`pq: relation "compliance_report_jobs" does not exist`)
	h.svc.failJob(context.Background(), job, failureStageStore, cause)

	stored := h.repo.snapshot(job.ID)
	if stored == nil {
		t.Fatal("job vanished")
	}
	for _, secret := range []string{
		"compliance-reports/acme-org",   // bucket layout + org id
		"creport-leak.pdf",              // object key
		"axonflow-prod-artifacts",       // bucket name
		"eu-central-1",                  // region
		"s3.eu-central-1.amazonaws.com", // endpoint
		"PutObject",                     // SDK operation
		"AccessDenied",                  // SDK error code
		"pq:",                           // raw driver text
		"compliance_report_jobs",        // table name
	} {
		if strings.Contains(stored.Error, secret) {
			t.Errorf("the caller-visible failure message leaks %q:\n  %s", secret, stored.Error)
		}
	}
	// CONTROL: it must still SAY something. A fix that blanked the field would
	// pass every assertion above and leave the caller with nothing.
	if len(stored.Error) < 40 || !strings.Contains(stored.Error, "could not be stored") {
		t.Errorf("the failure message is not useful to the caller: %q", stored.Error)
	}
}

// TestGetJob_DoesNotReapAJobThatIsStillYoung is the control: a job a sibling
// replica may still be working on must be left alone.
func TestGetJob_DoesNotReapAJobThatIsStillYoung(t *testing.T) {
	h := newHarness(t, populatedProvider(RegulatorEUAIAct))

	young := &ReportJob{
		ID: "creport-young", OrgID: testScope().OrgID, TenantID: testScope().TenantID,
		Regulator: RegulatorEUAIAct, Framework: FrameworkEUAIAct, Format: FormatJSON,
		PeriodStart: fixedNow.AddDate(0, -1, 0), PeriodEnd: fixedNow,
		Status: StatusProcessing, ReportState: ReportStateUndetermined, Progress: 55,
		CreatedAt: fixedNow.Add(-time.Minute),
	}
	if err := h.repo.Create(context.Background(), young); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := h.svc.GetJob(context.Background(), testScope(), young.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Status != StatusProcessing {
		t.Errorf("status = %s, want processing - a job younger than the timeout must not be reaped", got.Status)
	}
}

// TestStorageSegmentIsPathSafe pins that an organization id cannot split its own
// key prefix in two, which is what `compliance-reports/<org>/*` bucket policies
// depend on.
func TestStorageSegmentIsPathSafe(t *testing.T) {
	job := &ReportJob{ID: "creport-1", OrgID: "acme/../evil", Regulator: RegulatorOJK}
	key := StorageKeyFor(job, "pdf")
	if strings.Count(key, "/") != 3 {
		t.Errorf("key %q has %d separators, want exactly 3 - the org id split its own prefix", key, strings.Count(key, "/"))
	}
	if strings.Contains(key, "..") {
		t.Errorf("key %q retains a traversal sequence", key)
	}
	// A normal org id must survive unchanged, or the sanitizer is mangling real keys.
	normal := StorageKeyFor(&ReportJob{ID: "creport-2", OrgID: "acme-org_1.2", Regulator: RegulatorSEBI}, "csv")
	if normal != "compliance-reports/acme-org_1.2/sebi/creport-2.csv" {
		t.Errorf("a well-formed org id was mangled: %s", normal)
	}

	// Two DIFFERENT org ids that sanitize to the same characters must not share
	// a key prefix, or a per-organization bucket policy written on the prefix
	// describes more than one organization.
	seen := map[string]string{}
	for _, org := range []string{"acme/1", "acme_1", "acme:1", "acme 1"} {
		key := StorageKeyFor(&ReportJob{ID: "creport-x", OrgID: org, Regulator: RegulatorOJK}, "json")
		if prior, dup := seen[key]; dup {
			t.Errorf("org ids %q and %q collide on the key %q", prior, org, key)
		}
		seen[key] = org
		if strings.Count(key, "/") != 3 {
			t.Errorf("org %q produced a malformed key %q", org, key)
		}
	}

	// A nil job must not panic an exported function.
	if got := StorageKeyFor(nil, "pdf"); got != "" {
		t.Errorf("StorageKeyFor(nil) = %q, want the empty string", got)
	}
}
