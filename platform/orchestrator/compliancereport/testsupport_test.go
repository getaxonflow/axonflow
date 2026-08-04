// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/agent/license"
	"axonflow/platform/orchestrator/cloudstorage"
	"axonflow/platform/shared/tenantscope"
)

// Shared fakes for the compliancereport unit tests.
//
// Every fake here enforces the SAME scoping rules production does, or a
// stricter version of them. A permissive fake would make each test above it
// certify the very bug the production code exists to prevent
// (`[[feedback_mocks_that_replicate_prod_semantics_certify_the_bug]]`).

// fixedNow is the pinned clock. Every lifecycle timestamp in a test derives
// from it, so nothing in the suite depends on wall-clock time.
var fixedNow = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

func fixedClock() func() time.Time { return func() time.Time { return fixedNow } }

// -----------------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------------

// memRepo is an in-memory Repository that applies the same org predicate the
// SQL does. It is concurrency-safe because the service mutates jobs from an
// async goroutine while the test reads them.
//
// EVERY METHOD HONOURS ctx CANCELLATION, exactly as database/sql does (M4 of
// the #3241 round-2 record). It did not, and that made
// TestFailJob_RecordsTheTerminalStateEvenWhenTheJobContextExpired vacuous: the
// test handed failJob a cancelled context to prove the terminal write does not
// ride the dying job's context, but the repo never looked at the context, so
// the assertion passed whether or not the fix was present. A mock that is more
// permissive than the thing it stands in for certifies the bug.
type memRepo struct {
	mu        sync.Mutex
	jobs      map[string]*ReportJob
	createErr error
	updateErr error
	getErr    error
	countErr  error
}

func newMemRepo() *memRepo { return &memRepo{jobs: make(map[string]*ReportJob)} }

func (m *memRepo) Create(ctx context.Context, job *ReportJob) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	if err := tenantscope.ValidateRowKeys(job.OrgID, job.TenantID); err != nil {
		return err
	}
	m.jobs[job.ID] = job.Clone()
	return nil
}

func (m *memRepo) GetByID(ctx context.Context, scope tenantscope.Scope, id string) (*ReportJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	job, ok := m.jobs[id]
	// The ORG predicate, exactly as the SQL WHERE clause applies it. The
	// tenant dimension is checked by the SERVICE (tenantscope.Authorize), so
	// this deliberately does not check it - mirroring the real split.
	if !ok || !scope.Bound() || job.OrgID != scope.OrgID {
		return nil, ErrJobNotFound
	}
	return job.Clone(), nil
}

func (m *memRepo) Update(ctx context.Context, job *ReportJob) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	existing, ok := m.jobs[job.ID]
	if !ok || existing.OrgID != job.OrgID {
		return ErrJobNotFound
	}
	m.jobs[job.ID] = job.Clone()
	return nil
}

func (m *memRepo) CountSince(ctx context.Context, orgID string, since time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.countErr != nil {
		return 0, m.countErr
	}
	n := 0
	for _, j := range m.jobs {
		if j.OrgID == orgID && !j.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

// snapshot returns a copy of the stored job, or nil.
func (m *memRepo) snapshot(id string) *ReportJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.jobs[id]; ok {
		return j.Clone()
	}
	return nil
}

// -----------------------------------------------------------------------------
// Storage
// -----------------------------------------------------------------------------

// memStorage is an in-memory cloudstorage.StorageBackend.
type memStorage struct {
	mu         sync.Mutex
	objects    map[string][]byte
	uploadErr  error
	presignErr error
	presign    string
}

func newMemStorage() *memStorage {
	return &memStorage{objects: make(map[string][]byte), presign: "https://storage.example/signed"}
}

func (s *memStorage) Upload(ctx context.Context, req *cloudstorage.UploadRequest) (*cloudstorage.UploadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uploadErr != nil {
		return nil, s.uploadErr
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	s.objects[req.Key] = b
	return &cloudstorage.UploadResult{Key: req.Key, SizeBytes: int64(len(b))}, nil
}

func (s *memStorage) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}

func (s *memStorage) GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.presignErr != nil {
		return "", s.presignErr
	}
	if _, ok := s.objects[key]; !ok {
		return "", errors.New("not found")
	}
	return s.presign + "/" + key + "?expiry=" + expiry.String(), nil
}

func (s *memStorage) Delete(ctx context.Context, key string) error { return nil }
func (s *memStorage) List(ctx context.Context, prefix string) ([]cloudstorage.ObjectInfo, error) {
	return nil, nil
}
func (s *memStorage) HealthCheck(ctx context.Context) error { return nil }
func (s *memStorage) Type() string                          { return "memory" }

func (s *memStorage) object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	return b, ok
}

// -----------------------------------------------------------------------------
// Licenses
// -----------------------------------------------------------------------------

// fakeLicense implements the narrow LicenseGate.
type fakeLicense struct {
	enterprise    bool
	tier          license.Tier
	exportEnabled bool
	maxPerDay     int
}

func enterpriseLicense() *fakeLicense {
	return &fakeLicense{enterprise: true, tier: license.TierEnterprise, exportEnabled: true, maxPerDay: -1}
}

func (f *fakeLicense) IsEnterprise() bool            { return f.enterprise }
func (f *fakeLicense) Tier() license.Tier            { return f.tier }
func (f *fakeLicense) IsEvidenceExportEnabled() bool { return f.exportEnabled }
func (f *fakeLicense) MaxEvidenceExportsPerDay() int { return f.maxPerDay }

// -----------------------------------------------------------------------------
// Providers
// -----------------------------------------------------------------------------

// fakeProvider is a scriptable DataProvider.
type fakeProvider struct {
	regulator    Regulator
	available    bool
	availableErr error
	result       *ProviderResult
	fetchErr     error
	// gotRequest records the last ProviderRequest, so a test can assert WHICH
	// tenancy key the service handed the provider.
	mu         sync.Mutex
	gotRequest ProviderRequest
}

func (f *fakeProvider) Regulator() Regulator { return f.regulator }

func (f *fakeProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return f.available, f.availableErr
}

func (f *fakeProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	f.mu.Lock()
	f.gotRequest = req
	f.mu.Unlock()
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.result, nil
}

func (f *fakeProvider) lastRequest() ProviderRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotRequest
}

// populatedProvider returns a provider with one row in one section.
func populatedProvider(reg Regulator) *fakeProvider {
	return &fakeProvider{
		regulator: reg,
		available: true,
		result: &ProviderResult{
			State:       ReportStatePopulated,
			RecordCount: 1,
			Sections: []Section{{
				Key:     "demo",
				Title:   "Demo section",
				Columns: []string{"ID", "Value"},
				Rows:    [][]string{{"row-1", "alpha"}},
			}},
		},
	}
}

// emptyProvider returns a provider that is enabled and has no rows.
func emptyProvider(reg Regulator) *fakeProvider {
	return &fakeProvider{
		regulator: reg,
		available: true,
		result: &ProviderResult{
			State:       ReportStateEnabledEmpty,
			RecordCount: 0,
			Sections: []Section{{
				Key:   "demo",
				Title: "Demo section",
				Notes: []string{"No rows in the reporting period."},
			}},
		},
	}
}

// -----------------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------------

type harness struct {
	svc     *Service
	repo    *memRepo
	storage *memStorage
	lic     *fakeLicense
}

func newHarness(t *testing.T, providers ...DataProvider) *harness {
	t.Helper()
	h := &harness{repo: newMemRepo(), storage: newMemStorage(), lic: enterpriseLicense()}
	h.svc = NewService(ServiceConfig{
		Repo:     h.repo,
		Registry: NewRegistry(providers...),
		Storage:  h.storage,
		Licenses: h.lic,
		Now:      fixedClock(),
	})
	return h
}

// scope is the standard authenticated caller.
func testScope() tenantscope.Scope {
	return tenantscope.Scope{OrgID: "acme-org", TenantID: "acme-tenant"}
}

// validRequest is a well-formed report request for the given regulator.
func validRequest(reg Regulator, format Format) ReportRequest {
	fw, _ := DefaultFramework(reg)
	if reg == RegulatorOJK {
		fw = FrameworkOJKAIGovernance
	}
	return ReportRequest{
		Regulator:   reg,
		Framework:   fw,
		Format:      format,
		PeriodStart: fixedNow.AddDate(0, -1, 0),
		PeriodEnd:   fixedNow,
	}
}

// runToCompletion creates a report and waits for the async processor.
func (h *harness) runToCompletion(t *testing.T, req ReportRequest) *ReportJob {
	t.Helper()
	created, err := h.svc.CreateReport(context.Background(), testScope(), req, "tester@acme.example")
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	// WaitForProcessing, not a sleep: a sleeping test is a flaky test, and a
	// too-short sleep would assert on a job still in `processing`.
	h.svc.WaitForProcessing()
	final := h.repo.snapshot(created.ID)
	if final == nil {
		t.Fatalf("job %s vanished from the repository", created.ID)
	}
	return final
}

// sha256Hex is the digest form the service records on a job.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
