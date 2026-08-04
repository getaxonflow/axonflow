// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/license"
	"axonflow/platform/orchestrator/cloudstorage"
	"axonflow/platform/orchestrator/compliancereport/renderer"
	"axonflow/platform/shared/tenantscope"
)

// LicenseGate is the slice of the orchestrator's LicenseChecker this package
// needs. Declared here as a narrow interface so compliancereport does not have
// to import package orchestrator (which imports this package - that would be a
// cycle); the orchestrator's checker satisfies it structurally.
type LicenseGate interface {
	IsEnterprise() bool
	Tier() license.Tier
	// IsEvidenceExportEnabled is the existing "may this deployment produce
	// compliance evidence at all" tier switch. Reports are the same data class
	// as evidence exports, so they gate on the same switch rather than
	// inventing a second, silently divergent one.
	IsEvidenceExportEnabled() bool
	// MaxEvidenceExportsPerDay is the per-tenant daily budget; -1 is unlimited.
	MaxEvidenceExportsPerDay() int
}

// presignTTL is how long a download URL stays valid. One hour, matching the EU
// AI Act export precedent (euaiact/export_service.go).
const presignTTL = time.Hour

// Service owns the async report lifecycle.
type Service struct {
	repo     Repository
	registry *Registry
	storage  cloudstorage.StorageBackend
	licenses LicenseGate
	limiter  *rateLimiter

	// now is injectable ONLY so tests can pin the lifecycle timestamps. It is
	// never used for anything a renderer sees: the artifact's GeneratedAt comes
	// off the persisted job record.
	now func() time.Time

	// processWG lets tests wait for in-flight async processing instead of
	// sleeping. A sleeping test is a flaky test.
	processWG sync.WaitGroup
}

// ServiceConfig wires a Service.
type ServiceConfig struct {
	Repo     Repository
	Registry *Registry
	// Storage is the artifact store. A nil backend does NOT silently produce
	// undownloadable "completed" jobs - see processJob.
	Storage  cloudstorage.StorageBackend
	Licenses LicenseGate
	Now      func() time.Time
}

// NewService creates a Service.
func NewService(cfg ServiceConfig) *Service {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		repo:     cfg.Repo,
		registry: cfg.Registry,
		storage:  cfg.Storage,
		licenses: cfg.Licenses,
		limiter:  newRateLimiter(nowFn),
		now:      nowFn,
	}
}

// WaitForProcessing blocks until every async job started by this Service has
// reached a terminal state. Test-only helper; production code never calls it.
func (s *Service) WaitForProcessing() { s.processWG.Wait() }

// Available reports whether a regulator's module is wired in this deployment.
// Exposed so a caller (and the runtime-e2e suite) can ask the deployment
// question without creating a job.
func (s *Service) Available(ctx context.Context, scope tenantscope.Scope, req ReportRequest) (bool, error) {
	p := s.registry.Get(req.Regulator)
	if p == nil {
		return false, nil
	}
	return p.Available(ctx, ProviderRequest{
		OrgID:       scope.OrgID,
		TenantID:    scope.TenantID,
		Framework:   req.Framework,
		PeriodStart: req.PeriodStart,
		PeriodEnd:   req.PeriodEnd,
	})
}

// CreateReport validates, gates, persists and starts a report job.
//
// Order of checks is deliberate and mirrors evidence_export_handler:
//
//  1. Vocabulary + window validation. A malformed request is a 400 the caller
//     will retry after fixing; it must not consume a rate-limit slot.
//  2. License tier. A tier refusal is stable for the whole day - burning a slot
//     on it would let an under-tier caller exhaust its own future budget.
//  3. Availability probe. "Your Indonesia module is not enabled" is a
//     deployment fact and must not cost a slot either.
//  4. Rate limit. Consumed last, and RELEASED again if the job then fails to
//     persist, so a consumed slot always corresponds to a job that exists.
//     Without the release, a database outage would burn an Evaluation
//     tenant's whole daily budget on three 500s and then answer "3/3" for the
//     rest of the UTC day - a message that is both a lockout and a lie.
func (s *Service) CreateReport(ctx context.Context, scope tenantscope.Scope, req ReportRequest, requestedBy string) (*ReportJob, error) {
	if !scope.Bound() {
		return nil, tenantscope.ErrNoCallerScope
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if s.licenses != nil && !s.licenses.IsEvidenceExportEnabled() {
		return nil, &RequestError{
			Code: ErrCodeLicenseRequired,
			Message: fmt.Sprintf(
				"compliance report generation requires an Evaluation or Enterprise license (this deployment is on the %s tier). Get a free evaluation license: https://getaxonflow.com/evaluation-license",
				s.licenses.Tier()),
		}
	}

	available, err := s.Available(ctx, scope, req)
	if err != nil {
		return nil, err
	}
	if !available {
		return nil, &RequestError{
			Code: ErrCodeNotAvailable,
			Message: fmt.Sprintf(
				"the %s compliance module is not enabled in this deployment, so no report can be generated for it",
				req.Regulator.DisplayName()),
		}
	}

	// THE DAILY BUDGET IS KEYED PER ORGANIZATION, NOT PER TENANT (M1 of the
	// #3241 round-2 record). Stated here because the licence field is named
	// MaxEvidenceExportsPerDay with no dimension in the name, and a reader can
	// reasonably assume either.
	//
	// Org is the right key and it is the CONSERVATIVE one. A licence is issued
	// to an organization (#3071: one enterprise licence can carry many
	// tenancies, so org != tenant), and the thing the limit exists to bound is
	// what that licence entitles - not what each tenancy under it may do
	// separately. Keying per tenant would multiply an Evaluation licence's
	// 3-per-day by the number of tenancies the holder chooses to create, which
	// makes the limit self-service.
	//
	// The consequence, said out loud rather than discovered: on a multi-tenancy
	// organization the tenancies SHARE one daily budget, so a busy tenancy can
	// exhaust the org's allowance and a sibling gets
	// ErrCodeRateLimitExceeded. On Enterprise the limit is -1 (unlimited) and
	// none of this is reachable; it bites only on Evaluation, where 3/day and
	// multiple tenancies is an unlikely combination. The refusal message says
	// "for this organization" so the caller is not left thinking their own
	// tenancy did it.
	//
	// usedToday and the in-memory limiter are keyed identically (scope.OrgID);
	// they must not diverge, or the durable floor would be counting a different
	// population from the one being decremented.
	consumedSlot := false
	if s.licenses != nil {
		limit := s.licenses.MaxEvidenceExportsPerDay()
		used, err := s.usedToday(ctx, scope.OrgID)
		if err != nil {
			return nil, err
		}
		allowed, count := s.limiter.tryConsumeFrom(scope.OrgID, limit, used)
		if !allowed {
			return nil, &RequestError{
				Code: ErrCodeRateLimitExceeded,
				Message: fmt.Sprintf(
					"daily compliance report limit reached (%d/%d for this organization). Upgrade to Enterprise for unlimited reports: https://getaxonflow.com/pricing",
					count, limit),
			}
		}
		consumedSlot = limit >= 0
	}

	now := s.now().UTC()
	job := &ReportJob{
		ID:          "creport-" + uuid.New().String(),
		OrgID:       scope.OrgID,
		TenantID:    scope.TenantID,
		Regulator:   req.Regulator,
		Framework:   req.Framework,
		Format:      req.Format,
		PeriodStart: req.PeriodStart.UTC(),
		PeriodEnd:   req.PeriodEnd.UTC(),
		Status:      StatusPending,
		// Genuinely not known until the provider has run. See
		// ReportStateUndetermined: blank means "ask again when terminal", never
		// "no data".
		ReportState: ReportStateUndetermined,
		Progress:    0,
		RequestedBy: requestedBy,
		CreatedAt:   now,
	}
	if err := s.repo.Create(ctx, job); err != nil {
		// Give the slot back: nothing was created, so nothing should have been
		// charged for.
		if consumedSlot {
			s.limiter.release(scope.OrgID)
		}
		return nil, fmt.Errorf("compliancereport: persist job: %w", err)
	}

	// Snapshot BEFORE launching the goroutine: the async processor mutates the
	// job it was handed, and returning the same pointer would be a data race
	// the caller could observe as a status that flickers while it serializes.
	result := job.Clone()

	s.processWG.Add(1)
	go func(j *ReportJob) {
		defer s.processWG.Done()
		// A panic in a provider, a renderer or the storage SDK would otherwise
		// take down the whole orchestrator process: this goroutine has no
		// caller to unwind into. Recover, record the job as failed so the
		// caller's poll terminates instead of hanging at `processing` until the
		// stranded-job timeout, and log the stack.
		//
		// The recover is INSIDE the WaitGroup's Done deferral order such that
		// Done still runs; ordering matters because a shutdown waiting on
		// processWG would otherwise block forever on a panicking job.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[compliance-report] job %s PANICKED during processing: %v\n%s",
					j.ID, r, debug.Stack())
				j.Status = StatusFailed
				j.Error = failureStagePanic.callerSafeMessage()
				completed := s.now().UTC()
				j.CompletedAt = &completed
				s.persistTerminal(j)
			}
		}()
		s.processJob(j)
	}(job)

	return result, nil
}

// usedToday is the DURABLE half of the daily budget.
//
// The in-process counter alone resets on every restart, so a rolling deploy
// handed an Evaluation tenant a fresh budget and N replicas multiplied it by N.
// Three comments in this change described CountSince as "the rate limiter's
// durable backstop" while nothing called it; this is the call site that makes
// that true. The stored count is authoritative when it is HIGHER than the
// in-process one, so a replica that has just started cannot under-count.
//
// The window is the same UTC day the in-memory limiter resets on, so the two
// halves cannot disagree about when the budget rolls over.
func (s *Service) usedToday(ctx context.Context, orgID string) (int, error) {
	if s.repo == nil {
		return 0, nil
	}
	n, err := s.repo.CountSince(ctx, orgID, startOfUTCDay(s.now()))
	if err != nil {
		// FAIL CLOSED. An earlier revision fell back to the in-process counter
		// here, on the reasoning that refusing during a transient blip is worse.
		// That reasoning is wrong in the one case this function was added for:
		// on a freshly started replica the in-process counter is ZERO, so an
		// unreadable count hands the tenant an entirely fresh budget - and
		// CountSince is a range scan over a growing table, so "statement
		// timeout" is a plausible steady state rather than a blip.
		//
		// Refusing costs an admin-only, low-frequency route a 500 that names
		// the cause. Failing open costs the daily budget silently.
		log.Printf("[compliance-report] refusing a report: could not read the durable daily count for org=%s: %v", orgID, err)
		return 0, &RequestError{
			Code:    ErrCodeInternal,
			Message: "could not verify this organization's daily report budget; the report was not started. Retry shortly.",
		}
	}
	return n, nil
}

// GetJob reads a job by id within the caller's scope.
//
// TWO independent checks, deliberately: the repository predicates on org_id in
// SQL, and tenantscope.Authorize then checks BOTH tenancy dimensions of the
// fetched row against the caller. The SQL predicate alone would let a caller
// authenticated for org A / tenant T1 read a job written by org A / tenant T2,
// which under a single enterprise license is a different customer-facing scope
// (#3071). Both refusals surface as ErrJobNotFound so the endpoint is not a
// cross-scope existence oracle.
func (s *Service) GetJob(ctx context.Context, scope tenantscope.Scope, id string) (*ReportJob, error) {
	if !scope.Bound() {
		return nil, tenantscope.ErrNoCallerScope
	}
	job, err := s.repo.GetByID(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if err := scope.Authorize(job.OrgID, job.TenantID); err != nil {
		log.Printf("[compliance-report] DENIED by-id read: job=%s caller_org=%s caller_tenant=%s reason=%v",
			id, scope.OrgID, scope.TenantID, err)
		return nil, ErrJobNotFound
	}
	return s.reapIfStranded(job), nil
}

// staleAfter is how long a non-terminal job may sit before a reader reports it
// as stranded. processTimeout bounds the async goroutine, so anything older
// than that plus a margin cannot still be running IN THIS PROCESS - and the
// goroutine does not survive a restart at all.
const staleAfter = processTimeout + 5*time.Minute

// reapIfStranded reports a job abandoned by a dead process as an honest
// failure. It DERIVES the answer and returns a copy; it does not write.
//
// # Why a read must not write
//
// A job can be stranded two ways: the process was replaced between the
// `processing` write and the terminal write (a deploy, an ECS task
// replacement, an OOM), or processJob's own 10-minute deadline expired - in
// which case the terminal write is issued on an already-cancelled context and
// only logged. Either way the row sits at `processing` and the portal polls it
// for ever.
//
// The obvious fix - have the reader persist the transition - was written and
// then removed: the STATUS POLL is deliberately exempt from the admin-authority
// export gate (read_scope.go complianceReportPollShape), so persisting here
// would let any non-admin caller in the tenancy MUTATE the compliance record of
// a report someone else requested, on a GET. A read that writes an audit record
// is a worse defect than the one it fixes.
//
// Deriving instead is sound because the derivation is a pure function of the
// stored row and the clock: every reader computes the same answer, so the
// portal, the download route and a second replica agree without any of them
// writing. The row keeps its stored status, which nothing else counts.
//
// # Why the message says what it says
//
// It names only what this process can observe: that no terminal status was
// recorded within the window. It does NOT claim a restart or a deployment - an
// expired processTimeout produces the identical row, and asserting a cause the
// code cannot distinguish is how a diagnostic misleads the operator reading it.
func (s *Service) reapIfStranded(job *ReportJob) *ReportJob {
	if job == nil || job.Status.Terminal() {
		return job
	}
	if s.now().Sub(job.CreatedAt) < staleAfter {
		return job
	}
	out := job.Clone()
	completed := s.now().UTC()
	out.Status = StatusFailed
	out.CompletedAt = &completed
	out.Error = fmt.Sprintf(
		"no terminal status was recorded within %s of the request, so this report is not being generated: "+
			"either the process working on it stopped, or generation exceeded its own %s limit. Generate the report again.",
		staleAfter, processTimeout)
	log.Printf("[compliance-report] job %s reported as STRANDED (org=%s, created %s, stored status %s) - derived on read, not persisted",
		out.ID, out.OrgID, out.CreatedAt.Format(time.RFC3339), job.Status)
	return out
}

// startOfUTCDay is the daily budget window shared by both halves of the limiter.
func startOfUTCDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

// ErrArtifactUnavailable means the job is complete but its artifact cannot be
// served (no storage backend at download time, or no stored key).
var ErrArtifactUnavailable = errors.New("compliancereport: report artifact is not available for download")

// ErrNotCompleted means the job exists but has not reached `completed`.
var ErrNotCompleted = errors.New("compliancereport: report is not completed")

// DownloadURL mints a presigned URL for a completed job's artifact.
func (s *Service) DownloadURL(ctx context.Context, scope tenantscope.Scope, id string) (string, *ReportJob, error) {
	job, err := s.GetJob(ctx, scope, id)
	if err != nil {
		return "", nil, err
	}
	if job.Status != StatusCompleted {
		return "", job, ErrNotCompleted
	}
	if job.StorageKey == "" || s.storage == nil {
		// A completed job with no retrievable artifact should be impossible -
		// processJob fails the job rather than completing it when the artifact
		// cannot be stored. Reaching here means the backend was removed from
		// the deployment after the job completed, so say that instead of
		// serving a broken redirect.
		return "", job, ErrArtifactUnavailable
	}
	url, err := s.storage.GeneratePresignedURL(ctx, job.StorageKey, presignTTL)
	if err != nil {
		return "", job, fmt.Errorf("compliancereport: presign %s: %w", job.StorageKey, err)
	}
	if url == "" {
		return "", job, ErrArtifactUnavailable
	}
	return url, job, nil
}

// -----------------------------------------------------------------------------
// Async processing
// -----------------------------------------------------------------------------

// processJob runs one report to a terminal state.
//
// The invariant this function exists to hold: a job reaches `completed` ONLY
// when a checksummed artifact is durably stored under its storage key. The EU
// AI Act export precedent does the opposite - it marks an export `completed`
// with no storage backend configured, leaving a permanently undownloadable
// "success" (euaiact/export_service.go finalizeExportPayload returns nil when
// storageBackend == nil). That trap is not reproduced here: no backend is a
// FAILED job with an error naming the missing configuration.
func (s *Service) processJob(job *ReportJob) {
	// Detached from the request context on purpose: the HTTP handler has
	// already returned 202 and cancelling the client connection must not
	// abandon a half-written report. Bounded so a wedged provider query cannot
	// pin a goroutine for the life of the process.
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()

	started := s.now().UTC()
	job.Status = StatusProcessing
	job.StartedAt = &started
	job.Progress = 5
	s.persist(ctx, job)

	report, state, count, err := s.buildReport(ctx, job)
	if err != nil {
		// A failure caused by the module having gone away IS a data state we
		// can name, and the portal renders it differently from a crash. Every
		// other failure leaves the state undetermined, because it is.
		if errors.Is(err, errProviderUnavailable) {
			job.ReportState = ReportStateNotAvailable
		}
		s.failJob(ctx, job, failureStageCollect, err)
		return
	}
	job.ReportState = state
	job.RecordCount = count
	job.Progress = 55
	s.persist(ctx, job)

	rend, err := RendererFor(job.Format)
	if err != nil {
		s.failJob(ctx, job, failureStageRender, err)
		return
	}
	artifact, err := rend.Render(report)
	if err != nil {
		s.failJob(ctx, job, failureStageRender, fmt.Errorf("render %s: %w", job.Format, err))
		return
	}
	job.Progress = 80
	s.persist(ctx, job)

	sum := sha256.Sum256(artifact)
	checksum := hex.EncodeToString(sum[:])
	key := StorageKeyFor(job, rend.Extension())

	if s.storage == nil {
		s.failJob(ctx, job, failureStageStorageUnconfigured, errors.New(
			"no artifact storage backend is configured, so the generated report cannot be stored or downloaded; "+
				"set AUDIT_EXPORT_STORAGE_TYPE (s3|gcs|azure) and its bucket/credential variables on the orchestrator"))
		return
	}
	if _, err := s.storage.Upload(ctx, &cloudstorage.UploadRequest{
		Key:         key,
		Body:        bytes.NewReader(artifact),
		ContentType: rend.ContentType(),
		Metadata: map[string]string{
			"report_id": job.ID,
			"org_id":    job.OrgID,
			"tenant_id": job.TenantID,
			"regulator": string(job.Regulator),
			"framework": string(job.Framework),
			"checksum":  checksum,
		},
	}); err != nil {
		s.failJob(ctx, job, failureStageStore, fmt.Errorf("store report artifact at %s: %w", key, err))
		return
	}

	completed := s.now().UTC()
	job.Status = StatusCompleted
	job.Progress = 100
	job.StorageKey = key
	job.Checksum = checksum
	job.SizeBytes = int64(len(artifact))
	job.CompletedAt = &completed
	job.Error = ""
	s.persistTerminal(job)
}

// processTimeout bounds one report build+render+upload.
const processTimeout = 10 * time.Minute

// errProviderUnavailable marks the failure mode where the regulator's module
// is not (or is no longer) wired. Distinguished from a generic error so the job
// can carry report_state=not_available instead of a blank.
var errProviderUnavailable = errors.New("compliancereport: regulator module unavailable")

// buildReport asks the provider for the data and assembles the render model.
func (s *Service) buildReport(ctx context.Context, job *ReportJob) (*Report, ReportState, int, error) {
	p := s.registry.Get(job.Regulator)
	if p == nil {
		// The provider was present at create time (CreateReport checks
		// Available) and is gone now, which in practice means the process was
		// reconfigured. Fail honestly rather than emitting an empty report that
		// reads as "your organization had no activity".
		return nil, "", 0, fmt.Errorf("%w: the %s compliance module is no longer enabled in this deployment",
			errProviderUnavailable, job.Regulator.DisplayName())
	}
	res, err := p.Fetch(ctx, ProviderRequest{
		OrgID:       job.OrgID,
		TenantID:    job.TenantID,
		Framework:   job.Framework,
		PeriodStart: job.PeriodStart,
		PeriodEnd:   job.PeriodEnd,
	})
	if err != nil {
		return nil, "", 0, fmt.Errorf("collect %s report data: %w", job.Regulator, err)
	}
	if res == nil {
		return nil, "", 0, fmt.Errorf("provider %s returned no result", job.Regulator)
	}
	if !res.State.Valid() {
		return nil, "", 0, fmt.Errorf("provider %s returned invalid report state %q", job.Regulator, res.State)
	}
	if res.State == ReportStateNotAvailable {
		return nil, "", 0, fmt.Errorf("%w: the %s compliance module reported itself unavailable while the report was being generated",
			errProviderUnavailable, job.Regulator.DisplayName())
	}

	rep := &Report{
		JobID:         job.ID,
		Regulator:     string(job.Regulator),
		RegulatorName: job.Regulator.DisplayName(),
		Framework:     string(job.Framework),
		OrgID:         job.OrgID,
		PeriodStart:   job.PeriodStart,
		PeriodEnd:     job.PeriodEnd,
		// The persisted creation time, NOT time.Now(): this is what makes a
		// re-render of the same job reproduce the same bytes and the same
		// checksum.
		GeneratedAt:   job.CreatedAt,
		ReportState:   string(res.State),
		RetentionNote: RetentionNoteFor(job.Regulator),
		RecordCount:   res.RecordCount,
		Sections:      res.Sections,
	}
	return rep, res.State, res.RecordCount, nil
}

// terminalWriteTimeout bounds the write that records a terminal state.
//
// It is deliberately SHORT and on a FRESH context. processJob runs under a
// 10-minute deadline; when that deadline is what killed the job, reusing its
// context for the failure write means the write is refused by the already
// cancelled context and the row is left at `processing` for ever - measured,
// not theorised. The terminal state is the one write that must not inherit the
// cancellation that caused it.
const terminalWriteTimeout = 15 * time.Second

// failJob records a terminal failure. The error text is the operator-facing
// diagnosis, so it must name only causes this process can actually observe.
func (s *Service) failJob(ctx context.Context, job *ReportJob, stage failureStage, cause error) {
	completed := s.now().UTC()
	job.Status = StatusFailed
	job.CompletedAt = &completed
	// The CALLER-SAFE message, not cause.Error() (M3 of the #3241 round-2
	// record). job.Error is persisted and then handed straight back on the poll
	// response and in the download 409, so whatever goes in here is readable by
	// anyone who can poll the job - which, by design, includes a non-admin
	// viewer. The raw cause routinely carried:
	//
	//   - the object-storage KEY, i.e. the deployment's bucket layout plus the
	//     org id of the report ("store report artifact at acme-org/sebi/..."),
	//   - raw driver text from Postgres and from the storage SDK: table names,
	//     column names, endpoint hostnames, occasionally a presigned URL.
	//
	// None of that helps the person polling, and all of it helps someone
	// mapping the deployment. The full cause is logged below, keyed by job id,
	// so support loses nothing.
	job.Error = stage.callerSafeMessage()
	// Progress is deliberately left where it stopped rather than reset or
	// advanced to 100: it tells an operator how far the job got.
	// The FULL cause, only here. This is the correlation point: an operator
	// matches the job id from the caller's poll response to this line.
	log.Printf("[compliance-report] job %s FAILED at stage %s (org=%s regulator=%s format=%s): %v",
		job.ID, stage, job.OrgID, job.Regulator, job.Format, cause)
	s.persistTerminal(job)
}

// persistTerminal writes a terminal state on a fresh, bounded context.
//
// A failure here is louder than the intermediate one: an unrecorded terminal
// state leaves the row at `processing` for ever, which is exactly the stranded
// condition reapIfStranded exists to paper over on read. The log line says so,
// because "could not persist" and "could not persist THE FINAL STATE" are
// different operational facts.
func (s *Service) persistTerminal(job *ReportJob) {
	ctx, cancel := context.WithTimeout(context.Background(), terminalWriteTimeout)
	defer cancel()
	if err := s.repo.Update(ctx, job); err != nil {
		log.Printf("[compliance-report] job %s: FAILED TO RECORD THE TERMINAL STATE %s - the row stays non-terminal and readers will report it as stranded: %v",
			job.ID, job.Status, err)
	}
}

// persist writes the job's current state, logging (not swallowing) a failure.
// A lost intermediate write only costs progress fidelity; a lost TERMINAL write
// would leave a job stuck in `processing` forever, which is why the log line
// names the status it failed to record.
func (s *Service) persist(ctx context.Context, job *ReportJob) {
	if err := s.repo.Update(ctx, job); err != nil {
		log.Printf("[compliance-report] job %s: failed to persist status=%s progress=%d: %v",
			job.ID, job.Status, job.Progress, err)
	}
}

// StorageKeyFor is the artifact's object key. Deterministic and org-prefixed so
// a bucket policy can be written per organization, and unique per job so a
// re-run never overwrites a stored artifact an auditor may already hold.
func StorageKeyFor(job *ReportJob, ext string) string {
	if job == nil {
		return ""
	}
	// An empty org would produce an empty path SEGMENT ("compliance-reports//…"),
	// which is a different key shape and breaks the per-organization prefix.
	// Unreachable in production - tenantscope.ValidateRowKeys runs before any
	// job is persisted - but this is an exported function and the guard costs a
	// branch. storageSegment turns "" into a digest-derived segment.
	return fmt.Sprintf("compliance-reports/%s/%s/%s.%s",
		storageSegment(job.OrgID), job.Regulator, storageSegment(job.ID), ext)
}

// storageSegment makes a value safe to use as ONE path segment.
//
// tenantscope validates that an org id is non-empty and is not the unowned
// sentinel; it does not constrain the character class. An org id containing a
// slash would split into two prefixes, so `compliance-reports/<org>/*` would no
// longer describe one organization's objects - which is the whole reason the
// key is org-prefixed. Anything outside [A-Za-z0-9._-] becomes '_'.
//
// Consecutive dots are also collapsed. Not for traversal - an S3 key is an
// opaque string - but because the LOCAL filesystem backend rejects any key
// containing ".." outright (cloudstorage/local.go fullPath), so a `..` reaching
// the key would make every report for that organization fail to store rather
// than escape anywhere. Fail-closed is the right posture there; producing a key
// that trips it is not.
//
// This is defence in depth, not the boundary: the org id is stamped by the
// authenticating hop and the key is never used for authorization. But a comment
// promising "a bucket policy can be written per organization" should be a
// property of the code rather than of the callers.
func storageSegment(v string) string {
	safe := sanitizeSegment(v)
	if safe == v {
		return safe
	}
	// The value was CHANGED, so it can now collide with a different id that
	// sanitizes to the same thing ("acme/1", "acme_1" and "acme:1" all become
	// "acme_1"). A per-organization bucket policy written on the prefix would
	// then describe three organizations. An 8-hex digest of the ORIGINAL keeps
	// them apart, and is deterministic so the key of a given job never moves.
	sum := sha256.Sum256([]byte(v))
	if safe == "" {
		// Sanitizing to nothing at all would produce an empty path segment.
		return "org-" + hex.EncodeToString(sum[:4])
	}
	return safe + "-" + hex.EncodeToString(sum[:4])
}

func sanitizeSegment(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	prevDot := false
	for _, r := range v {
		var out byte
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			out = byte(r)
		default:
			out = '_'
		}
		if out == '.' {
			if prevDot {
				out = '_'
			} else {
				prevDot = true
				b.WriteByte(out)
				continue
			}
		}
		prevDot = false
		b.WriteByte(out)
	}
	return b.String()
}

// RendererFor maps a format to its renderer.
func RendererFor(f Format) (renderer.Renderer, error) {
	switch f {
	case FormatPDF:
		return renderer.NewPDF(), nil
	case FormatCSV:
		return renderer.NewCSV(), nil
	case FormatXLSX:
		return renderer.NewXLSX(), nil
	case FormatJSON:
		return renderer.NewJSON(), nil
	default:
		return nil, &RequestError{
			Code:    ErrCodeUnsupportedFormat,
			Message: fmt.Sprintf("no renderer for format %q", f),
		}
	}
}

// -----------------------------------------------------------------------------
// Rate limiting
// -----------------------------------------------------------------------------

// rateLimiter is a per-org daily counter.
//
// Per-PROCESS in-memory state, exactly like the evidence-export limiter it
// mirrors (evidence_export_handler.go): in a multi-replica deployment each
// replica enforces its own budget. That is stated rather than hidden - a
// limiter that claims a fleet-wide guarantee it cannot keep is worse than one
// whose scope is documented.
type rateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	resetAt time.Time
	now     func() time.Time
}

func newRateLimiter(now func() time.Time) *rateLimiter {
	return &rateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(now()),
		now:     now,
	}
}

// tryConsumeFrom takes one slot, treating `durable` as a floor on how many have
// already been used today.
//
// limit < 0 means unlimited. limit == 0 means the tier grants none, which is a
// refusal on the FIRST call - the returned count is what was already there, so
// the message reads 0/0.
//
// The durable floor is what survives a restart: this process may have counted
// zero, but the database knows the organization already generated three
// reports today.
func (rl *rateLimiter) tryConsumeFrom(orgID string, limit, durable int) (bool, int) {
	if limit < 0 {
		return true, 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.rollIfNeededLocked()
	current := rl.counts[orgID]
	if durable > current {
		// Adopt the durable count so a later release() cannot take the
		// in-process counter below what the database already recorded.
		current = durable
		rl.counts[orgID] = durable
	}
	if current >= limit {
		return false, current
	}
	rl.counts[orgID]++
	return true, current + 1
}

// release gives a slot back after a create that did not persist.
func (rl *rateLimiter) release(orgID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rollIfNeededLocked()
	if rl.counts[orgID] > 0 {
		rl.counts[orgID]--
	}
}

// rollIfNeededLocked resets the counters at the UTC day boundary. Caller holds
// the mutex.
func (rl *rateLimiter) rollIfNeededLocked() {
	// `!Before`, not `After`: startOfUTCDay is inclusive of midnight, so with a
	// strict comparison the two halves disagreed for the one instant AT the
	// boundary - the durable window said "0 used today" while the in-process
	// counter still held yesterday's count, and tryConsumeFrom only ever raises
	// the count, so the stale one won and refused.
	if !rl.now().Before(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = nextUTCMidnight(rl.now())
	}
}

func nextUTCMidnight(from time.Time) time.Time {
	u := from.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// failureStage names WHERE a report job died, and is the only thing that
// decides what the caller is told (M3 of the #3241 round-2 record).
//
// The design point: the caller-facing text is a closed set of strings chosen
// here, not a transformation of an error message from somewhere else. A
// sanitizer that tries to redact an arbitrary error is a losing game - the next
// storage SDK phrases its failures differently and the redaction misses. A
// closed set cannot leak something nobody wrote into it.
//
// Each message says what happened, whether retrying is sensible, and what an
// operator should look at. The job id is already in the caller's hands, and the
// full cause is in the orchestrator log keyed by that id.
type failureStage string

const (
	// failureStageCollect: a regulator module's read failed, or the module is
	// gone. Covers both, because the caller's next action is the same.
	failureStageCollect failureStage = "collect"
	// failureStageRender: the artifact could not be produced from data that was
	// collected successfully - an unsupported format, or a malformed model.
	failureStageRender failureStage = "render"
	// failureStageStorageUnconfigured: a deployment-configuration fault, not a
	// data one. Named separately because it is the one failure an operator can
	// fix immediately and it is not transient.
	failureStageStorageUnconfigured failureStage = "storage_unconfigured"
	// failureStageStore: the artifact was produced but could not be persisted.
	failureStageStore failureStage = "store"
	// failureStagePanic: the worker goroutine panicked. Distinct from the
	// others because it means a bug in this deployment's code, not a data or
	// configuration condition the caller can reason about.
	failureStagePanic failureStage = "panic"
)

// callerSafeMessage returns the text put on the job record and handed to the
// caller. It never interpolates anything.
func (f failureStage) callerSafeMessage() string {
	switch f {
	case failureStageCollect:
		return "the report could not be generated: collecting compliance data from the regulator module failed. " +
			"Retrying is reasonable; if it persists, an operator should check the orchestrator log for this report id."
	case failureStageRender:
		return "the report could not be generated: rendering the collected data into the requested format failed. " +
			"Retrying in the same format is unlikely to help; try another format, and have an operator check the " +
			"orchestrator log for this report id."
	case failureStageStorageUnconfigured:
		// This one message DOES name a configuration variable, deliberately.
		// AUDIT_EXPORT_STORAGE_TYPE is a documented, public setting name, not a
		// secret and not a fact about this deployment's topology, and it is the
		// single failure the reader can act on immediately. Withholding it here
		// would be redaction as ritual: it hides nothing and costs the operator
		// a support round trip.
		return "the report could not be stored: this deployment has no artifact storage backend configured " +
			"(set AUDIT_EXPORT_STORAGE_TYPE and its bucket/credential variables on the orchestrator). " +
			"This is a deployment configuration fault, not a transient error - retrying will fail the same way."
	case failureStageStore:
		return "the report was generated but could not be stored, so there is nothing to download. " +
			"Retrying is reasonable; if it persists, an operator should check the orchestrator log for this report id."
	case failureStagePanic:
		return "the report could not be generated because report processing failed unexpectedly. " +
			"This is a defect rather than a data or configuration condition - an operator should check the " +
			"orchestrator log for this report id and report it."
	default:
		// Unreachable by construction, and deliberately not "unknown error: %v".
		return "the report could not be generated. An operator should check the orchestrator log for this report id."
	}
}
