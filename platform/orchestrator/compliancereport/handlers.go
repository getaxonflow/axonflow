// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/shared/identity"
	"axonflow/platform/shared/tenantscope"
)

// Route paths. Exported so the orchestrator's read-scope gate and the portal
// proxy allowlist can name them from one place instead of re-typing a literal.
const (
	// BasePath is the collection route: POST creates a report.
	BasePath = "/api/v1/compliance/reports"
	// ByIDPath is the poll route template.
	ByIDPath = BasePath + "/{id}"
	// DownloadPath is the artifact route template.
	DownloadPath = ByIDPath + "/download"
)

// maxBodyBytes bounds the create request body. A report request is a handful of
// short fields; anything larger is a mistake or an attempt to make the JSON
// decoder do the work.
const maxBodyBytes = 32 << 10

// Handler serves the compliance report facade.
type Handler struct {
	service *Service
}

// NewHandler creates a Handler.
func NewHandler(service *Service) *Handler { return &Handler{service: service} }

// createReport handles POST /api/v1/compliance/reports.
func (h *Handler) createReport(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.bindScope(w, r)
	if !ok {
		return
	}

	var body createRequestBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	// Unknown fields are an ERROR, not silently dropped: a caller that
	// misspells "period_start" would otherwise get a 400 about a missing
	// required field it believes it sent, or worse, a report over a default
	// window it never asked for.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidBody, "invalid JSON body: "+err.Error(), "")
		return
	}

	req, reqErr := body.toReportRequest()
	if reqErr != nil {
		writeError(w, http.StatusBadRequest, reqErr.Code, reqErr.Message, "")
		return
	}

	job, err := h.service.CreateReport(r.Context(), scope, req, resolveRequestedBy(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// getReport handles GET /api/v1/compliance/reports/{id}.
func (h *Handler) getReport(w http.ResponseWriter, r *http.Request, id string) {
	scope, ok := h.bindScope(w, r)
	if !ok {
		return
	}
	job, err := h.service.GetJob(r.Context(), scope, id)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// downloadReport handles GET /api/v1/compliance/reports/{id}/download.
//
// It responds 307 to a presigned URL rather than streaming the bytes: the
// artifact is already in object storage, the orchestrator is not a CDN, and a
// redirect keeps a 200 MB PDF off the orchestrator's heap. 307 (not 302) so a
// client cannot be talked into rewriting the method.
func (h *Handler) downloadReport(w http.ResponseWriter, r *http.Request, id string) {
	scope, ok := h.bindScope(w, r)
	if !ok {
		return
	}
	url, job, err := h.service.DownloadURL(r.Context(), scope, id)
	switch {
	case err == nil:
		// The Location header of this 307 is a PRESIGNED URL: a bearer
		// credential for the artifact, valid for an hour, usable by anyone
		// holding it and with no further authentication. A 307 is cacheable by
		// a shared cache under some configurations, and browsers and
		// intermediaries also persist redirect targets in history and logs.
		//
		// no-store is the strong form (no-cache still permits storing), and
		// Pragma covers HTTP/1.0 intermediaries that ignore Cache-Control.
		// Set BEFORE http.Redirect, which writes the header block.
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	case errors.Is(err, ErrNotCompleted):
		state := ReportState("")
		if job != nil {
			state = job.ReportState
		}
		msg := "report is not completed yet"
		if job != nil {
			msg = fmt.Sprintf("report is %s, not completed", job.Status)
			if job.Status == StatusFailed && job.Error != "" {
				msg = fmt.Sprintf("report failed: %s", job.Error)
			}
		}
		writeError(w, http.StatusConflict, ErrCodeNotCompleted, msg, state)
	case errors.Is(err, ErrArtifactUnavailable):
		state := ReportState("")
		if job != nil {
			state = job.ReportState
		}
		writeError(w, http.StatusConflict, ErrCodeArtifactUnavailable,
			"the report completed but its stored artifact is no longer retrievable; regenerate the report", state)
	default:
		h.writeServiceError(w, r, err)
	}
}

// bindScope resolves the caller's authenticated tenancy, failing closed.
//
// Header-only, both dimensions, trimmed - tenantscope.Bind. This mirrors the
// hardened rbi/org_scope.go resolveOrgID rule and deliberately does NOT accept
// an `?org_id=` query parameter or a context value: no gateway policy can
// neutralise a query parameter (#3066), and a census of context.WithValue in
// this tree found zero production writers of the string keys sebi's handler
// falls back to (tenantscope.go:109-112). A request that arrives without both
// headers did not traverse an authenticating hop.
func (h *Handler) bindScope(w http.ResponseWriter, r *http.Request) (tenantscope.Scope, bool) {
	scope, err := tenantscope.Bind(r)
	if err != nil {
		// COUNTABLE, not just fail-closed: an operator debugging "why is my
		// portal getting 401s" needs this in the log, and a security reviewer
		// needs the refusal to be observable.
		log.Printf("[compliance-report] DENIED %s %s: no authenticated caller scope (X-Org-ID and X-Tenant-ID are set by the AxonFlow Agent gateway or the customer portal proxy)",
			r.Method, r.URL.Path)
		writeError(w, http.StatusUnauthorized, ErrCodeScopeRequired,
			"X-Org-ID and X-Tenant-ID are required; they are set by the AxonFlow Agent gateway or the customer portal proxy", "")
		return tenantscope.Scope{}, false
	}
	return scope, true
}

// writeServiceError maps a service error to its HTTP shape.
func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		status := statusForCode(reqErr.Code)
		state := ReportState("")
		if reqErr.Code == ErrCodeNotAvailable {
			state = ReportStateNotAvailable
		}
		if status >= 400 && status != http.StatusBadRequest {
			log.Printf("[compliance-report] REFUSED %s %s: %s", r.Method, r.URL.Path, reqErr.Code)
		}
		writeError(w, status, reqErr.Code, reqErr.Message, state)
		return
	}
	if errors.Is(err, ErrJobNotFound) {
		// 404, never 403: a distinguishable refusal is a cross-scope existence
		// oracle (tenantscope.ErrNotOwned carries the same instruction).
		writeError(w, http.StatusNotFound, ErrCodeNotFound, "report not found", "")
		return
	}
	if errors.Is(err, tenantscope.ErrNoCallerScope) {
		log.Printf("[compliance-report] DENIED %s %s: caller scope not bound", r.Method, r.URL.Path)
		writeError(w, http.StatusUnauthorized, ErrCodeScopeRequired,
			"X-Org-ID and X-Tenant-ID are required; they are set by the AxonFlow Agent gateway or the customer portal proxy", "")
		return
	}
	log.Printf("[compliance-report] ERROR %s %s: %v", r.Method, r.URL.Path, err)
	writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to process the compliance report request", "")
}

func statusForCode(code string) int {
	switch code {
	case ErrCodeLicenseRequired:
		return http.StatusForbidden
	case ErrCodeRateLimitExceeded:
		return http.StatusTooManyRequests
	case ErrCodeNotAvailable:
		return http.StatusConflict
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// createRequestBody is the wire shape of a create request. Dates arrive as
// RFC3339 STRINGS and are parsed here rather than being decoded straight into
// time.Time, so a malformed date produces a field-specific 400 instead of the
// json package's generic unmarshal error.
type createRequestBody struct {
	Regulator   string `json:"regulator"`
	Framework   string `json:"framework,omitempty"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	Format      string `json:"format"`
}

func (b createRequestBody) toReportRequest() (ReportRequest, *RequestError) {
	start, err := parseRFC3339(b.PeriodStart)
	if err != nil {
		return ReportRequest{}, &RequestError{Code: ErrCodeInvalidPeriod, Message: "period_start must be an RFC3339 timestamp"}
	}
	end, err := parseRFC3339(b.PeriodEnd)
	if err != nil {
		return ReportRequest{}, &RequestError{Code: ErrCodeInvalidPeriod, Message: "period_end must be an RFC3339 timestamp"}
	}
	return ReportRequest{
		Regulator:   Regulator(strings.TrimSpace(b.Regulator)),
		Framework:   Framework(strings.TrimSpace(b.Framework)),
		PeriodStart: start,
		PeriodEnd:   end,
		Format:      Format(strings.TrimSpace(strings.ToLower(b.Format))),
	}, nil
}

func parseRFC3339(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	return time.Parse(time.RFC3339, s)
}

// resolveRequestedBy records WHO asked for the report.
//
// Same precedence as rbi/org_scope.go resolveActor, and for the same reason:
// the artifact is regulatory evidence, so "who requested this" must not be a
// self-asserted body field. It never refuses - bindScope is the authentication
// gate - it only decides how precisely the record names the actor.
//
//  1. A per-user identity, but ONLY behind the platform trust gate
//     (AXONFLOW_TRUST_IDENTITY_HEADERS, default OFF). The agent also re-sets
//     X-User-Email from a validated per-user token regardless of the gate.
//  2. The authenticated client credential, recorded in the reserved synthetic
//     domain so it reads as "requested by this credential", which is the truth.
//  3. "system".
func resolveRequestedBy(r *http.Request) string {
	if r == nil {
		return "system"
	}
	if trusted, _ := identity.FromEnv(); trusted {
		if email := identity.CanonicalEmail(r.Header.Get("X-User-Email")); email != "" {
			return email
		}
		if userID := strings.TrimSpace(r.Header.Get("X-User-ID")); userID != "" {
			return userID
		}
	}
	clientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
	if clientID == "" {
		clientID = strings.TrimSpace(r.Header.Get(tenantscope.HeaderTenantID))
	}
	if clientID != "" {
		return identity.CanonicalEmail(clientID + "@axonflow.local")
	}
	return "system"
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[compliance-report] failed to encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string, state ReportState) {
	writeJSON(w, status, ErrorResponse{Error: message, ErrorCode: code, ReportState: state})
}
