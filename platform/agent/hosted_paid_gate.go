// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/agent/rls"
)

const hostedCheckoutPath = "/api/v1/billing/checkout"
const hostedBillingStatusPath = "/api/v1/billing/status"
const hostedBillingPortalPath = "/api/v1/billing/portal"

const hostedMeteringBodyLimit = 16 << 20
const hostedPublicBaseURLEnv = "AXONFLOW_HOSTED_PUBLIC_BASE_URL"

var errHostedEventIDConflict = errors.New("hosted event ID was already used for a different request")

const (
	hostedSecurityAcceptanceEnv = "AXONFLOW_HOSTED_SECURITY_ACCEPTANCE"
	hostedWorkflowAcceptanceEnv = "AXONFLOW_HOSTED_WORKFLOW_ACCEPTANCE"
	hostedModuleCapabilitiesEnv = "AXONFLOW_HOSTED_MODULE_CAPABILITIES"
)

var hostedStarterRequiredModules = []string{"fincrime", "payment_exception", "support_refund"}

type hostedStarterLimits struct {
	GovernedEvents int64
	Cases          int64
	Seats          int64
	Integrations   int64
	RetentionDays  int64
	BurstPerMinute int64
}

func hostedPaidLaunchReady() bool {
	if os.Getenv(hostedSecurityAcceptanceEnv) != "4488" ||
		os.Getenv(hostedWorkflowAcceptanceEnv) != "4486" {
		return false
	}
	if _, err := hostedPublicBaseURL(); err != nil {
		return false
	}
	modules, err := hostedConfiguredModules()
	if err != nil || len(modules) != len(hostedStarterRequiredModules) {
		return false
	}
	for index := range modules {
		if modules[index] != hostedStarterRequiredModules[index] {
			return false
		}
	}
	return true
}

// hostedPublicBaseURL is the single public origin for paid-action links,
// Checkout redirects, recovery links, and billing Portal returns. Requiring an
// HTTPS origin prevents staging from silently sending a tenant to production.
func hostedPublicBaseURL() (string, error) {
	raw := strings.TrimRight(strings.TrimSpace(os.Getenv(hostedPublicBaseURLEnv)), "/")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New(hostedPublicBaseURLEnv + " must be an HTTPS origin")
	}
	return raw, nil
}

func communitySaasPublicEndpoint() string {
	if endpoint, err := hostedPublicBaseURL(); err == nil {
		return endpoint
	}
	return communitySaasTryEndpoint
}

// hostedConfiguredModules parses the server-side capability set advertised by
// Hosted Starter. Keeping this distinct from the paid subscription prevents a
// payment row from silently authorizing a module whose routes or isolation
// proof have not shipped. The canonical order also makes the public plan stable.
func hostedConfiguredModules() ([]string, error) {
	known := make(map[string]struct{}, len(hostedStarterRequiredModules))
	for _, module := range hostedStarterRequiredModules {
		known[module] = struct{}{}
	}
	configured := map[string]struct{}{}
	for _, raw := range strings.Split(os.Getenv(hostedModuleCapabilitiesEnv), ",") {
		module := strings.TrimSpace(raw)
		if module == "" {
			continue
		}
		if _, ok := known[module]; !ok {
			return nil, errors.New("unknown hosted module capability: " + module)
		}
		configured[module] = struct{}{}
	}
	modules := make([]string, 0, len(configured))
	for _, module := range hostedStarterRequiredModules {
		if _, ok := configured[module]; ok {
			modules = append(modules, module)
		}
	}
	return modules, nil
}

func hostedStarterPlanLimits() (hostedStarterLimits, error) {
	readPositive := func(name string) (int64, error) {
		value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64)
		if err != nil || value <= 0 {
			return 0, errors.New(name + " must be a positive integer")
		}
		return value, nil
	}

	var limits hostedStarterLimits
	var err error
	if limits.GovernedEvents, err = readPositive("AXONFLOW_HOSTED_INCLUDED_EVENTS"); err != nil {
		return hostedStarterLimits{}, err
	}
	if limits.Cases, err = readPositive("AXONFLOW_HOSTED_INCLUDED_CASES"); err != nil {
		return hostedStarterLimits{}, err
	}
	if limits.Seats, err = readPositive("AXONFLOW_HOSTED_INCLUDED_SEATS"); err != nil {
		return hostedStarterLimits{}, err
	}
	if limits.Integrations, err = readPositive("AXONFLOW_HOSTED_INCLUDED_INTEGRATIONS"); err != nil {
		return hostedStarterLimits{}, err
	}
	if limits.RetentionDays, err = readPositive("AXONFLOW_HOSTED_RETENTION_DAYS"); err != nil {
		return hostedStarterLimits{}, err
	}
	if limits.BurstPerMinute, err = readPositive("COMMUNITY_SAAS_MINUTE_LIMIT_PRO"); err != nil {
		return hostedStarterLimits{}, err
	}
	return limits, nil
}

// hostedPaidGateApplies gives operators a stable tenant cohort and an
// immediate rollback switch. The default is off until the migration starts.
func hostedPaidGateApplies(tenantID string) bool {
	if os.Getenv("AXONFLOW_HOSTED_PAID_GATE") != "enforce" {
		return false
	}
	percent, err := strconv.Atoi(os.Getenv("AXONFLOW_HOSTED_PAID_GATE_PERCENT"))
	if err != nil || percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID))
	return int(h.Sum32()%100) < percent
}

// hostedPaidGateAppliesToTenant makes paid-first mandatory for registrations
// created after the operator's migration cutoff. The percentage cohort then
// applies only to older tenants, so registering a new tenant cannot evade a
// partial migration rollout.
func hostedPaidGateAppliesToTenant(ctx context.Context, db *sql.DB, tenantID string) (bool, error) {
	if os.Getenv("AXONFLOW_HOSTED_PAID_GATE") != "enforce" {
		return false, nil
	}
	if hostedPaidGateApplies(tenantID) {
		return true, nil
	}
	cutoffRaw := strings.TrimSpace(os.Getenv("AXONFLOW_HOSTED_PAID_REQUIRED_AFTER"))
	if cutoffRaw != "" {
		cutoff, err := time.Parse(time.RFC3339, cutoffRaw)
		if err != nil {
			return false, errors.New("AXONFLOW_HOSTED_PAID_REQUIRED_AFTER must be RFC3339")
		}
		if db == nil {
			return false, errors.New("hosted paid rollout database unavailable")
		}
		var createdAt time.Time
		if err := rls.WithOrgScope(ctx, db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT created_at FROM community_saas_registrations WHERE tenant_id = $1`, tenantID).Scan(&createdAt)
		}); err != nil {
			return false, err
		}
		if !createdAt.Before(cutoff) {
			return true, nil
		}
	}
	return false, nil
}

// Checkout and account status stay available after a tenant's paid term ends.
// These paths do not execute governance and authenticate the Basic credential
// in their own handlers.
func isHostedBillingManagementPath(r *http.Request) bool {
	return r.URL.Path == hostedCheckoutPath || r.URL.Path == hostedBillingStatusPath || r.URL.Path == hostedBillingPortalPath
}

// hasHostedPaidEntitlement consults the database on every request so a refund,
// cancellation, or expiry cannot continue through a stale process cache. Old
// 90-day purchases remain valid until their original paid expiry.
func hasHostedPaidEntitlement(ctx context.Context, db *sql.DB, tenantID string) (bool, error) {
	if db == nil {
		return false, errors.New("hosted entitlement database unavailable")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var paid bool
	err := rls.WithOrgScope(lookupCtx, db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(lookupCtx, `
			SELECT EXISTS (
				SELECT 1 FROM hosted_subscriptions
				 WHERE tenant_id = $1 AND status = 'active' AND paid_until > NOW()
			) OR EXISTS (
				SELECT 1 FROM plugin_user_licenses
				 WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
			)`, tenantID).Scan(&paid)
	})
	return paid, err
}

func hostedPaymentRequiredError(tenantID string) *CommunitySaasAuthError {
	baseURL, _ := hostedPublicBaseURL()
	return &CommunitySaasAuthError{
		StatusCode:  http.StatusPaymentRequired,
		Code:        "hosted_payment_required",
		Message:     "Hosted governance requires an active paid plan. Create checkout with POST " + hostedCheckoutPath + ". Self-hosted Community remains free.",
		CheckoutURL: baseURL + hostedCheckoutPath,
		TenantID:    tenantID,
	}
}

func hostedLaunchUnavailableError() *CommunitySaasAuthError {
	return &CommunitySaasAuthError{
		StatusCode: http.StatusServiceUnavailable,
		Code:       "hosted_paid_launch_not_accepted",
		Message:    "Hosted paid workflows are not available until the #4488 security and #4486 workflow acceptance gates pass.",
	}
}

func writeHostedPaymentRequired(w http.ResponseWriter, checkoutURL, tenantID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Checkout-URL", checkoutURL)
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":           "hosted_payment_required",
		"message":         "Hosted governance requires an active paid plan.",
		"checkout_url":    checkoutURL,
		"checkout_method": http.MethodPost,
		"tenant_id":       tenantID,
	})
}

func writeHostedMonthlyLimitReached(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Tier-Limit", "monthly_governed_events")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":             "hosted_monthly_limit_reached",
		"message":           "Monthly hosted governance allowance reached.",
		"limit_type":        "monthly_governed_events",
		"higher_usage_path": "paid_enterprise_poc",
	})
}

// Keep the management bypass exact. A prefix match would let an attacker
// append arbitrary path segments to turn a governed route into a free route.
func isHostedGovernanceRequest(r *http.Request) bool {
	return !isHostedBillingManagementPath(r) && !strings.HasPrefix(r.URL.Path, "/health")
}

func isMeteredHostedGovernancePath(path string) bool {
	switch path {
	case "/api/request", "/api/policy/pre-check", "/api/v1/decide",
		"/api/v1/mcp/check-input", "/api/v1/mcp/check-output":
		return true
	default:
		return false
	}
}

func hostedMonthlyAllowance() int64 {
	value, _ := strconv.ParseInt(strings.TrimSpace(os.Getenv("AXONFLOW_HOSTED_INCLUDED_EVENTS")), 10, 64)
	return value
}

func hostedEventID(r *http.Request) string {
	for _, header := range []string{"X-Axonflow-Event-ID", "X-Request-ID"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			if len(value) > 255 {
				return value[:255]
			}
			return value
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(raw)
}

func hostedRequestFingerprint(r *http.Request, parsedPayload []byte) (string, error) {
	body := parsedPayload
	if body == nil && r.Body != nil {
		limited := io.LimitReader(r.Body, hostedMeteringBodyLimit+1)
		var err error
		body, err = io.ReadAll(limited)
		if err != nil {
			return "", err
		}
		if len(body) > hostedMeteringBodyLimit {
			return "", errors.New("hosted governance request body is too large to meter")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	h := sha256.New()
	_, _ = io.WriteString(h, r.Method)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, r.URL.EscapedPath())
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, r.URL.RawQuery)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, r.Header.Get("Content-Type"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func reserveHostedGovernanceEvent(ctx context.Context, db *sql.DB, tenantID, eventID, fingerprint string, limit int64) (bool, error) {
	if limit <= 0 {
		return false, errors.New("hosted monthly allowance is not configured")
	}
	if fingerprint == "" {
		return false, errors.New("hosted request fingerprint is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", tenantID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO hosted_governance_events (tenant_id, event_id, request_fingerprint) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, tenantID, eventID, fingerprint)
	if err != nil {
		return false, err
	}
	inserted, _ := result.RowsAffected()
	if inserted == 0 {
		var existingFingerprint string
		if err = tx.QueryRowContext(ctx, `SELECT request_fingerprint FROM hosted_governance_events WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).Scan(&existingFingerprint); err != nil {
			return false, err
		}
		if existingFingerprint != fingerprint {
			return false, errHostedEventIDConflict
		}
		return true, tx.Commit()
	}
	var count int64
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosted_governance_events WHERE tenant_id = $1 AND occurred_at >= date_trunc('month', NOW())`, tenantID).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > limit {
		_, _ = tx.ExecContext(ctx, `DELETE FROM hosted_governance_events WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID)
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	return true, tx.Commit()
}
