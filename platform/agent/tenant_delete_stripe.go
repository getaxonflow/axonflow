// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"axonflow/platform/shared/secretenv"
)

// StripeCustomerArchiver abstracts the Stripe Customer Archive API call so
// tests can substitute a no-op or capturing implementation.
//
// Stripe forbids hard-delete of customers via API; the closest analog is
// `customer.deleted = true` via DELETE /v1/customers/{id}. Per Stripe docs
// this preserves billing history but unsubscribes + sets the customer to
// deleted state. That's the right semantic for GDPR right-to-erasure: we
// purge ON OUR SIDE; Stripe retains a redacted record because financial
// transaction history is a separate retention regime under tax/AML rules
// that GDPR Article 17(3)(b) explicitly carves out.
//
// Reference: https://docs.stripe.com/api/customers/delete
type StripeCustomerArchiver interface {
	ArchiveCustomer(ctx context.Context, customerID string) error
}

// StripeCheckoutSessionExpirer is required before erasing a tenant with an
// open Checkout attempt. An unknown create outcome has no session ID to
// expire and must instead remain for reconciliation.
type StripeCheckoutSessionExpirer interface {
	ExpireCheckoutSession(ctx context.Context, sessionID string) error
}

// NoopStripeCustomerArchiver returns nil for all calls. Used when
// STRIPE_SECRET_KEY is unset (dev/test/CI).
type NoopStripeCustomerArchiver struct{}

func (NoopStripeCustomerArchiver) ArchiveCustomer(_ context.Context, _ string) error {
	return nil
}

// HTTPStripeCustomerArchiver calls Stripe's DELETE /v1/customers/{id}
// endpoint directly via HTTP. We don't pull in the official Stripe SDK
// because the rest of the billing path also uses raw HTTPS (see
// platform/agent/billing/webhook.go) and adding a dependency for one
// archive call is not worth the binary-size cost.
type HTTPStripeCustomerArchiver struct {
	APIKey     string
	HTTPClient *http.Client
}

// ArchiveCustomer calls DELETE https://api.stripe.com/v1/customers/{id}.
// Returns nil on 2xx; an error string on non-2xx that the caller can
// log into the deletion log row.
func (s *HTTPStripeCustomerArchiver) ArchiveCustomer(ctx context.Context, customerID string) error {
	if s.APIKey == "" {
		return fmt.Errorf("HTTPStripeCustomerArchiver: APIKey is empty (set STRIPE_SECRET_KEY)")
	}
	if customerID == "" {
		return fmt.Errorf("HTTPStripeCustomerArchiver: empty customerID")
	}

	endpoint := "https://api.stripe.com/v1/customers/" + url.PathEscape(customerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build stripe request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("stripe call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Surface a small slice of the body for ops debugging; cap to avoid
	// piping a multi-KB Stripe error into a log line.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("stripe DELETE returned %d: %s",
		resp.StatusCode, strings.TrimSpace(string(body)))
}

// ExpireCheckoutSession only succeeds after Stripe reports the Session as
// expired. A completed Session, network failure, or unknown status leaves the
// tenant and its deletion token intact for payment reconciliation.
func (s *HTTPStripeCustomerArchiver) ExpireCheckoutSession(ctx context.Context, sessionID string) error {
	if s == nil || s.APIKey == "" || !strings.HasPrefix(sessionID, "cs_") {
		return fmt.Errorf("Stripe Checkout expiry is not configured or session ID is invalid")
	}
	status, err := s.checkoutSessionStatus(ctx, sessionID)
	if err != nil {
		return err
	}
	if status == "expired" {
		return nil
	}
	if status != "open" {
		return fmt.Errorf("Stripe Checkout Session is not open")
	}
	endpoint := "https://api.stripe.com/v1/checkout/sessions/" + url.PathEscape(sessionID) + "/expire"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, postErr := client.Do(req)
	if postErr == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
	}
	// Even an ambiguous POST outcome is safe to accept only when a fresh GET
	// proves that Stripe can no longer accept payment on this Session.
	status, err = s.checkoutSessionStatus(ctx, sessionID)
	if err != nil || status != "expired" {
		return fmt.Errorf("Stripe Checkout Session expiry is unverified")
	}
	return nil
}

func (s *HTTPStripeCustomerArchiver) checkoutSessionStatus(ctx context.Context, sessionID string) (string, error) {
	endpoint := "https://api.stripe.com/v1/checkout/sessions/" + url.PathEscape(sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Stripe Checkout Session lookup returned %d", resp.StatusCode)
	}
	var session struct{ ID, Status string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&session); err != nil {
		return "", err
	}
	if session.ID != sessionID {
		return "", fmt.Errorf("Stripe Checkout Session ID mismatch")
	}
	return session.Status, nil
}

// NewStripeCustomerArchiverFromEnv returns an HTTPStripeCustomerArchiver if
// STRIPE_SECRET_KEY is set; otherwise a Noop archiver. STRIPE_SECRET_KEY is
// the same env var the billing webhook expects, so this is a no-config-add
// addition to the v1 launch wiring.
func NewStripeCustomerArchiverFromEnv() StripeCustomerArchiver {
	key := secretenv.Get("STRIPE_SECRET_KEY")
	if key == "" {
		return NoopStripeCustomerArchiver{}
	}
	return &HTTPStripeCustomerArchiver{APIKey: key}
}

// stripeCustomerArchiverConfigured prevents a paid deletion from treating the
// development no-op as a completed Stripe customer archive. Injected test
// archivers are configured by construction.
func stripeCustomerArchiverConfigured(archiver StripeCustomerArchiver) bool {
	switch a := archiver.(type) {
	case nil, NoopStripeCustomerArchiver, *NoopStripeCustomerArchiver:
		return false
	case *HTTPStripeCustomerArchiver:
		return a != nil && a.APIKey != ""
	default:
		return true
	}
}
