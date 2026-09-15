// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// deferredTrust is a reloadable whose reload was deferred: in flight, or inside
// the floor, as refreshingTrust reports for a key it has not loaded, which may
// be one another replica authorized moments ago.
type deferredTrust struct{ current *pdp.TrustStore }

func (d *deferredTrust) Current() *pdp.TrustStore { return d.current }

func (d *deferredTrust) reload(context.Context) (bool, error) { return false, nil }

func (d *deferredTrust) reloadDeferring(context.Context) (bool, bool, error) { return false, true, nil }

// deferredFailingTrust is a deferring reloadable whose skipped reload carries
// the last reload's storage error, as refreshingTrust does inside the floor
// after a failed reload.
type deferredFailingTrust struct {
	current *pdp.TrustStore
	err     error
}

func (d *deferredFailingTrust) Current() *pdp.TrustStore { return d.current }

func (d *deferredFailingTrust) reload(context.Context) (bool, error) { return false, d.err }

func (d *deferredFailingTrust) reloadDeferring(context.Context) (bool, bool, error) {
	return false, true, d.err
}

// A STORED ARTIFACT THAT DOES NOT VERIFY IS NOT A STORAGE FAILURE (#4255). The
// typed-authoring route answers ErrArtifactUnverifiable 500 active_unverifiable
// and a storage failure 503 storage_unavailable, so loadFailure's classification
// is what keeps an integrity fault from reading as an outage, and an outage
// from reading as an integrity fault. Pinned without a database, through
// loadVerified over the stub source.
func TestALoadFailureIsTheArtifactsOwnUnlessTheKeysCouldNotBeReRead(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, stored := artifactFor(t, "probe-key-4255", priv, 1)

	t.Run("a key no longer authorized is ErrArtifactUnverifiable", func(t *testing.T) {
		stub := &stubTrust{current: pdp.NewTrustStore(), changed: false}
		_, lerr := (&Store{trust: stub}).loadVerified(context.Background(), stored)
		if lerr == nil {
			t.Fatal("the artifact loaded although no trust source authorizes its key")
		}
		err := loadFailure(pdp.RootOrganization, lerr)
		if !errors.Is(err, ErrArtifactUnverifiable) {
			t.Fatalf("a key that is no longer authorized was not classified as an artifact that does not verify: %v", err)
		}
		if !errors.Is(err, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("the refusal's own sentinel was lost, so callers keyed on it stop working: %v", err)
		}
	})

	t.Run("a failed re-read of the keys is a storage failure, never ErrArtifactUnverifiable", func(t *testing.T) {
		stub := &stubTrust{current: pdp.NewTrustStore(), err: errors.New("dial tcp: connection refused")}
		_, lerr := (&Store{trust: stub}).loadVerified(context.Background(), stored)
		if lerr == nil {
			t.Fatal("the artifact loaded although its key is unknown and the reload failed")
		}
		err := loadFailure(pdp.RootOrganization, lerr)
		if errors.Is(err, ErrArtifactUnverifiable) {
			t.Fatalf("a database outage while re-reading the keys was classified as an artifact that does not verify: %v", err)
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("the storage failure is no longer visible: %v", err)
		}
	})

	t.Run("a key whose reload was deferred is ErrSigningKeyNotLoaded, never ErrArtifactUnverifiable", func(t *testing.T) {
		_, lerr := (&Store{trust: &deferredTrust{current: pdp.NewTrustStore()}}).loadVerified(context.Background(), stored)
		if lerr == nil {
			t.Fatal("the artifact loaded although no trust source authorizes its key")
		}
		err := loadFailure(pdp.RootOrganization, lerr)
		if !errors.Is(err, ErrSigningKeyNotLoaded) {
			t.Fatalf("a key a deferred reload has not loaded was not named as such: %v", err)
		}
		if errors.Is(err, ErrArtifactUnverifiable) {
			t.Fatalf("a key a deferred reload has not loaded was classified as an artifact that does not verify: %v", err)
		}
		if !errors.Is(err, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("the refusal's own sentinel was lost: %v", err)
		}
	})

	// A FAILED RELOAD WINS OVER A DEFERRAL (R3 round 3). Inside the floor after a
	// failed reload, the skip carries the storage error: during an outage every
	// such read is a storage failure, never key_not_loaded.
	t.Run("a deferred skip carrying a reload failure is storage, never key_not_loaded", func(t *testing.T) {
		stub := &deferredFailingTrust{current: pdp.NewTrustStore(), err: errors.New("dial tcp: connection refused")}
		_, lerr := (&Store{trust: stub}).loadVerified(context.Background(), stored)
		if lerr == nil {
			t.Fatal("the artifact loaded although its key is unknown and the reload failed")
		}
		err := loadFailure(pdp.RootOrganization, lerr)
		if !errors.Is(err, errKeyReloadFailed) {
			t.Fatalf("a floored read during an outage was not reported as the storage failure it is: %v", err)
		}
		if errors.Is(err, ErrSigningKeyNotLoaded) || errors.Is(err, ErrArtifactUnverifiable) {
			t.Fatalf("a floored read during an outage was classified as a key or an artifact fault: %v", err)
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("the storage failure is no longer visible: %v", err)
		}
	})
}

// A RELOAD SAYS WHETHER IT WAS DEFERRED OR IMPOSSIBLE (#4255). Inside the floor
// or while another reload runs, a retry can admit a new key; with no loader,
// nothing ever will. loadVerified keys ErrSigningKeyNotLoaded on the difference.
func TestAReloadSaysWhetherItWasDeferredOrImpossible(t *testing.T) {
	t.Run("with no loader a skipped reload is not deferred", func(t *testing.T) {
		changed, deferred, err := newRefreshingTrust(pdp.NewTrustStore()).reloadDeferring(context.Background())
		if changed || deferred || err != nil {
			t.Fatalf("no loader: changed=%t deferred=%t err=%v; want false, false, nil", changed, deferred, err)
		}
	})
	// Each skip cause is set UNDER THE LOCK rather than produced by timing, so no
	// subtest depends on the machine's speed (R3 round 3).
	bound := func() *refreshingTrust {
		r := newRefreshingTrust(pdp.NewTrustStore())
		r.bind(func(context.Context) (*pdp.TrustStore, error) { return pdp.NewTrustStore(), nil })
		return r
	}
	t.Run("inside the floor a skipped reload is deferred", func(t *testing.T) {
		r := bound()
		r.mu.Lock()
		// An hour ahead: time.Since is negative, so the read is inside the floor
		// however long the machine stalls here (R3 round 4).
		r.lastReload = time.Now().Add(time.Hour)
		r.mu.Unlock()
		changed, deferred, err := r.reloadDeferring(context.Background())
		if changed || !deferred || err != nil {
			t.Fatalf("inside the floor: changed=%t deferred=%t err=%v; want false, true, nil", changed, deferred, err)
		}
	})
	t.Run("while another reload is in flight a skipped reload is deferred", func(t *testing.T) {
		r := bound()
		r.mu.Lock()
		r.reloading = true
		r.mu.Unlock()
		changed, deferred, err := r.reloadDeferring(context.Background())
		if changed || !deferred || err != nil {
			t.Fatalf("in flight: changed=%t deferred=%t err=%v; want false, true, nil", changed, deferred, err)
		}
	})
}
