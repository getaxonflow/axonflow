// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// loadVerified's semantics, pinned WITHOUT a database.
//
// It reads s.trust and the raw bytes and touches no connection, so a Store
// built over a stub source exercises every branch. That matters beyond
// convenience: these run in the mirror and on any developer machine, where the
// real-Postgres suite is skipped, and the properties below are exactly the ones
// that separate "the reload admitted a key the database authorizes" from "the
// reload made verification lenient".

// stubTrust is a TrustSource whose reload behaviour is dictated by the test.
type stubTrust struct {
	current *pdp.TrustStore
	// afterReload is published when reload reports a change.
	afterReload *pdp.TrustStore
	changed     bool
	err         error
	calls       int
}

func (s *stubTrust) Current() *pdp.TrustStore { return s.current }

func (s *stubTrust) reload(_ context.Context) (bool, error) {
	s.calls++
	if s.err != nil {
		return false, s.err
	}
	if !s.changed {
		return false, nil
	}
	s.current = s.afterReload
	return true, nil
}

// artifactFor builds and signs one probe artifact, and returns it with the
// stored bytes. It mirrors the real-Postgres harness's publish helper, minus
// the harness, so a test that needs an artifact does not need a container.
func artifactFor(t *testing.T, keyID string, priv ed25519.PrivateKey, version int) (*authoring.Artifact, []byte) {
	t.Helper()
	// Resolve returns ONE snapshot rather than a loose catalog (#3895): the
	// authoring view, the admission registry, the digest and the registry
	// version now come out of a single call, so a consumer cannot hold a
	// catalog whose digest belongs to a different resolution. Deployment{} is
	// ignored for SourceConformance, whose fixture world declares its own
	// realms; passing the real one here would describe a deployment this
	// fixture is not.
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceConformance, authoringcatalog.Deployment{})
	if err != nil || snap == nil || snap.Catalog == nil {
		t.Fatalf("building the conformance catalog: %v", err)
	}
	cat := snap.Catalog
	raw := fmt.Sprintf(`{
	  "root": "organization",
	  "version": %d,
	  "attributes": [{"path": "signal.detector.probe", "type": "any", "optional": false}],
	  "policies": [{
	    "id": "test:probe:v%d",
	    "authority": "constraint",
	    "root": "organization",
	    "scope": {"organization": true},
	    "actions": {"any": true},
	    "where": {"kind": "compare", "path": "signal.detector.probe", "op": "eq", "literal": true}
	  }]
	}`, version, version)
	var policy pdp.Document
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatal(err)
	}
	doc, findings, err := authoring.NewDocument(authoring.Document{Metadata: authoring.Metadata{
		DocumentID: "trust-source-probe",
		Title:      "Trust source probe",
		Author:     contract.MustParseID(contract.KindPrincipal, "User::portal:alice@example.com"),
	}, Policy: policy}, cat)
	if err != nil {
		t.Fatalf("the probe document must validate: %v\n%v", err, findings)
	}
	art, findings, err := authoring.Publish(context.Background(), doc, cat, authoring.PublishOptions{
		Profile:    mustEnterpriseProfile(t),
		Root:       pdp.RootOrganization,
		KeyID:      keyID,
		PrivateKey: priv,
		Approvers:  []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")},
		Fixtures: []authoring.Fixture{{
			Name:       "the probe detector fires",
			Attributes: probeAttributes(),
			Expect:     map[string]pdp.Verdict{fmt.Sprintf("test:probe:v%d", version): pdp.VerdictMatch},
		}},
		Now: time.Unix(1_700_000_100, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("the probe artifact must publish: %v\n%v", err, findings)
	}
	stored, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	return art, stored
}

func TestLoadVerifiedRetriesOnlyForAKeyItHasNotHeardOf(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "probe-key-1"
	art, stored := artifactFor(t, keyID, priv, 1)

	authorized := pdp.NewTrustStore()
	authorized.Authorize(pdp.RootOrganization, keyID, pub)

	t.Run("an unknown key reloads once and then verifies against the RELOADED trust", func(t *testing.T) {
		stub := &stubTrust{current: pdp.NewTrustStore(), afterReload: authorized, changed: true}
		s := &Store{trust: stub}

		got, err := s.loadVerified(context.Background(), stored)
		if err != nil {
			t.Fatalf("the artifact did not load after a reload that authorizes its key: %v", err)
		}
		if got.Digest() != art.Digest() {
			t.Fatalf("loaded %s, want %s", got.Digest(), art.Digest())
		}
		if stub.calls != 1 {
			t.Fatalf("reload was called %d times, want exactly 1", stub.calls)
		}
	})

	t.Run("a signature that does not verify is NOT retried at all", func(t *testing.T) {
		// Same identifier, different material: the lookup succeeds and
		// ed25519.Verify fails. THE RELOAD MUST NOT BE ATTEMPTED - this is the
		// input an attacker controls, and a store that re-read its trust and
		// tried again would be retrying on tampering.
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrong := pdp.NewTrustStore()
		wrong.Authorize(pdp.RootOrganization, keyID, otherPub)
		stub := &stubTrust{current: wrong, afterReload: authorized, changed: true}
		s := &Store{trust: stub}

		if _, err := s.loadVerified(context.Background(), stored); err == nil {
			t.Fatal("an artifact whose signature does not verify was accepted")
		} else if errors.Is(err, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("a signature mismatch was reported as an unauthorized key: %v", err)
		}
		if stub.calls != 0 {
			t.Fatalf("reload was called %d times for a signature mismatch, want 0; a reload here would retry on tampering", stub.calls)
		}
	})

	t.Run("a reload that FAILS carries both facts and stays refused", func(t *testing.T) {
		stub := &stubTrust{current: pdp.NewTrustStore(), err: errors.New("dial tcp: connection refused")}
		s := &Store{trust: stub}

		_, err := s.loadVerified(context.Background(), stored)
		if err == nil {
			t.Fatal("the artifact loaded although its key is unknown and the reload failed")
		}
		// The sentinel must survive, or callers keyed on it stop working.
		if !errors.Is(err, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("the original refusal was lost: %v", err)
		}
		// AND the storage failure must be visible, or a database outage
		// presents to an operator as "this key is not authorized" - a
		// security-sounding message for an availability problem.
		if !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("the reload's own failure was swallowed, so an outage reads as an authorization refusal: %v", err)
		}
	})

	t.Run("a reload that reports no change returns the original refusal", func(t *testing.T) {
		// A reload that reports no change and no deferral (stubTrust does not
		// defer) cannot have admitted a key, and the caller must see the
		// original error. A deferred skip is ErrSigningKeyNotLoaded instead,
		// which load_failure_test.go pins (#4255).
		stub := &stubTrust{current: pdp.NewTrustStore(), changed: false}
		s := &Store{trust: stub}

		_, err := s.loadVerified(context.Background(), stored)
		if !errors.Is(err, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("want the original refusal, got: %v", err)
		}
		if stub.calls != 1 {
			t.Fatalf("reload was called %d times, want 1", stub.calls)
		}
	})

	// THE NEGATIVE CONTROL FOR THE WHOLE FILE. A source that already knows the
	// key must load with NO reload at all - otherwise every assertion above
	// could be satisfied by a store that reloads unconditionally.
	t.Run("a key already in force loads with no reload", func(t *testing.T) {
		stub := &stubTrust{current: authorized}
		s := &Store{trust: stub}

		if _, err := s.loadVerified(context.Background(), stored); err != nil {
			t.Fatalf("an artifact whose key is already authorized did not load: %v", err)
		}
		if stub.calls != 0 {
			t.Fatalf("reload was called %d times on the happy path, want 0", stub.calls)
		}
	})
}

// TestAFailedReloadKeepsTheTrustInForce tests the REAL type, which is the whole
// point of it existing.
//
// The "a failed reload keeps the previous trust" rule was asserted only through
// loadVerified against a stub whose reload keeps `current` BY CONSTRUCTION - so
// that assertion tested the stub, not refreshingTrust. Both directions of the
// rule were written into the comment and neither was exercised on the type that
// implements it.
//
// What the untested branch costs: one transient database error, and every
// artifact in the organization becomes unverifiable on that replica for the life
// of the process. That is worse than the defect this whole change repairs.
func TestAFailedReloadKeepsTheTrustInForce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "probe-key-failed-reload"
	_, stored := artifactFor(t, keyID, priv, 3)

	authorized := pdp.NewTrustStore()
	authorized.Authorize(pdp.RootOrganization, keyID, pub)

	assertUnchanged := func(t *testing.T, r *refreshingTrust, before *pdp.TrustStore) {
		t.Helper()
		// POINTER IDENTITY, not equivalence: a fresh empty store and a fresh
		// equivalent store are both "not the one that was in force", and the
		// mutant this catches installs a different object.
		if r.Current() != before {
			t.Fatal("a failed reload REPLACED the trust store in force")
		}
		if _, ok := r.Current().PublicKey(pdp.RootOrganization, keyID); !ok {
			t.Fatal("a failed reload dropped a key that was in force; one transient database error would make every artifact unverifiable")
		}
		// And it still does its job, which is the consequence a reader cares
		// about rather than the field's identity.
		if _, lerr := (&Store{trust: r}).loadVerified(context.Background(), stored); lerr != nil {
			t.Fatalf("an artifact that verified before the failed reload no longer verifies: %v", lerr)
		}
	}

	t.Run("a loader that errors changes nothing", func(t *testing.T) {
		r := newRefreshingTrust(authorized)
		before := r.Current()
		r.bind(func(context.Context) (*pdp.TrustStore, error) {
			return nil, errors.New("dial tcp: connection refused")
		})
		changed, rerr := r.reload(context.Background())
		if changed {
			t.Fatal("a failed reload reported that the trust in force had changed")
		}
		if rerr == nil {
			t.Fatal("a failed reload reported no error, so the caller cannot tell it apart from a no-change reload")
		}
		assertUnchanged(t, r, before)
	})

	t.Run("a PARTIAL key set arriving alongside an error is not installed", func(t *testing.T) {
		// The read failed halfway and handed back what it had. Publishing that
		// would NARROW what this process will verify - the second direction of
		// the rule, and the one a "return what we got" refactor would break.
		partial := pdp.NewTrustStore()
		r := newRefreshingTrust(authorized)
		before := r.Current()
		r.bind(func(context.Context) (*pdp.TrustStore, error) {
			return partial, errors.New("read failed after 3 of 7 rows")
		})
		if changed, rerr := r.reload(context.Background()); changed || rerr == nil {
			t.Fatalf("a partial set with an error was treated as a successful reload: changed=%t err=%v", changed, rerr)
		}
		assertUnchanged(t, r, before)
	})

	t.Run("a nil key set with NO error is not installed either", func(t *testing.T) {
		// authoring.TrustSource says Current() must never be nil. A loader
		// returning (nil, nil) must not be able to make it so.
		r := newRefreshingTrust(authorized)
		before := r.Current()
		r.bind(func(context.Context) (*pdp.TrustStore, error) { return nil, nil })
		if changed, rerr := r.reload(context.Background()); changed || rerr == nil {
			t.Fatalf("a nil key set was accepted: changed=%t err=%v", changed, rerr)
		}
		assertUnchanged(t, r, before)
	})
}

// TestAPanickingLoaderDoesNotWedgeTheInFlightGuard is the failure that would
// bring the original defect back permanently.
//
// A panic inside the loader does NOT end the process: net/http recovers per
// connection, so the server keeps serving. If the in-flight guard were cleared
// only on the normal return, one panicking reload would leave `reloading` set
// for the life of the process, every later reload would answer (false, nil),
// and this replica would go back to refusing every artifact signed by a key it
// had not heard of - silently, and with no way back short of a restart.
func TestAPanickingLoaderDoesNotWedgeTheInFlightGuard(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "probe-key-panic"
	_, stored := artifactFor(t, keyID, priv, 4)
	authorized := pdp.NewTrustStore()
	authorized.Authorize(pdp.RootOrganization, keyID, pub)

	calls := 0
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		calls++
		if calls == 1 {
			panic("the database driver panicked")
		}
		return authorized, nil
	})

	func() {
		// The panic propagates out of reload, as it should - swallowing it here
		// would be this package deciding a caller's crash policy. What must NOT
		// survive it is the guard.
		defer func() {
			if rec := recover(); rec == nil {
				t.Error("the panicking loader did not panic, so this test proves nothing")
			}
		}()
		_, _ = r.reload(context.Background())
	}()

	r.mu.Lock()
	stuck := r.reloading
	r.mu.Unlock()
	if stuck {
		t.Fatal("the in-flight guard is still set after a panicking loader; every later reload would answer (false, nil) for the life of the process")
	}

	// A READ INSIDE THE FLOOR THE PANIC STAMPED MUST STILL SAY SOMETHING. The
	// defer sets lastReload, so the next reloadFloor's worth of reads are
	// refused; without an error carried with them they would be refused as a
	// bare unauthorized-key refusal, which is the availability-as-authorization
	// confusion on the one path that reaches it by crashing.
	if _, perr := r.reload(context.Background()); perr == nil {
		t.Fatal("a read inside the floor after a panicking loader reports no error at all, so the panic is invisible to the caller")
	}

	// And prove it in BEHAVIOUR, not only in the field: clear the floor - which
	// the panic legitimately stamped - and a healthy loader must now run and
	// admit the key.
	r.mu.Lock()
	r.lastReload = time.Time{}
	r.mu.Unlock()

	changed, rerr := r.reload(context.Background())
	if !changed || rerr != nil {
		t.Fatalf("after a panicking reload a healthy one did not run: changed=%t err=%v (loader calls=%d)", changed, rerr, calls)
	}
	if _, lerr := (&Store{trust: r}).loadVerified(context.Background(), stored); lerr != nil {
		t.Fatalf("the recovered source cannot verify a key the reload admitted: %v", lerr)
	}
}

// TestAFlooredReadStillReportsTheStorageError pins the half of the carried
// error that the floor otherwise hides.
//
// lastReload is stamped on FAILURES too - it has to be, or a database that is
// down gets one query per read. So during an outage only the first read in each
// reloadFloor window performs a reload; every read in between is refused by the
// floor. If those carry no error, they are refused as a bare "key is not
// authorized" - an availability problem wearing an authorization message, on
// nearly every request.
//
// Without this test the mutant that reverts the floored return to
// `(false, nil)` - the shape before the fix - compiles and passes the whole
// suite.
func TestAFlooredReadStillReportsTheStorageError(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "probe-key-floored"
	authorized := pdp.NewTrustStore()
	authorized.Authorize(pdp.RootOrganization, keyID, pub)
	_ = priv

	failing := true
	calls := 0
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		calls++
		if failing {
			return nil, errors.New("dial tcp 10.0.0.5:5432: connection refused")
		}
		return authorized, nil
	})

	if _, err := r.reload(context.Background()); err == nil {
		t.Fatal("the first reload should have failed")
	}

	// THE SECOND READ IS INSIDE THE FLOOR. It performs no reload - asserted by
	// the call count - and must still carry the storage reason.
	changed, err2 := r.reload(context.Background())
	if changed {
		t.Fatal("a floored read reported that the trust had changed")
	}
	if calls != 1 {
		t.Fatalf("the loader ran %d times; the second read was not inside the floor, so this test asserts nothing", calls)
	}
	if err2 == nil {
		t.Fatal("a floored read after a FAILED reload reports no error; during an outage nearly every read would be refused as a bare unauthorized key")
	}
	if !strings.Contains(err2.Error(), "connection refused") {
		t.Fatalf("the floored read reports %q, which does not carry the storage reason", err2)
	}

	// AND A SUCCESS CLEARS IT - the other direction, without which the fix
	// would be "always report the last error you ever saw".
	failing = false
	r.mu.Lock()
	r.lastReload = time.Time{}
	r.mu.Unlock()
	if changed, err := r.reload(context.Background()); !changed || err != nil {
		t.Fatalf("the recovering reload did not succeed: changed=%t err=%v", changed, err)
	}
	if _, err := r.reload(context.Background()); err != nil {
		t.Fatalf("a floored read after a SUCCESSFUL reload still reports an error: %v", err)
	}
}

// TestTheReloadFloorBoundsAnUnauthorizedKey pins the rate limit as behaviour
// rather than as a constant. A key that is genuinely not authorized never
// becomes loadable, so without the floor every read of such an artifact would
// query the signing-key table.
func TestTheReloadFloorBoundsAnUnauthorizedKey(t *testing.T) {
	loads := 0
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		loads++
		return pdp.NewTrustStore(), nil
	})

	if changed, err := r.reload(context.Background()); !changed || err != nil {
		t.Fatalf("the first reload should have run: changed=%t err=%v", changed, err)
	}
	if changed, err := r.reload(context.Background()); changed || err != nil {
		t.Fatalf("a reload within the floor should report no change and no error: changed=%t err=%v", changed, err)
	}
	if loads != 1 {
		t.Fatalf("the loader ran %d times, want 1; the floor is what stops a page of unverifiable rows becoming a query storm", loads)
	}
}

// TestAnUnboundSourceNeverReloads pins the wiring-mistake case: a source whose
// loader was never bound verifies against what it has rather than failing.
func TestAnUnboundSourceNeverReloads(t *testing.T) {
	r := newRefreshingTrust(pdp.NewTrustStore())
	if changed, err := r.reload(context.Background()); changed || err != nil {
		t.Fatalf("an unbound source reported changed=%t err=%v; it must be a no-op", changed, err)
	}
}
