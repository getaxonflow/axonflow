// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// refreshingTrust is an authoring.TrustSource that re-reads the authorized
// keys from the database when it meets a key it does not know.
//
// # The problem it closes
//
// A process loads the authorized keys once, when it opens its store, and every
// artifact read back is re-verified against that set. So a replica that
// started BEFORE another process authorized a key cannot verify anything that
// process publishes: the listing fails, the active version fails, and Promote
// fails - not with a missing row, but with an error, because a stored artifact
// that will not load is exactly the condition the durable store exists to
// detect. Driven on real Postgres: `key "..." is not authorized to publish
// under the "organization" authority root`, from a replica whose own artifacts
// still verified.
//
// # Why it swaps a pointer instead of authorizing into the live store
//
// A reload NEVER mutates a store readers already hold. It builds a fresh
// *pdp.TrustStore and publishes the POINTER under this lock, so a reader
// holding the previous pointer keeps reading something nobody will write to
// again. That is what makes Current() safe to hand out bare.
//
// pdp.TrustStore is separately gaining an RWMutex (#4000 at ca1b38bc3 - the
// sha rather than the number, because that branch is being rebased and a bare
// number points at a moving head), which makes an in-place write safe for every
// holder rather than only for the ones that remembered to coordinate. This
// shape is kept regardless - publishing a finished object beats mutating a
// shared one, and costs nothing - but which of the two is LOAD BEARING depends
// on merge order, and the PR body states that rather than leaving a reader to
// guess.
//
// # A hazard for whoever rebases a caller onto this
//
// THE SWAP ONLY WORKS FOR A CALLER THAT ASKS EACH TIME. Current() inside the
// function that uses the trust store honours a reload; a Current() result
// HOISTED into a struct field, a closure capture, or a local reused across
// operations is a snapshot again, and it silently reintroduces exactly the
// defect this file exists to remove - on the activation path, where it is
// hardest to notice, because a stale trust store fails only for keys another
// process authorized after the capture.
//
// #4000's activator closure captures its trust at construction and calls
// Authorize per activation. When it rebases onto this, the capture has to
// become a per-operation Current(), or Promote goes back to refusing artifacts
// another replica published.
type refreshingTrust struct {
	mu      sync.RWMutex
	current *pdp.TrustStore

	// load re-reads the authorized keys. Bound AFTER construction because the
	// loader reads through the Store and the Store is built over this source;
	// see bind. A nil loader makes reload a no-op, which is the right
	// behaviour for a source nobody finished wiring: it verifies against what
	// it already has rather than failing closed on a wiring mistake.
	load func(context.Context) (*pdp.TrustStore, error)

	// reloading coalesces concurrent reloads: a page of artifacts signed by an
	// unknown key would otherwise start one database round trip per row, all
	// asking the same question.
	reloading bool
	// lastReload rate-limits them; see reloadFloor.
	lastReload time.Time
	// lastErr is why the most recent reload failed, carried so a read refused
	// by the floor still reports the real reason. Without it, a sustained
	// outage surfaces the storage error on one read per reloadFloor and the
	// bare "key is not authorized" on every read in between - which is the
	// availability-problem-wearing-an-authorization-message case the joined
	// error exists to prevent, applied to nearly every request. Cleared on a
	// successful reload.
	lastErr error
}

// reloadFloor is the minimum interval between two reloads, and it is LOAD
// BEARING rather than tuning.
//
// A key that genuinely is not authorized - revoked, or never this
// organization's - does not become loadable by being asked about again. Without
// a floor, every read of such an artifact would query the signing-key table,
// and a page of them would be a query storm on the one table an attacker would
// most like a verification failure to hammer. The floor bounds an otherwise
// unbounded failure.
//
// It is SHORT because the event it recovers from - another replica authorized a
// key moments ago - is one an operator is watching happen, and a long floor
// turns "publish, then look" into a puzzle.
const reloadFloor = 2 * time.Second

// newRefreshingTrust wraps a starting trust store.
func newRefreshingTrust(t *pdp.TrustStore) *refreshingTrust {
	return &refreshingTrust{current: t}
}

// bind supplies the loader. Separate from construction because the loader
// reads through the Store and the Store is built over this source: binding
// afterwards breaks that cycle without giving the store a second constructor.
func (r *refreshingTrust) bind(load func(context.Context) (*pdp.TrustStore, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.load = load
}

// Current returns the trust store in force. Never nil, per
// authoring.TrustSource. The caller must treat it as read-only.
func (r *refreshingTrust) Current() *pdp.TrustStore {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// reloadDeferring re-reads the authorized keys.
//
// It reports whether the trust in force may have CHANGED, and separately the
// error if the re-read itself failed. The two are different facts and the
// caller needs both: a reload that did not happen and a reload that failed are
// the same `false` and must not be the same message.
//
// It returns without touching anything when there is no loader, when another
// reload is in flight, or when the last one was too recent: changed is false,
// err is the last reload's error (nil after a success), and deferred says
// whether a retry could admit a key (in flight, or inside the floor) or never
// will (no loader). A reload that did not happen cannot have admitted a key, so
// the caller reports the original refusal - wrapped in ErrSigningKeyNotLoaded
// when the reload was only deferred (#4255).
//
// A FAILED LOAD LEAVES THE PREVIOUS TRUST STORE IN FORCE, in both directions
// and both matter. It does not DROP trust: a database that could not be read
// is not evidence a key was withdrawn, and dropping on a transient error would
// make every artifact in the organization unverifiable at once. And it does
// not ADMIT anything: nothing is published unless a complete key set came back,
// so a partial or failed read can never widen what this process will verify.
func (r *refreshingTrust) reloadDeferring(ctx context.Context) (changed, deferred bool, err error) {
	r.mu.Lock()
	if r.load == nil || r.reloading || (!r.lastReload.IsZero() && time.Since(r.lastReload) < reloadFloor) {
		// THE LAST FAILURE TRAVELS WITH THE REFUSAL. A reload that did not
		// happen cannot have admitted a key, so `changed` is false either way -
		// but if the previous attempt failed for a storage reason, the caller
		// needs that reason rather than a bare unauthorized-key refusal. nil
		// when the last attempt succeeded, or when there has never been one.
		err := r.lastErr
		// DEFERRED, NOT IMPOSSIBLE, when a loader exists: another reload is in
		// flight or the last one was inside the floor, so a retry can admit a
		// key another replica authorized moments ago (#4255). With no loader
		// nothing ever will.
		deferred := r.load != nil
		r.mu.Unlock()
		return false, deferred, err
	}
	r.reloading = true
	load := r.load
	r.mu.Unlock()

	// THE GUARD IS RELEASED BY defer, NOT ON THE HAPPY PATH. A panic inside the
	// loader does not end the process - net/http recovers per connection - so a
	// guard cleared only by the normal return would stay set for the life of
	// the process, every later reload would answer (false, nil), and the defect
	// this whole file removes would be back, silently and permanently. The
	// timestamp is stamped here too, so a panicking loader is rate-limited like
	// any other failure rather than retried on every read.
	// completed distinguishes "the loader returned" from "the loader panicked",
	// WITHOUT recover(): recovering here would decide a caller's crash policy
	// on its behalf, and this package is not entitled to that. The flag is set
	// after load returns, so the defer can tell the two apart while the panic
	// still propagates.
	completed := false
	defer func() {
		r.mu.Lock()
		r.reloading = false
		r.lastReload = time.Now()
		if !completed {
			// THE TIMESTAMP WITHOUT THE ERROR WOULD BE THE WORST OF BOTH. The
			// floor is now in force for reloadFloor, so every read in that
			// window is refused - and with no lastErr they would be refused
			// as a bare "key is not authorized", which is the exact
			// availability-as-authorization confusion the carried error exists
			// to prevent, reintroduced on the one path that reaches it by
			// crashing.
			r.lastErr = fmt.Errorf("authoringstore: the trust reload panicked")
		}
		r.mu.Unlock()
	}()

	loaded, err := load(ctx)
	completed = true

	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err != nil:
		// REMEMBERED, because the floor would otherwise hide it. lastReload is
		// stamped on a failure too - it has to be, or a database that is down
		// gets one query per read - so the reads in between are refused by the
		// floor and would carry only the bare "key is not authorized". During a
		// sustained outage that is nearly every read: an availability problem
		// wearing an authorization message, which is exactly what this error
		// was joined on to prevent. Carrying it forward means every floored
		// read still reports the real reason.
		r.lastErr = err
		return false, false, err
	case loaded == nil:
		r.lastErr = fmt.Errorf("authoringstore: the trust reload returned no key set")
		return false, false, r.lastErr
	}
	r.lastErr = nil
	r.current = loaded
	return true, false, nil
}

// reload is reloadDeferring without the deferral: the reloadable contract,
// which the tests and every other caller read.
func (r *refreshingTrust) reload(ctx context.Context) (bool, error) {
	changed, _, err := r.reloadDeferring(ctx)
	return changed, err
}

// reloadable is what loadVerified needs of a source, and it is UNEXPORTED on
// purpose: only a source in this package implements it, so authoring's
// StaticTrust - and every test built on it - keeps exactly today's behaviour of
// one attempt and no database round trip. The new behaviour cannot reach a
// caller that did not construct its way into it.
type reloadable interface {
	reload(ctx context.Context) (bool, error)
}

// deferringReloadable is a reloadable that also says, when it did not reload,
// whether that was deferred (a reload in flight, or the floor) rather than
// impossible (no loader). refreshingTrust implements it (#4255).
type deferringReloadable interface {
	reloadDeferring(ctx context.Context) (changed, deferred bool, err error)
}

// loadVerified turns a stored row back into a verified artifact, retrying once
// if the only thing wrong was a key this process had not yet heard of.
//
// THE RETRY IS DELIBERATELY NARROW. Only authoring.ErrKeyNotAuthorized, which
// is what another replica authorizing a key looks like from here. Never a
// signature or digest failure: those are real refusals and the shape tampering
// takes, and reloading on them would mean re-reading trust and trying again on
// exactly the input an attacker controls.
//
// ON A SECOND FAILURE THE ORIGINAL ERROR IS RETURNED, not the retry's. The two
// can differ, and the first describes the artifact as the caller asked about
// it; reporting the second would explain a refusal in terms of a reload the
// caller never requested.
//
// A RELOAD THAT FAILED FOR STORAGE REASONS IS JOINED ONTO THE REFUSAL RATHER
// THAN SWALLOWED. Otherwise a database outage during the re-read presents to an
// operator as "this key is not authorized" - a security-sounding message for an
// availability problem, which gets investigated as the wrong thing entirely.
// errors.Join carries both facts in one error and leaves errors.Is(err,
// ErrKeyNotAuthorized) true, so callers keyed on the sentinel are unaffected.
func (s *Store) loadVerified(ctx context.Context, raw []byte) (*authoring.Artifact, error) {
	art, err := authoring.LoadArtifact(raw, s.trust.Current())
	if err == nil {
		return art, nil
	}
	if !errors.Is(err, authoring.ErrKeyNotAuthorized) {
		return nil, err
	}
	r, ok := s.trust.(reloadable)
	if !ok {
		return nil, err
	}
	var changed, deferred bool
	var reloadErr error
	if d, ok := r.(deferringReloadable); ok {
		changed, deferred, reloadErr = d.reloadDeferring(ctx)
	} else {
		changed, reloadErr = r.reload(ctx)
	}
	if reloadErr != nil {
		return nil, errors.Join(err, fmt.Errorf("%w: %w", errKeyReloadFailed, reloadErr))
	}
	if !changed {
		if deferred {
			// The key may be one another replica authorized moments ago, which a
			// retry admits once the deferred reload runs (#4255). Neither a
			// storage failure nor an artifact that does not verify.
			return nil, fmt.Errorf("%w: %w", ErrSigningKeyNotLoaded, err)
		}
		return nil, err
	}
	art, retryErr := authoring.LoadArtifact(raw, s.trust.Current())
	if retryErr != nil {
		// A KNOWN AND ACCEPTED IMPRECISION, recorded so it is not rediscovered
		// as a bug. If the reload admitted the key and the artifact then fails
		// for a DIFFERENT reason - a signature that does not verify - the
		// caller still sees the original "key not authorized". That is the
		// price of the rule above, and the rule is worth more: reporting the
		// retry's error would explain a refusal in terms of a reload nobody
		// asked for. The artifact is refused either way, which is the part
		// that matters; only the wording is less precise than it could be.
		return nil, err
	}
	return art, nil
}

// errKeyReloadFailed marks the one loadVerified refusal that is a STORAGE
// failure: the artifact's key was unknown and re-reading the authorized keys
// failed too. loadFailure keys on it, so a database outage is never reported as
// an artifact that does not verify (#4255).
var errKeyReloadFailed = errors.New("re-reading the authorized keys also failed")
