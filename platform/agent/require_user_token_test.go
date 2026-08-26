// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// fakeRequireUserTokenReader is an in-memory requireUserTokenReader for unit
// tests — no DB. rows[orgID] present means "row present with that value";
// absent means "no row" (NOT an error). Set err to make every read fail.
type fakeRequireUserTokenReader struct {
	mu    sync.Mutex
	rows  map[string]bool
	calls map[string]int
	err   error
}

func (f *fakeRequireUserTokenReader) ReadOrgRequireUserToken(_ context.Context, orgID string) (bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[orgID]++
	if f.err != nil {
		return false, false, f.err
	}
	v, ok := f.rows[orgID]
	return v, ok, nil
}

func (f *fakeRequireUserTokenReader) callCount(orgID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[orgID]
}

// installTestRequireUserTokenCache wires a cache over reader for the test's
// lifetime, computing envDefault the same way InitRequireUserToken does (so
// tests that set AXONFLOW_REQUIRE_USER_TOKEN via t.Setenv before calling this
// exercise the real parsing idiom, not a hand-rolled substitute).
func installTestRequireUserTokenCache(t *testing.T, reader requireUserTokenReader, ttl time.Duration) *requireUserTokenCache {
	t.Helper()
	envDefault := parseBoolEnv(EnvRequireUserToken, false)
	c := newRequireUserTokenCache(reader, ttl, envDefault)
	setRequireUserTokenCacheForTest(c)
	t.Cleanup(ResetRequireUserTokenCacheForTest)
	return c
}

// --- 1. Env unset, no org row -> false (the compatibility default). ---

func TestResolveRequireUserToken_EnvUnset_NoOrgRow_False(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), "org-a"); got != false {
		t.Errorf("env unset + no org row: got %v, want false", got)
	}
}

// --- 2. Env true, no org row -> true. ---

func TestResolveRequireUserToken_EnvTrue_NoOrgRow_True(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "true")
	installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), "org-a"); got != true {
		t.Errorf("env true + no org row: got %v, want true", got)
	}
}

// --- 3. Org row true, env unset -> true. ---

func TestResolveRequireUserToken_OrgRowTrue_EnvUnset_True(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{"org-a": true}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), "org-a"); got != true {
		t.Errorf("org row true + env unset: got %v, want true", got)
	}
}

// --- 4. Org row false, env true -> false. The direction-specific assertion:
// an explicit per-org row beats the deployment default, proving the column is
// actually consulted rather than OR'd with the env default.

func TestResolveRequireUserToken_OrgRowFalse_EnvTrue_False(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "true")
	installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{"org-a": false}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), "org-a"); got != false {
		t.Errorf("org row false + env true: got %v, want false (org row must win over env default)", got)
	}
}

// --- 5. Reader error -> true (fail-closed). Cache-level (any error) plus
// repository-level (a genuine query error AND a genuine scan error, below).

func TestResolveRequireUserToken_ReaderError_FailsClosed(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "") // env default false — proves the true comes from fail-closed, not the env
	installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{err: errors.New("db down")}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), "org-a"); got != true {
		t.Errorf("reader error: got %v, want true (fail closed)", got)
	}
}

func TestRequireUserTokenRepository_QueryError_PropagatesAsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT require_user_token FROM organizations WHERE org_id = \$1`).
		WithArgs("org-a").
		WillReturnError(errors.New("connection reset by peer"))
	mock.ExpectRollback()

	repo := NewRequireUserTokenRepository(db)
	_, ok, err := repo.ReadOrgRequireUserToken(context.Background(), "org-a")
	if err == nil {
		t.Fatalf("query error must propagate as an error")
	}
	if ok {
		t.Errorf("query error must report ok=false, got true")
	}
	if err2 := mock.ExpectationsWereMet(); err2 != nil {
		t.Errorf("unmet sqlmock expectations: %v", err2)
	}
}

func TestRequireUserTokenRepository_ScanError_PropagatesAsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"require_user_token"}).
		AddRow(true).
		RowError(0, errors.New("scan boom"))
	mock.ExpectQuery(`SELECT require_user_token FROM organizations WHERE org_id = \$1`).
		WithArgs("org-a").
		WillReturnRows(rows)
	mock.ExpectRollback()

	repo := NewRequireUserTokenRepository(db)
	_, ok, err := repo.ReadOrgRequireUserToken(context.Background(), "org-a")
	if err == nil {
		t.Fatalf("scan error must propagate as an error")
	}
	if ok {
		t.Errorf("scan error must report ok=false, got true")
	}
	if err2 := mock.ExpectationsWereMet(); err2 != nil {
		t.Errorf("unmet sqlmock expectations: %v", err2)
	}
}

// --- 6. sql.ErrNoRows / zero rows -> NOT an error; falls through to the env
// default. Proved at the repository level (real ErrNoRows via sqlmock) and at
// the resolution level for both env values.

func TestRequireUserTokenRepository_RowAbsent_NotAnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT require_user_token FROM organizations WHERE org_id = \$1`).
		WithArgs("org-a").
		WillReturnRows(sqlmock.NewRows([]string{"require_user_token"})) // zero rows -> sql.ErrNoRows
	mock.ExpectRollback()

	repo := NewRequireUserTokenRepository(db)
	value, ok, err := repo.ReadOrgRequireUserToken(context.Background(), "org-a")
	if err != nil {
		t.Fatalf("row-absent (sql.ErrNoRows) must NOT be reported as an error; got %v", err)
	}
	if ok {
		t.Errorf("row-absent must report ok=false, got true")
	}
	if value {
		t.Errorf("row-absent must report value=false, got true")
	}
	if err2 := mock.ExpectationsWereMet(); err2 != nil {
		t.Errorf("unmet sqlmock expectations: %v", err2)
	}
}

func TestResolveRequireUserToken_NoRow_FallsThroughToEnvDefault(t *testing.T) {
	t.Run("env true", func(t *testing.T) {
		t.Setenv(EnvRequireUserToken, "true")
		installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{}}, time.Minute)
		if got := ResolveRequireUserToken(context.Background(), "org-a"); got != true {
			t.Errorf("no row + env true: got %v, want true", got)
		}
	})
	t.Run("env false (unset)", func(t *testing.T) {
		t.Setenv(EnvRequireUserToken, "")
		installTestRequireUserTokenCache(t, &fakeRequireUserTokenReader{rows: map[string]bool{}}, time.Minute)
		if got := ResolveRequireUserToken(context.Background(), "org-a"); got != false {
			t.Errorf("no row + env unset: got %v, want false", got)
		}
	})
}

// --- 7. db == nil (no cache wired) -> env default, NOT fail-closed. ---

func TestResolveRequireUserToken_NoCacheWired_EnvDefault_NotFailClosed(t *testing.T) {
	t.Run("env unset", func(t *testing.T) {
		t.Setenv(EnvRequireUserToken, "")
		ResetRequireUserTokenCacheForTest()
		if got := ResolveRequireUserToken(context.Background(), "org-a"); got != false {
			t.Errorf("no cache wired + env unset: got %v, want false (env default, not fail-closed)", got)
		}
	})
	t.Run("env true", func(t *testing.T) {
		t.Setenv(EnvRequireUserToken, "true")
		ResetRequireUserTokenCacheForTest()
		if got := ResolveRequireUserToken(context.Background(), "org-a"); got != true {
			t.Errorf("no cache wired + env true: got %v, want true (env default)", got)
		}
	})
}

// InitRequireUserToken(nil) must be a documented no-op leaving the cache
// unwired (mirrors InitDetectionOverrides(nil)).
func TestInitRequireUserToken_NilDB_LeavesCacheUnwired(t *testing.T) {
	ResetRequireUserTokenCacheForTest()
	t.Cleanup(ResetRequireUserTokenCacheForTest)
	InitRequireUserToken(nil)
	if getRequireUserTokenCache() != nil {
		t.Errorf("InitRequireUserToken(nil) must leave the cache unwired")
	}
}

// --- 8. Caching: a second resolution within the TTL does not re-read. ---

func TestRequireUserTokenCache_CachesWithinTTL(t *testing.T) {
	r := &fakeRequireUserTokenReader{rows: map[string]bool{"org-a": true}}
	c := installTestRequireUserTokenCache(t, r, time.Minute)

	_ = c.get(context.Background(), "org-a")
	_ = c.get(context.Background(), "org-a")
	if got := r.callCount("org-a"); got != 1 {
		t.Errorf("two gets within TTL must read once; calls=%d", got)
	}
}

// --- 9. Cache is org-granular: two orgs with different postures resolve
// differently and do not share a cache entry. ---

func TestRequireUserTokenCache_OrgGranular(t *testing.T) {
	r := &fakeRequireUserTokenReader{rows: map[string]bool{"org-a": true, "org-b": false}}
	c := installTestRequireUserTokenCache(t, r, time.Minute)

	gotA := c.get(context.Background(), "org-a")
	gotB := c.get(context.Background(), "org-b")
	if gotA != true {
		t.Errorf("org-a: got %v, want true", gotA)
	}
	if gotB != false {
		t.Errorf("org-b: got %v, want false", gotB)
	}
	if gotA == gotB {
		t.Fatalf("org-a and org-b must resolve differently; both got %v", gotA)
	}
	// Each org must have been read independently (no shared cache entry).
	if got := r.callCount("org-a"); got != 1 {
		t.Errorf("org-a calls=%d, want 1", got)
	}
	if got := r.callCount("org-b"); got != 1 {
		t.Errorf("org-b calls=%d, want 1", got)
	}
	// Re-reading org-a must not have consumed org-b's cache slot or vice versa.
	_ = c.get(context.Background(), "org-a")
	_ = c.get(context.Background(), "org-b")
	if got := r.callCount("org-a"); got != 1 {
		t.Errorf("org-a must still be cached; calls=%d, want 1", got)
	}
	if got := r.callCount("org-b"); got != 1 {
		t.Errorf("org-b must still be cached; calls=%d, want 1", got)
	}
}

// --- 10. The error outcome is cached for the bounded error-TTL, not the
// full TTL. ---

func TestRequireUserTokenCache_ErrorCachedForErrTTLNotFullTTL(t *testing.T) {
	r := &fakeRequireUserTokenReader{err: errors.New("db down")}
	// ttl (1 minute) is well above maxRequireUserTokenErrTTL (15s), so the
	// cache must clamp the ERROR entry's expiry to errTTL, not ttl.
	c := newRequireUserTokenCache(r, time.Minute, false)
	if c.ttl != time.Minute {
		t.Fatalf("setup: ttl = %s, want 1m", c.ttl)
	}
	if c.errTTL != maxRequireUserTokenErrTTL {
		t.Fatalf("setup: errTTL = %s, want %s", c.errTTL, maxRequireUserTokenErrTTL)
	}

	before := time.Now()
	got := c.get(context.Background(), "org-a")
	if got != true {
		t.Fatalf("error must fail closed; got %v", got)
	}

	// Capture what get() ACTUALLY stored, in a variable we never touch again,
	// so the assertion below reflects the code under test rather than
	// anything this test subsequently pokes into the map.
	c.mu.RLock()
	originalExpiresAt := c.entries["org-a"].expiresAt
	c.mu.RUnlock()

	// Prove the entry's expiry was set to errTTL-scale (~15s), not
	// ttl-scale (1m): it must land well under 30s from "before".
	if d := originalExpiresAt.Sub(before); d >= 30*time.Second {
		t.Errorf("error entry expiresAt %s after start, want within errTTL (%s), not the full ttl (%s)",
			d, maxRequireUserTokenErrTTL, time.Minute)
	}

	// Simulate time passing the error TTL boundary (independent of the
	// assertion above) and confirm a refresh happens on the next get.
	c.mu.Lock()
	e := c.entries["org-a"]
	e.expiresAt = time.Now().Add(-time.Second)
	c.entries["org-a"] = e
	c.mu.Unlock()

	_ = c.get(context.Background(), "org-a")
	if got := r.callCount("org-a"); got != 2 {
		t.Errorf("an entry expired past errTTL must refresh; calls=%d, want 2", got)
	}
}

// --- 11. TTL clamping: below the minimum and above the maximum both clamp. ---

func TestResolveRequireUserTokenTTL(t *testing.T) {
	t.Run("unset uses default", func(t *testing.T) {
		t.Setenv(EnvRequireUserTokenTTLSeconds, "")
		if got := resolveRequireUserTokenTTL(); got != defaultRequireUserTokenTTL {
			t.Errorf("got %s, want default %s", got, defaultRequireUserTokenTTL)
		}
	})
	t.Run("valid", func(t *testing.T) {
		t.Setenv(EnvRequireUserTokenTTLSeconds, "120")
		if got := resolveRequireUserTokenTTL(); got != 120*time.Second {
			t.Errorf("got %s, want 120s", got)
		}
	})
	t.Run("invalid uses default", func(t *testing.T) {
		t.Setenv(EnvRequireUserTokenTTLSeconds, "abc")
		if got := resolveRequireUserTokenTTL(); got != defaultRequireUserTokenTTL {
			t.Errorf("got %s, want default", got)
		}
	})
	t.Run("clamped to min", func(t *testing.T) {
		t.Setenv(EnvRequireUserTokenTTLSeconds, "1")
		if got := resolveRequireUserTokenTTL(); got != minRequireUserTokenTTL {
			t.Errorf("got %s, want min %s", got, minRequireUserTokenTTL)
		}
	})
	t.Run("clamped to max", func(t *testing.T) {
		t.Setenv(EnvRequireUserTokenTTLSeconds, "99999")
		if got := resolveRequireUserTokenTTL(); got != maxRequireUserTokenTTL {
			t.Errorf("got %s, want max %s", got, maxRequireUserTokenTTL)
		}
	})
}

// newRequireUserTokenCache itself must clamp ttl/errTTL at construction time
// (belt-and-suspenders alongside resolveRequireUserTokenTTL's own clamping).
func TestNewRequireUserTokenCache_ClampsTTL(t *testing.T) {
	t.Run("below min clamps up", func(t *testing.T) {
		c := newRequireUserTokenCache(&fakeRequireUserTokenReader{}, time.Second, false)
		if c.ttl != minRequireUserTokenTTL {
			t.Errorf("ttl = %s, want clamped min %s", c.ttl, minRequireUserTokenTTL)
		}
	})
	t.Run("above max clamps down", func(t *testing.T) {
		c := newRequireUserTokenCache(&fakeRequireUserTokenReader{}, 24*time.Hour, false)
		if c.ttl != maxRequireUserTokenTTL {
			t.Errorf("ttl = %s, want clamped max %s", c.ttl, maxRequireUserTokenTTL)
		}
	})
}

// --- Empty org id resolves against the DEPLOYMENT org, not the env default. ---
//
// An enterprise caller CAN arrive with no org binding: the boot-time licence
// check (run.go) is `result.OrgID != "" && result.OrgID != deploymentOrgID`,
// so it fatals only on a MISMATCH and tolerates a licence carrying no org_id
// at all. Falling back to the env default for those callers would be a hole,
// not a neutral default — an operator who set require_user_token = true on
// their org would find the control silently not applying to exactly that
// credential.
//
// The pairing is what makes these meaningful: the SAME empty org id resolves
// true or false purely according to the DEPLOYMENT org's row. A single-sided
// test would pass against code that ignored the row entirely.

func TestResolveRequireUserToken_EmptyOrgID_ConsultsDeploymentOrgRow_True(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "") // env default false — so a `true` can ONLY come from the row
	t.Setenv("ORG_ID", "deployment-org-x")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{"deployment-org-x": true}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), ""); got != true {
		t.Errorf("empty org id with deployment org row=true: got %v, want true "+
			"(the deployment org's posture must still apply to a credential with no org binding)", got)
	}
}

func TestResolveRequireUserToken_EmptyOrgID_DeploymentOrgRowFalse_StaysFalse(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "true") // env default TRUE — so a `false` can ONLY come from the row
	t.Setenv("ORG_ID", "deployment-org-x")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{"deployment-org-x": false}}, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), ""); got != false {
		t.Errorf("empty org id with deployment org row=false: got %v, want false "+
			"(an explicit row must win over the env default on this path too)", got)
	}
}

// The lookup must be keyed on the DEPLOYMENT org specifically — not on the
// empty string, and not on some other org's row. Without this, a cache that
// stored the resolution under "" would satisfy both tests above while never
// consulting the deployment org at all.
func TestResolveRequireUserToken_EmptyOrgID_KeysOnDeploymentOrgNotEmptyString(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "")
	t.Setenv("ORG_ID", "deployment-org-x")
	reader := &fakeRequireUserTokenReader{rows: map[string]bool{"deployment-org-x": true}}
	installTestRequireUserTokenCache(t, reader, time.Minute)

	_ = ResolveRequireUserToken(context.Background(), "")

	if got := reader.callCount("deployment-org-x"); got != 1 {
		t.Errorf("deployment org read count: got %d, want 1 (the empty org id must be resolved "+
			"against the deployment org's row)", got)
	}
	if got := reader.callCount(""); got != 0 {
		t.Errorf("empty-string org read count: got %d, want 0 (the empty org id must never be "+
			"used as a lookup key of its own)", got)
	}
}

// ORG_ID unset: getDeploymentOrgID() falls back to "local-dev-org", so the
// path still resolves against a real key rather than degrading to the env
// default. Pins that the fallback org is never empty.
func TestResolveRequireUserToken_EmptyOrgID_NoOrgIDEnv_UsesLocalDevOrg(t *testing.T) {
	t.Setenv(EnvRequireUserToken, "")
	t.Setenv("ORG_ID", "")
	reader := &fakeRequireUserTokenReader{rows: map[string]bool{"local-dev-org": true}}
	installTestRequireUserTokenCache(t, reader, time.Minute)

	if got := ResolveRequireUserToken(context.Background(), ""); got != true {
		t.Errorf("empty org id with ORG_ID unset: got %v, want true (must resolve against "+
			"getDeploymentOrgID()'s local-dev-org fallback, never an empty key)", got)
	}
}

// TestRequireUserTokenEnvOrFatal_AcceptsOnlyRecognisedBooleans pins which
// values boot.
//
// parseBoolEnv's default arm returns the DEFAULT on an unrecognised value, so
// without this validation "True " with a stray character, "enabled", or "yes
// please" turns the control OFF across every gate point, permanently, for an
// operator who explicitly set the flag intending the opposite — signalled only
// by one boot line prefixed "[Detection]". That is the one direction in this
// file that would otherwise fail OPEN, and it is the likelier of the two
// operator errors.
//
// The fatal itself cannot be exercised in-process, so this pins the
// classification the fatal branches on.
func TestRequireUserTokenEnvOrFatal_AcceptsOnlyRecognisedBooleans(t *testing.T) {
	accepted := []string{"", "  ", "true", "TRUE", " true ", "1", "yes", "false", "0", "no", "NO"}
	rejected := []string{"True!", "enabled", "yes please", "on", "off", "y", "n", "2", "-1", "tru"}

	for _, v := range accepted {
		if !requireUserTokenEnvIsRecognised(v) {
			t.Errorf("%q must boot: it is a value parseBoolEnv interprets, so refusing it would "+
				"break a working deployment", v)
		}
	}
	for _, v := range rejected {
		if requireUserTokenEnvIsRecognised(v) {
			t.Errorf("%q must NOT boot: parseBoolEnv silently returns the default for it, which "+
				"disables the control while the operator believes it is on", v)
		}
	}
}

// "on"/"off" are deliberately in the rejected set: they read as valid to a
// human but parseBoolEnv does not interpret them, so accepting them here would
// boot a deployment whose flag resolves to the opposite of what was written.
func TestRequireUserTokenEnv_OnOffAreNotSilentlyAccepted(t *testing.T) {
	for _, v := range []string{"on", "off"} {
		t.Setenv(EnvRequireUserToken, v)
		if parseBoolEnv(EnvRequireUserToken, false) {
			t.Fatalf("%q parsed as true — the rejection set assumes parseBoolEnv does not interpret it", v)
		}
		if requireUserTokenEnvIsRecognised(v) {
			t.Fatalf("%q is not interpreted by parseBoolEnv, so it must be refused at boot rather "+
				"than silently resolving false", v)
		}
	}
}

// TestRequireUserTokenSyntheticFallbackCensus pins EVERY site that synthesises
// a service identity on a ResolveUser failure, and whether this flag gates it.
//
// The gap this exists to catch was found in review, not by any test: the docs
// enumerate six gate points and carve out one plane explicitly, which reads as
// exhaustive — but `openai_compat_handler.go` has a seventh synthetic-identity
// fallback that no gate reaches. An operator who turns the flag on is refused
// on six planes and served on the seventh with the shared credential.
//
// A prose enumeration cannot notice a new fallback; this can. If a site is
// added, this test names it and forces a decision: gate it, or document why it
// cannot be gated.
func TestRequireUserTokenSyntheticFallbackCensus(t *testing.T) {
	// file -> gated by ResolveRequireUserToken?
	const (
		gated   = true
		ungated = false
	)
	expected := map[string]bool{
		"decision_handler.go": gated,
		"mcp_handler.go":      gated,
		// NOT gated, and it cannot be: this plane has no per-user token field
		// on the wire at all (ResolveUser is called with a hardcoded ""), so a
		// refusal would be a WALL rather than a migration ask — no caller can
		// comply. Closing it needs the verified machine principal: #3410,
		// which depends on #3279. Documented in
		// docs/security/require-user-token.md.
		"openai_compat_handler.go": ungated,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(src)
		// The synthetic fallback's signature: a service identity minted from
		// the client id on the reserved platform domain.
		if !strings.Contains(body, `+ "@axonflow.local"`) || !strings.Contains(body, "ResolveUser(") {
			continue
		}
		found[name] = strings.Contains(body, "ResolveRequireUserToken(")
	}

	for name, isGated := range found {
		want, known := expected[name]
		if !known {
			t.Errorf("NEW synthetic-service-identity fallback in %s that this census does not know about. "+
				"require_user_token must either gate it, or docs/security/require-user-token.md must say "+
				"why it cannot be gated — an operator reads that enumeration as exhaustive.", name)
			continue
		}
		if isGated != want {
			t.Errorf("%s: gated=%v, expected %v — if this changed deliberately, update the census AND "+
				"the docs table together", name, isGated, want)
		}
	}
	for name := range expected {
		if _, ok := found[name]; !ok {
			t.Errorf("%s no longer has a synthetic-service-identity fallback; if it was removed, drop it "+
				"from this census and from the docs", name)
		}
	}
}
