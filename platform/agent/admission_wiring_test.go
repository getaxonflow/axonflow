// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

// The agent side of #3593's Field-Level table: the wiring's own behaviour
// (unwired, skipped, refused, outage), the refusal's wire shape on every
// plane it is rendered on, the node identity's persistence, and the AST pin
// that run.go wires the admitter on the database path.

func wireMemoryAdmitter(t *testing.T, tier license.Tier, opts ...admission.Option) *admission.MemoryLedger {
	t.Helper()
	mem := admission.NewMemoryLedger()
	prev := tierAdmitter.Load()
	all := append([]admission.Option{
		admission.WithNodeLeases(mem),
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: tier, KeyPresent: tier != license.TierCommunity}
		}),
	}, opts...)
	tierAdmitter.Store(admission.New(mem, all...))
	t.Cleanup(func() {
		if prev == nil {
			tierAdmitter.Store(nil)
		} else {
			tierAdmitter.Store(prev)
		}
	})
	return mem
}

func TestAdmitPrincipalUnwiredAdmitsAndCounts(t *testing.T) {
	prev := tierAdmitter.Load()
	tierAdmitter.Store(nil)
	t.Cleanup(func() {
		if prev != nil {
			tierAdmitter.Store(prev)
		}
	})
	before := testutil.ToFloat64(admissionUnwiredTotal.WithLabelValues(string(admission.HumanPrincipal)))
	if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, "org", "someone@example.com"); ref != nil {
		t.Fatalf("unwired must admit: %v", ref)
	}
	if got := testutil.ToFloat64(admissionUnwiredTotal.WithLabelValues(string(admission.HumanPrincipal))) - before; got != 1 {
		t.Fatalf("unwired counter moved %v, want 1", got)
	}
}

func TestAdmitPrincipalSkipsBlankOrgOrPrincipalAndCounts(t *testing.T) {
	wireMemoryAdmitter(t, license.TierCommunity)
	orgBefore := testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(string(admission.ServicePrincipal), "org"))
	prBefore := testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(string(admission.ServicePrincipal), "principal"))
	if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "   ", "client"); ref != nil {
		t.Fatalf("blank org must be a counted skip: %v", ref)
	}
	if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "org", ""); ref != nil {
		t.Fatalf("blank principal must be a counted skip: %v", ref)
	}
	if testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(string(admission.ServicePrincipal), "org"))-orgBefore != 1 ||
		testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(string(admission.ServicePrincipal), "principal"))-prBefore != 1 {
		t.Fatal("skip counters did not move by one each")
	}
}

// TestAdmitPrincipalRefusalIsA402WithItsOwnCode drives the 26th human on a
// Community ledger through the wiring and checks the AuthError shape every
// AuthError-carrying plane renders, plus the raw-JSON writer.
func TestAdmitPrincipalRefusalIsA402WithItsOwnCode(t *testing.T) {
	mem := wireMemoryAdmitter(t, license.TierCommunity)
	for i := 1; i <= license.CommunityLimits.MaxHumanPrincipals; i++ {
		if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, "org", "u"+strings.Repeat("x", i)+"@example.com"); ref != nil {
			t.Fatalf("human %d: %v", i, ref)
		}
	}
	ref := admitPrincipal(context.Background(), admission.HumanPrincipal, "org", "one-too-many@example.com")
	if ref == nil {
		t.Fatal("the 26th human on Community must be refused")
	}
	ae := ref.AuthError()
	if ae.HTTPStatus != 402 || ae.Code != "ERR_TIER_LIMIT_HUMAN_PRINCIPAL" || ae.RetryAfter != "" {
		t.Fatalf("AuthError: %+v", ae)
	}
	if !strings.HasPrefix(ae.Message, "ERR_TIER_LIMIT_HUMAN_PRINCIPAL:") {
		t.Fatalf("the message must begin with the code so text-only planes carry it: %q", ae.Message)
	}
	if !isTierLimitAuthError(ae) || isTierLimitAuthError(&AuthError{Code: "invalid_user_token"}) {
		t.Fatal("isTierLimitAuthError must recognise the refusal and nothing else")
	}
	if mem.Rows("org", admission.HumanPrincipal) != license.CommunityLimits.MaxHumanPrincipals {
		t.Fatalf("rows=%d", mem.Rows("org", admission.HumanPrincipal))
	}
	// The raw-JSON writer.
	rec := httptest.NewRecorder()
	writeTierLimitRefusal(rec, ref)
	if rec.Code != 402 || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("writer: code=%d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "ERR_TIER_LIMIT_HUMAN_PRINCIPAL" || body["reason"] != "over_limit" || body["limit"] != float64(25) || body["count"] != float64(25) || body["edition"] != "community" {
		t.Fatalf("body: %v", body)
	}
	// Existing principals keep working after the limit.
	if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, "org", "ux@example.com"); ref != nil {
		t.Fatalf("existing principal after the limit: %v", ref)
	}
}

// TestAdmitPrincipalOutageRefusalCarriesRetryAfter: ledger down, unknown
// principal -> 402 with Retry-After and the outage reason; known principal
// -> admitted.
func TestAdmitPrincipalOutageRefusalCarriesRetryAfter(t *testing.T) {
	mem := wireMemoryAdmitter(t, license.TierEvaluation)
	if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "org", "known"); ref != nil {
		t.Fatal(ref)
	}
	mem.SetDown(true)
	if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "org", "known"); ref != nil {
		t.Fatalf("known principal during an outage: %v", ref)
	}
	ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "org", "unknown")
	if ref == nil || ref.Decision.Reason != admission.ReasonDependencyUnreachable {
		t.Fatalf("unknown principal during an outage: %v", ref)
	}
	ae := ref.AuthError()
	if ae.HTTPStatus != 402 || ae.RetryAfter != "30" || ae.Code != "ERR_TIER_LIMIT_SERVICE_PRINCIPAL" {
		t.Fatalf("AuthError: %+v", ae)
	}
	rec := httptest.NewRecorder()
	writeTierLimitRefusal(rec, ref)
	if rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("Retry-After=%q", rec.Header().Get("Retry-After"))
	}
	if h := tierAdmissionHealth(); h["ledger"] != "degraded" || h["wired"] != true {
		t.Fatalf("health: %v", h)
	}
}

// TestEnterpriseLicenceNeverReachesTheLedgerThroughTheWiring: the ledger is
// down and Enterprise still admits everything (skip, asserted as a skip).
func TestEnterpriseLicenceNeverReachesTheLedgerThroughTheWiring(t *testing.T) {
	mem := wireMemoryAdmitter(t, license.TierEnterprise)
	mem.SetDown(true)
	for i := 0; i < 100; i++ {
		if ref := admitPrincipal(context.Background(), admission.HumanPrincipal, "org", "h"+strings.Repeat("y", i)); ref != nil {
			t.Fatalf("enterprise human %d: %v", i, ref)
		}
	}
	if a := tierAdmitter.Load(); a.LedgerCalls() != 0 {
		t.Fatalf("enterprise made %d ledger calls", a.LedgerCalls())
	}
}

// TestNodeIdentityIsEnvThenPersistedFileNeverHostname.
func TestNodeIdentityIsEnvThenPersistedFileNeverHostname(t *testing.T) {
	dir := t.TempDir()
	if got := resolveNodeIdentity("  node-from-env  ", dir); got != "node-from-env" {
		t.Fatalf("env: %q", got)
	}
	first := resolveNodeIdentity("", dir)
	if !strings.HasPrefix(first, "node-") {
		t.Fatalf("generated: %q", first)
	}
	if again := resolveNodeIdentity("", dir); again != first {
		t.Fatalf("a second resolve on the same directory must return the persisted id: %q vs %q", again, first)
	}
	raw, err := os.ReadFile(filepath.Join(dir, nodeIDFile))
	if err != nil || strings.TrimSpace(string(raw)) != first {
		t.Fatalf("persisted file: %q err=%v", raw, err)
	}
	host, _ := os.Hostname()
	if first == host {
		t.Fatal("the node identity must never be the hostname")
	}
	// An unwritable directory yields an ephemeral id (and a loud log), never a panic.
	if id := resolveNodeIdentity("", filepath.Join(dir, "no", "such", "\x00dir")); !strings.HasPrefix(id, "node-") {
		t.Fatalf("ephemeral: %q", id)
	}
}

// TestRunWiresTierAdmissionOnTheDatabasePath is the AST pin behind the
// unwired-window default: run.go's database-connected branch must call
// initTierAdmission and then admitNodeAtBoot, in that order, and healthHandler
// must report tier_admission. Without this the default could outlive its
// window silently.
func TestRunWiresTierAdmissionOnTheDatabasePath(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// THE HANDLER /health IS REGISTERED TO, not the one that shares its name.
	// run.go declares both readinessAwareHealthHandler (registered) and
	// healthHandler (registered nowhere today), and the first version of this
	// test read the wrong one: it passed while a live agent served
	// "tier_admission": null. The registered name is derived from the
	// HandleFunc("/health", ...) call rather than written here.
	var run *ast.FuncDecl
	byName := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			byName[fn.Name.Name] = fn
			if fn.Name.Name == "Run" {
				run = fn
			}
		}
	}
	if run == nil {
		t.Fatal("run.go no longer declares Run")
	}
	registered := ""
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Value != `"/health"` {
			return true
		}
		if id, ok := call.Args[1].(*ast.Ident); ok {
			registered = id.Name
		}
		return true
	})
	if registered == "" {
		t.Fatal("no HandleFunc(\"/health\", <ident>) in run.go; this test cannot tell which handler serves /health")
	}
	health := byName[registered]
	if health == nil {
		t.Fatalf("/health is registered to %s, which run.go does not declare", registered)
	}
	initPos, nodePos := token.NoPos, token.NoPos
	ast.Inspect(run.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "initTierAdmission":
				initPos = call.Pos()
			case "admitNodeAtBoot":
				nodePos = call.Pos()
			}
		}
		return true
	})
	if initPos == token.NoPos {
		t.Fatal("Run does not call initTierAdmission; the admitter would stay unwired for the life of the process")
	}
	if nodePos == token.NoPos {
		t.Fatal("Run does not call admitNodeAtBoot; the node dimension would never be enforced")
	}
	if nodePos < initPos {
		t.Fatal("admitNodeAtBoot runs before initTierAdmission, i.e. always unwired")
	}
	healthy := false
	ast.Inspect(health.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "tierAdmissionHealth" {
			healthy = true
		}
		return true
	})
	if !healthy {
		t.Fatalf("%s (the handler /health is registered to) does not report tierAdmissionHealth", registered)
	}
}

// driveTierAdmissions is the metric label census's driver for the four #3593
// counters (metric_label_domain_test.go, runEveryDriver): over_limit on the
// 26th Community human, dependency_unreachable on an unknown principal with
// the ledger down, an unwired admitter, a blank org and a blank principal, and
// every allowed source. It restores whatever admitter was wired before.
func driveTierAdmissions(t *testing.T) {
	t.Helper()
	prev := tierAdmitter.Load()
	defer func() {
		if prev == nil {
			tierAdmitter.Store(nil)
		} else {
			tierAdmitter.Store(prev)
		}
	}()
	tierAdmitter.Store(nil)
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "unwired@example.com")

	mem := admission.NewMemoryLedger()
	tierAdmitter.Store(admission.New(mem,
		admission.WithNodeLeases(mem),
		admission.WithTierReader(func(context.Context) license.TierRead { return license.TierRead{Tier: license.TierCommunity} })))
	_ = admitPrincipal(context.Background(), admission.ServicePrincipal, " ", "blank-org")
	_ = admitPrincipal(context.Background(), admission.ServicePrincipal, "drive", " ")
	for i := 0; i <= license.CommunityLimits.MaxHumanPrincipals; i++ {
		_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "h"+strings.Repeat("z", i)+"@example.com")
	}
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "hz@example.com") // seen_set
	_ = admitPrincipal(context.Background(), admission.Node, "drive", "node-one")
	mem.SetDown(true)
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "never-seen@example.com")
	mem.SetDown(false)
	tierAdmitter.Store(admission.New(mem, // a cold process: ledger_existing
		admission.WithTierReader(func(context.Context) license.TierRead { return license.TierRead{Tier: license.TierCommunity} })))
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "hz@example.com")
	ent := admission.New(mem,
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}
		}))
	tierAdmitter.Store(ent)
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "unlimited@example.com")
	// Drive the background-drop counter: an unlimited tier records off the
	// request path, and a record against a DOWN ledger is counted as dropped.
	mem.SetDown(true)
	_ = admitPrincipal(context.Background(), admission.HumanPrincipal, "drive", "dropped@example.com")
	ent.WaitForRecording()
	mem.SetDown(false)
}

// TestCommunitySaaSSelfRegistrationCannotHitTheServicePrincipalCeiling is a
// blast-radius pin, not a feature test.
//
// The community-SaaS deployment (try.getaxonflow.com) lets anyone self-register
// a tenant, and every registered tenant authenticates through Authenticate,
// which now admits a SERVICE PRINCIPAL. The Community ceiling is 5. If those
// tenants shared one organization, the sixth person to sign up would get a 402
// and self-service registration would be over.
//
// They do not share one: validateCommunitySaasAuth sets OrgID == ClientID ==
// TenantID == the per-customer `cs_<uuid>` (auth.go, and deliberately so since
// v9 Phase 6 - the pre-Phase-6 shared constant "community-saas" was an RLS
// data-leak vector). So each tenant is its own organization holding exactly
// ONE service principal, and the ceiling is unreachable however many tenants
// register.
//
// This test asserts that SHAPE against the admission, so that a future change
// which reintroduces a shared org id fails here rather than on the public
// evaluation server. It is one of two independent reasons the fleet is safe;
// the other is that the live community-SaaS deployment holds a licence key
// that resolves to Enterprise, which skips the check entirely - and a test
// that relied on the key would be asserting a fact about a secret, so this
// asserts the structural one.
func TestCommunitySaaSSelfRegistrationCannotHitTheServicePrincipalCeiling(t *testing.T) {
	wireMemoryAdmitter(t, license.TierCommunity)
	// Ten tenants, each with the community-SaaS identity shape.
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("cs_%08d", i)
		if ref := admitPrincipal(context.Background(), admission.ServicePrincipal, id, id); ref != nil {
			t.Fatalf("community-SaaS tenant %d (%s) was refused: %v.\n\n"+
				"Each tenant must be its own organization (OrgID == ClientID), so each holds ONE service "+
				"principal and the Community ceiling of %d is unreachable. A refusal here means the org id "+
				"is shared again, which would end self-service registration at tenant %d on the public "+
				"evaluation server.", i, id, ref, license.CommunityLimits.MaxServicePrincipals,
				license.CommunityLimits.MaxServicePrincipals+1)
		}
	}
	// The control: with a SHARED org id the ceiling IS reached, so the test
	// above is not passing because the limit is unreachable in general.
	for i := 0; i <= license.CommunityLimits.MaxServicePrincipals; i++ {
		ref := admitPrincipal(context.Background(), admission.ServicePrincipal, "shared-org", fmt.Sprintf("cs_%08d", i))
		if i < license.CommunityLimits.MaxServicePrincipals && ref != nil {
			t.Fatalf("shared-org tenant %d was refused early: %v", i, ref)
		}
		if i == license.CommunityLimits.MaxServicePrincipals && ref == nil {
			t.Fatal("with a SHARED org id the ceiling must be reached; it was not, so the assertion above proves nothing")
		}
	}
}

// TestNextOverLimitBeatsBoundsTheSplitBrain is the MAJOR-2 remedy's test. Round
// 2 of the independent R3 found the whole remedy — the reason discrimination,
// the reset, and the stop at ten — unpinned: it is two branches and a counter,
// and a "simplify the heartbeat logging" edit that collapsed them back into a
// single log line would restore the unbounded two-node overlap without turning
// anything red.
//
// The case that matters most is the interleave. A dependency_unreachable beat
// RESETS rather than being skipped, so a flapping link defers the stop forever.
// That is deliberate — an unreachable store must never stop a running node —
// but it is the property most likely to be "tidied" into a skip by someone who
// reads the reset as a bug.
func TestNextOverLimitBeatsBoundsTheSplitBrain(t *testing.T) {
	overLimit := &tierLimitRefusal{Decision: admission.Decision{
		Dimension: admission.Node, Reason: admission.ReasonOverLimit,
	}}
	unreachable := &tierLimitRefusal{Decision: admission.Decision{
		Dimension: admission.Node, Reason: admission.ReasonDependencyUnreachable,
	}}

	t.Run("a renewal resets the count", func(t *testing.T) {
		if beats, stop := nextOverLimitBeats(7, nil); beats != 0 || stop {
			t.Fatalf("got (%d, %v), want (0, false): a renewed lease clears the history", beats, stop)
		}
	})

	t.Run("an unreachable store resets and never stops", func(t *testing.T) {
		if beats, stop := nextOverLimitBeats(nodeOverLimitBeatsBeforeGivingUp-1, unreachable); beats != 0 || stop {
			t.Fatalf("got (%d, %v), want (0, false). A node that cannot reach the lease store has not been told "+
				"it is over the limit, it has been told nothing, and an unreachable store must never stop a "+
				"running node — that is the availability posture the node dimension is built on.", beats, stop)
		}
	})

	t.Run("nine consecutive over-limit beats do not stop, the tenth does", func(t *testing.T) {
		beats, stop := 0, false
		for i := 1; i < nodeOverLimitBeatsBeforeGivingUp; i++ {
			beats, stop = nextOverLimitBeats(beats, overLimit)
			if stop {
				t.Fatalf("stopped at beat %d of %d; the budget exists so a stale lease can expire first",
					i, nodeOverLimitBeatsBeforeGivingUp)
			}
			if beats != i {
				t.Fatalf("beat %d counted as %d", i, beats)
			}
		}
		beats, stop = nextOverLimitBeats(beats, overLimit)
		if !stop || beats != nodeOverLimitBeatsBeforeGivingUp {
			t.Fatalf("got (%d, %v) at the final beat, want (%d, true). Without the stop, two nodes serve one "+
				"single-node licence until someone restarts the process.", beats, stop, nodeOverLimitBeatsBeforeGivingUp)
		}
	})

	t.Run("an unreachable beat interleaved at five defers the stop", func(t *testing.T) {
		beats := 0
		for i := 0; i < 5; i++ {
			beats, _ = nextOverLimitBeats(beats, overLimit)
		}
		if beats != 5 {
			t.Fatalf("five over-limit beats counted as %d", beats)
		}
		beats, stop := nextOverLimitBeats(beats, unreachable)
		if beats != 0 || stop {
			t.Fatalf("got (%d, %v) after an unreachable beat, want (0, false): the count is CONSECUTIVE "+
				"over-limit answers, so anything else clears it", beats, stop)
		}
		// And the budget is now full-length again, not five short.
		for i := 1; i < nodeOverLimitBeatsBeforeGivingUp; i++ {
			beats, stop = nextOverLimitBeats(beats, overLimit)
			if stop {
				t.Fatalf("stopped after only %d beats following the reset; the reset must restore the whole budget", i)
			}
		}
		if _, stop = nextOverLimitBeats(beats, overLimit); !stop {
			t.Fatal("never stopped after a full run of consecutive over-limit beats following a reset")
		}
	})

	t.Run("the budget outlasts one lease TTL", func(t *testing.T) {
		budget := time.Duration(nodeOverLimitBeatsBeforeGivingUp) * admission.NodeHeartbeatInterval
		if budget <= admission.NodeLeaseTTL {
			t.Fatalf("the stop fires after %v, which is not longer than the %v lease TTL. A node must not give up "+
				"before a stale foreign lease could have expired, or a routine redeploy stops the new node.",
				budget, admission.NodeLeaseTTL)
		}
	})
}
