// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// One-call boot wiring for the decision shadow (#3564).
//
// Both binaries that evaluate policy - the agent and the orchestrator - install
// the observer through this function, for the reason compat_bootstrap.go gives
// for the identity adapter: two assemblies drift, and the result is a
// deployment that shadows on one plane and not the other, whose divergence
// report is a statement about which binary was configured rather than about the
// migration.
package planeshadow

import (
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// defaultMatchLogEvery samples the match log line.
//
// A match is the expected outcome on a healthy migration, so logging every one
// puts a line on the log of every governed request. One in ten thousand is
// enough to prove the shadow is alive from outside the process without
// drowning the two classes an operator actually needs to find, which are
// logged in full.
const defaultMatchLogEvery = 10000

// EnvMatchLogEvery overrides the match sampling interval.
//
// It exists because "the shadow ran on this plane and the two engines AGREED"
// is otherwise unobservable from outside the process without a metrics stack:
// agreements are the common case, they are sampled, and a suite asserting that
// a plane was measured cannot tell an agreement from a shadow that never ran.
// The runtime suite sets it to 1. A deployment has no reason to.
const EnvMatchLogEvery = "AXONFLOW_DECISION_SHADOW_MATCH_LOG_EVERY"

// EnvRealm names the trust realm compiled ADR-060 segment groups are qualified
// with. Empty is legacycompile.DefaultRealm.
//
// It is deployment configuration rather than a default each side picks,
// because it changes the IDENTIFIERS the request must use: a corpus built
// against a different realm silently drops every segment-scoped constraint
// from the ADR-065 side while the legacy side still applies it. Both sides
// here take it from the same place, which is what makes that unrepresentable.
const EnvRealm = "AXONFLOW_DECISION_SHADOW_REALM"

// EnvContentTarget names the field path a legacy static redaction targets.
// static_policies stores none - the target was whatever span the detector
// matched - so it has to come from configuration, and BOTH sides must be given
// the same one.
const EnvContentTarget = "AXONFLOW_DECISION_SHADOW_CONTENT_TARGET"

// BootstrapConfig is what a binary knows at boot.
type BootstrapConfig struct {
	// Component names the binary, so a difference can be attributed to a plane
	// rather than to whichever container's log it was read from.
	Component string
	// DB is the platform database the shadow reads policy rows from. Nil means
	// no shadow can run: there is nothing to compile a bundle from.
	DB *sql.DB
	// OrgModes is the per-organization mode source, nil where none exists
	// (every community build, and any deployment with no settings store).
	OrgModes identity.DecisionShadowModeSource
}

// Bootstrap resolves the configuration, assembles the observer and returns it.
//
// It returns an ERROR for every value that decides WHETHER or WHAT is
// measured. The caller turns that into a refusal to boot, for
// ParseCompatMode's reason one axis over: an operator who typed
// AXONFLOW_DECISION_SHADOW_MODE=shadwo believes their planes are being
// measured, and a shim that quietly disabled itself would leave them believing
// it until v11's gate is read off a window that was never open.
//
// It does NOT install the observer. Installation is a separate call so a test
// can build one without touching process state.
func Bootstrap(cfg BootstrapConfig) (*Observer, error) {
	conf, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if cfg.DB == nil {
		// No database, so no policy rows, so no bundle and no comparison.
		//
		// This is NOT an error and it is NOT silent: a no-DB agent is a real
		// deployment shape (the community no-DB mode), the shadow simply has
		// nothing to do there, and the caller logs it. Returning an observer
		// with a nil row source would construct successfully and then fail
		// every single evaluation, which reads on a dashboard as a broken
		// shadow rather than as an absent one.
		return nil, nil
	}
	rows, err := NewDBRowSource(cfg.DB)
	if err != nil {
		return nil, err
	}
	opts := legacycompile.Options{
		Realm:         strings.TrimSpace(os.Getenv(EnvRealm)),
		ContentTarget: strings.TrimSpace(os.Getenv(EnvContentTarget)),
	}
	recorder := MultiRecorder{
		NewLogRecorder(resolveMatchLogEvery(os.Getenv(EnvMatchLogEvery))),
		MetricsRecorder{},
	}
	return NewObserver(conf, rows, recorder,
		WithComponent(cfg.Component),
		WithOrgModes(cfg.OrgModes),
		WithCompileOptions(opts),
	)
}

// resolveMatchLogEvery reads the sampling interval.
//
// An unparseable value falls back to the default rather than refusing to boot,
// which is the opposite of how the MODE is treated and deliberately so: the
// mode decides whether anything is measured, and this decides how chatty a log
// line is. Refusing to start over the second would be a self-inflicted outage.
func resolveMatchLogEvery(raw string) uint64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultMatchLogEvery
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		log.Printf("[DECISION-SHADOW] %s=%q is not a non-negative integer; using the default of %d",
			EnvMatchLogEvery, raw, defaultMatchLogEvery)
		return defaultMatchLogEvery
	}
	return n
}

// InstallProcess installs the observer process-wide and logs what it did.
//
// The startup line is not decoration. "Which mode is this deployment in, on
// which planes, at what sampling rate" is the first question asked of any
// window, and reading it back off a running container is how the runtime suite
// proves the switch it is testing is actually set. It also states the sampling
// rate, because a denominator whose rate is unknown cannot be interpreted at
// all.
func InstallProcess(o *Observer, component string) {
	SetProcessObserver(o)
	if o == nil {
		// The gauge is published EVEN HERE, all-off on every plane. A
		// component that publishes nothing has no series for a rule to
		// evaluate over, and "this process was never wired" would then look
		// identical to "this process is not scraped" and to "this rule file
		// was never loaded". An all-zero gauge is a positive statement; its
		// absence is silence, which is the thing this whole surface exists to
		// stop reading as good news.
		publishMode(component, func(legacycompile.Plane) bool { return true }, identity.CompatModeOff)
		log.Printf("[DECISION-SHADOW] %s: not wired; no plane is dual-evaluated on this process", component)
		return
	}
	// Before the log line, and before any request. See publishMode: the series
	// that says "this plane is watched" has to exist with zero traffic, or the
	// vacuity rule has no left-hand side on the one deployment shape it is
	// about.
	//
	// Read through Mode(), the diagnostics accessor, for the reason the log
	// line below gives: the mode census permits exactly one consultation site
	// besides the accessors, and publishing a gauge is not a reason to add a
	// second.
	publishMode(component, o.cfg.Observes, o.Mode())
	planes := "every implemented plane"
	if o.cfg.Planes != nil {
		names := make([]string, 0, len(o.cfg.Planes))
		for p := range o.cfg.Planes {
			names = append(names, string(p))
		}
		planes = strings.Join(sortedStrings(names), ",")
	}
	perOrg := "no per-org source; the process mode applies to every organization"
	if o.HasPerOrgSource() {
		perOrg = "per-org records override it (identity_org_settings.decision_shadow_mode)"
	}
	// Read through Mode() and HasPerOrgSource(), the diagnostics accessors, NOT
	// off the fields: the AST census permits exactly one reader of each besides
	// them, and a startup log line is not a reason to add a second.
	log.Printf("[DECISION-SHADOW] %s: %s=%s; planes=%s; sample_rate=%.3f; workers=%d; queue=%d; %s",
		component, EnvMode, strings.ToLower(o.Mode().String()), planes,
		o.cfg.SampleRate, o.cfg.Workers, o.cfg.QueueDepth, perOrg)
	if !records(o.Mode()) && !o.HasPerOrgSource() {
		log.Printf("[DECISION-SHADOW] %s: nothing will be compared on this process; ADR-065 gate 18's window does not advance here", component)
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
