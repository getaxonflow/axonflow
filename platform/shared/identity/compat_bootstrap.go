// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// One-call boot wiring for the compatibility adapters (#3550).
//
// Both binaries that resolve a caller's identity - the agent and the
// orchestrator - install the adapter through this function. They do not each
// assemble a registry, a realm source and a recorder, because two assemblies
// drift: one deployment ends up shadowing on one plane and off on the other,
// and the resulting divergence report is a statement about which binary was
// configured rather than about the platform.
package identity

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultAgreementLogEvery samples the agreement log line. One line per
// hundred thousand agreements is enough to prove the adapter is alive without
// putting a line on the authentication path of every request.
const defaultAgreementLogEvery = 100000

// EnvAgreementLogEvery overrides the agreement sampling interval.
//
// It exists because "the adapter ran on this path and AGREED" is otherwise
// unobservable from outside the process: agreements are the common case, they
// are sampled at one in a hundred thousand, and a suite asserting that a path
// was evaluated cannot tell an agreement from an adapter that never ran. The
// runtime suite sets it to 1. A deployment has no reason to.
const EnvAgreementLogEvery = "AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY"

// resolveAgreementLogEvery reads the sampling interval.
//
// An unparseable or negative value falls back to the default rather than
// refusing to boot, which is the opposite of how the MODE is treated and
// deliberately so: the mode decides whether authentication changes, and a
// sampling interval decides how chatty a log line is. Refusing to start over
// the second would be a self-inflicted outage.
func resolveAgreementLogEvery(raw string) uint64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultAgreementLogEvery
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		log.Printf("[IDENTITY-COMPAT] %s=%q is not a non-negative integer; using the default of %d",
			EnvAgreementLogEvery, raw, defaultAgreementLogEvery)
		return defaultAgreementLogEvery
	}
	return n
}

// CompatBootstrapConfig is what a binary knows at boot.
type CompatBootstrapConfig struct {
	// RawMode is the configured mode string, normally os.Getenv(EnvCompatMode).
	RawMode string
	// RawPaths narrows which legacy credential paths evaluate (#3634).
	// Normally os.Getenv(EnvCompatPaths). Empty means every path.
	RawPaths string
	// RawEnforceReasons narrows what enforce refuses. Empty means every
	// reason. See EnvEnforceReasons.
	RawEnforceReasons string
	// Deployment describes what this deployment actually wired, and is what
	// the built-in realms are derived from.
	Deployment BuiltinRealmDeployment
	// ExtraRealmSources builds the sources consulted after the built-ins, in
	// order. The enterprise OIDC realm source goes here.
	//
	// It is a FUNCTION of the registry rather than a slice because a realm
	// source registers into the registry, and the registry is created here.
	// The alternative - construct the adapter, then attach sources to it -
	// would make the adapter's source list mutable after the first request has
	// already been served against it, which is a realm set that changes under
	// a running verification.
	ExtraRealmSources func(reg *RealmRegistry) ([]CompatRealmSource, error)
	// Revocations is the oracle consulted for realms declaring a revocation
	// source. Nil is legitimate for a deployment whose realms all declare
	// RevocationSourceNone; it is an outage for one that does not.
	Revocations RevocationOracle
	// Component names the binary. It reaches the startup log line AND every
	// counterfactual, so a divergence can be attributed to a plane.
	Component string
	// OrgModes is the per-organization mode source (session ADR65-I). Nil
	// means the process mode is the whole answer for every organization,
	// which is every community build. See compat_org_mode.go for the
	// composition rule.
	OrgModes CompatOrgModeSource
}

// CompatBootstrap is the assembled wiring, returned so a test or an operator
// command can read the recorder's counters and inspect the registry.
type CompatBootstrap struct {
	// Mode is the parsed mode.
	Mode CompatMode
	// EnforceReasons is the parsed allow-list; nil means every reason.
	EnforceReasons []AdmissionReason
	// Registry holds the declared realms.
	Registry *RealmRegistry
	// Recorder is the default log recorder.
	Recorder *LogCounterfactualRecorder
	// Adapter is the assembled adapter.
	Adapter *CompatAdapter
	// Realms is the realm source the adapter establishes an organization's
	// realms through. Exposed for the CAEP push receiver, which must
	// establish them BEFORE resolving a SET's issuer: the adapter registers
	// realms lazily on the first evaluating request, so on a deployment
	// whose mode is off nothing else ever would, and every push would read
	// as an undeclared issuer.
	Realms CompatRealmSource
	// Paths is the parsed per-path lever (#3634); nil means every path.
	Paths map[LegacyPath]bool
	// PerOrg reports whether a per-organization mode source was wired.
	PerOrg bool
}

// BootstrapCompat parses the mode, assembles the adapter, and returns it.
//
// IT RETURNS AN ERROR ON AN UNRECOGNIZED MODE, and the caller's contract is to
// refuse to boot. Falling back to off would leave an operator who typed
// "enfore" believing their deployment enforces; falling back to enforce would
// take their authentication down. Neither is a guess worth making, and a
// deployment that will not start is the one failure mode an operator notices
// immediately.
//
// IT ALSO REFUSES `enforce` BY NAME ON THIS PATH (#3633), which is the whole
// of the asymmetry this closes. The decision axis has always refused its
// process-wide enforce at parse (ParseDecisionShadowMode, decision_shadow_mode.go),
// while the identity axis accepted it in one unconditioned call: an operator
// could set AXONFLOW_IDENTITY_COMPAT_MODE=enforce and the process began
// refusing requests at boot, with no shadow phase behind it, no observed
// denominator, and nothing recorded about why it was safe.
//
// THE REFUSAL IS HERE, NOT IN ParseCompatMode, and that placement is the
// design. ParseCompatMode serves TWO callers: this process-wide boot path and
// the per-organization stored value, which reads a mode a reviewer set through
// the customer-portal handler against the full observed gate (shadow first, a
// non-zero organic denominator, zero unexplained divergences, an enforce-reason
// set, audited). Refusing inside the shared parser would take the per-org route
// away with it and leave no route to enforce at all. So the parser stays
// three-valued and the BOOT path is narrowed, which is exactly the split the
// two axes already have.
//
// It does NOT install the adapter. Installation is a separate call so a test
// can build one without touching process state.
func BootstrapCompat(cfg CompatBootstrapConfig) (*CompatBootstrap, error) {
	mode, err := ParseCompatMode(cfg.RawMode)
	if err != nil {
		return nil, err
	}
	if mode == CompatModeEnforce {
		// POSITIVE MEMBERSHIP ON THE ONE VALUE THAT ENFORCES, never
		// `mode != CompatModeShadow && mode != CompatModeOff`: the two differ
		// on CompatMode(99) and on the Unspecified zero value, and an
		// inequality that happens to be true for those would admit them. The
		// parser cannot return either today, and this must not become the
		// reason that stays true.
		return nil, fmt.Errorf(
			"identity: %s=enforce is not available at boot: process-wide enforcement would refuse requests "+
				"before any shadow phase has measured what it would refuse, on every organization at once. "+
				"Enforcement is granted per organization, through the identity settings surface, and only "+
				"where that organization is already in shadow with a non-zero observed denominator, zero "+
				"unexplained divergences and %s set; use shadow here to measure it",
			EnvCompatMode, EnvEnforceReasons)
	}
	registry := NewRealmRegistry()
	var extra []CompatRealmSource
	if cfg.ExtraRealmSources != nil {
		extra, err = cfg.ExtraRealmSources(registry)
		if err != nil {
			return nil, err
		}
	}
	source, err := NewBuiltinRealmSource(registry, cfg.Deployment, extra...)
	if err != nil {
		return nil, err
	}
	recorder := NewLogCounterfactualRecorder(resolveAgreementLogEvery(os.Getenv(EnvAgreementLogEvery)))
	reasons, err := ParseEnforceReasons(cfg.RawEnforceReasons)
	if err != nil {
		return nil, err
	}
	// FATAL ON AN UNRECOGNIZED PATH, for the reason the mode is fatal on an
	// unrecognized spelling: an operator who narrowed to a path name that
	// matches nothing believes that path is being measured, and a list that
	// silently dropped the entry would measure fewer paths than the operator
	// reads off their own configuration. The error is returned, and this
	// function's contract is that the caller refuses to boot.
	paths, err := ParseCompatPaths(cfg.RawPaths)
	if err != nil {
		return nil, err
	}
	// THE FAN-OUT IS THE WHOLE METRICS WIRING (#3602).
	//
	// The log recorder and the Prometheus recorder see the SAME record, in the
	// same call, so the two tallies cannot disagree about what happened - which
	// is why the metric is not derived from the log recorder's Snapshot. It is
	// assembled here rather than at each binary for the reason this file exists
	// at all: two assemblies drift, and a deployment exporting compat metrics
	// from the agent and not from the orchestrator would produce a window whose
	// denominator is a statement about which binary was configured.
	//
	// Order matters only for the log: the log recorder is first so a divergence
	// line is emitted before the counter moves, which is the order an operator
	// reading a log next to a graph expects.
	fanout := MultiCounterfactualRecorder{recorder, PrometheusCounterfactualRecorder{}}
	opts := []CompatAdapterOption{
		WithCompatComponent(cfg.Component),
		WithCompatEnforceReasons(reasons),
		WithCompatPaths(paths),
	}
	if cfg.Revocations != nil {
		opts = append(opts, WithCompatRevocations(cfg.Revocations))
	}
	if cfg.OrgModes != nil {
		opts = append(opts, WithCompatOrgModes(cfg.OrgModes))
	}
	adapter, err := NewCompatAdapter(mode, registry, source, fanout, opts...)
	if err != nil {
		return nil, err
	}
	return &CompatBootstrap{
		Mode: mode, EnforceReasons: reasons, Registry: registry, Recorder: recorder, Adapter: adapter,
		Realms: source, PerOrg: cfg.OrgModes != nil,
		Paths: paths,
	}, nil
}

// InstallProcessCompat installs the adapter as the process adapter and logs
// what it did.
//
// The startup line is not decoration. "Which mode is this deployment in" is
// the first question asked of every divergence report, and reading it back off
// a running container is how #3062's e2e proves the gate it is testing is
// actually set. Since session ADR65-I it also says whether a per-organization
// source is wired, because "the process mode is off" is no longer the whole
// answer on a deployment where it is.
func (b *CompatBootstrap) InstallProcessCompat(component string) {
	if b == nil {
		return
	}
	SetProcessCompatAdapter(b.Adapter)
	// The mode gauge is published HERE, at install, and not on the first
	// request. A process that never serves an evaluating request is exactly the
	// state the observation window has to be able to name, so the series that
	// says "this process is in shadow" must exist before any traffic does. See
	// compat_metrics.go's compatModeGauge.
	publishCompatMode(component, b.Mode)
	// Read off the bootstrap, NOT off the adapter's field: the AST census in
	// compat_org_mode_test.go permits exactly one reader of that field, and
	// a startup log line is not a reason to add a second.
	perOrg := "no per-org source; the process mode applies to every organization"
	if b.PerOrg {
		perOrg = "per-org records override it (identity_org_settings)"
	}
	log.Printf("[IDENTITY-COMPAT] %s: %s=%s (%s); %s", component, EnvCompatMode, b.Mode,
		compatModeDescription(b.Mode), perOrg)
	if b.Mode == CompatModeEnforce && len(b.EnforceReasons) > 0 {
		log.Printf("[IDENTITY-COMPAT] %s: %s=%v (every OTHER reason is recorded and NOT applied)",
			component, EnvEnforceReasons, b.EnforceReasons)
	}
	// A NARROWED PATH LIST IS SAID OUT LOUD, AND THE OMITTED PATHS ARE NAMED.
	//
	// Logged only when narrowed, following the enforce-reason line above: a
	// line on every boot saying "every path, as usual" is noise that teaches a
	// reader to skip the line, and this one has to be readable in the incident
	// it was set during. What an operator needs then is not what is being
	// measured but what has STOPPED being measured - a path recording nothing
	// looks identical to a path that never diverges, and the two are opposite
	// conclusions.
	if len(b.Paths) > 0 {
		var on, off []string
		for _, p := range legacyPaths {
			if b.Paths[p] {
				on = append(on, string(p))
				continue
			}
			off = append(off, string(p))
		}
		sort.Strings(on)
		sort.Strings(off)
		log.Printf("[IDENTITY-COMPAT] %s: %s=%s narrows compat to %v; %v evaluate as OFF and record NOTHING "+
			"(no evidence, which is not the same as clean evidence) until this variable is unset",
			component, EnvCompatPaths, strings.Join(on, ","), on, off)
	}
}

// compatModeDescription spells out the consequence of each mode, so the
// startup line answers "and what does that mean" without a doc lookup.
func compatModeDescription(m CompatMode) string {
	switch m {
	case CompatModeOff:
		return "identity-plane verification does not run; legacy authentication is unchanged"
	case CompatModeShadow:
		return "identity-plane verification runs and is RECORDED ONLY; legacy authentication decides every request"
	case CompatModeEnforce:
		return "identity-plane verification runs and REFUSES requests legacy would have accepted"
	default:
		return "unrecognized"
	}
}

// BootstrapCompatFromEnv is the ordinary call: read the mode from the
// environment, assemble, install, and refuse to boot on a bad mode.
//
// It returns the bootstrap for a caller that has something to do with it. The
// agent now holds it (session ADR65-I): the CAEP push endpoint verifies
// issuers against the bootstrap's registry, which is the reader #3582 said
// should be the one to start holding it. The orchestrator still discards it.
//
// orgModes is the per-organization mode source; nil means the process mode
// alone (every community build).
// EnvCompatConfig returns the ENVIRONMENT-DERIVED half of a bootstrap config,
// and it exists because there is more than one binary and they drifted.
//
// The agent bootstraps through BootstrapCompatFromEnv; the orchestrator builds
// its own CompatBootstrapConfig because it wires a different realm deployment
// and no revocation oracle. Both read the same variables, so both had a copy of
// the list - and when AXONFLOW_IDENTITY_COMPAT_PATHS was added (#3634) only one
// copy grew. The lever was declared in compose for both services, documented as
// applying to both, and read by ONE: the orchestrator kept evaluating every
// path, and its compose line was dead configuration that changed nothing
// observable.
//
// One reader means the next variable cannot drift the same way. Callers fill
// the non-environment fields on the returned value.
func EnvCompatConfig() CompatBootstrapConfig {
	return CompatBootstrapConfig{
		RawMode:           os.Getenv(EnvCompatMode),
		RawEnforceReasons: os.Getenv(EnvEnforceReasons),
		RawPaths:          os.Getenv(EnvCompatPaths),
	}
}

func BootstrapCompatFromEnv(component string, dep BuiltinRealmDeployment, extra func(*RealmRegistry) ([]CompatRealmSource, error), revocations RevocationOracle, orgModes CompatOrgModeSource) (*CompatBootstrap, error) {
	cfg := EnvCompatConfig()
	cfg.Deployment = dep
	cfg.ExtraRealmSources = extra
	cfg.Revocations = revocations
	cfg.Component = component
	cfg.OrgModes = orgModes
	b, err := BootstrapCompat(cfg)
	if err != nil {
		return nil, err
	}
	b.InstallProcessCompat(component)
	return b, nil
}

// compatRealmTimeout bounds how long establishing an organization's realms may
// take on the authentication path.
//
// It is a bound ON TOP OF the caller's, not a replacement for it: the derived
// context still inherits the parent's cancellation, so an already-cancelled
// caller gets an immediately-failed EnsureRealms. That is correct for the
// storage read it wraps.
//
// What survives cancellation is the RECORDING, and that is a separate fact:
// record() runs on every branch and the recorder does not consult a context, so
// a shadow phase does not go blind exactly when requests start being cancelled.
// The bound exists because a caller with no request context at all
// (adaptedValidateUserToken has none, deliberately) would otherwise have none.
const compatRealmTimeout = 2 * time.Second

// boundedRealmContext derives the context the realm source runs under.
func boundedRealmContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(nonNilContext(ctx), compatRealmTimeout)
}

// nonNilContext is context.Background() for a nil context.
//
// A named helper because two callers need it and one of them
// (CompatAdapter.effectiveMode) needs a DIFFERENT derivation on top of it -
// context.WithoutCancel, because a configuration read must not be poisoned for
// a whole TTL window by one client disconnect. Inlining the nil check at both
// would be two copies of the same guard, one of which would eventually be the
// one that was not updated.
func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
