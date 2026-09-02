// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// Mode is the shadow mode. It is identity.CompatMode deliberately: one
// vocabulary across both per-organization axes means an operator reading
// "shadow" never has to ask which shadow, and the tri-state rules compat.go
// argues for - membership validation rather than inequality against a zero
// value, an unrecognized value failing towards OFF - apply unchanged.
type Mode = identity.CompatMode

// records reports whether this mode runs the PDP at all.
//
// POSITIVE MEMBERSHIP on the single value that observes, never
// `m != CompatModeOff`. The two differ on every out-of-range value and on the
// Unspecified zero value, and the difference is the safety argument: with
// inequality, a Mode(99) that reached this predicate would start evaluating.
// It is also the enforces()-shaped predicate #3582 established - except that
// the thing it gates is recording, because there is no enforcement here to
// gate. See the package doc: the void return is the stronger guarantee, and
// this predicate is the one that decides whether any work happens.
func records(m Mode) bool { return m == identity.CompatModeShadow }

// EnvMode names the deployment-wide mode variable.
const EnvMode = identity.EnvDecisionShadowMode

// EnvPlanes names the variable that narrows which planes observe.
//
// # WHY A PLANE LIST EXISTS AT ALL
//
// A plane is the unit ADR-065 Phase 4 cuts over, so it is the unit a window is
// accumulated per, and it has to be the unit an operator can withdraw. If a
// single plane produces a flood of not-comparable records, or its worker cost
// is not affordable on one deployment, the alternative to turning that plane
// off is turning the whole window off - and the whole window is what v11 is
// waiting for.
//
// Empty or absent means EVERY implemented plane, which is the default and the
// only value that produces a complete window. A named plane that is not a
// declared one is an ERROR rather than a silently ignored entry: an operator
// who typed "gateway" believes the gateway plane is being measured, and a list
// that dropped the typo would measure nothing while reading as configured.
const EnvPlanes = "AXONFLOW_DECISION_SHADOW_PLANES"

// EnvSampleRate names the per-observation sampling rate variable, a float in
// (0, 1]. Absent means 1.0.
//
// # WHY THE DEFAULT IS 1.0 AND WHY A LOWER VALUE IS RECORDED
//
// The synchronous cost of an observation is a struct build and a channel send;
// the PDP evaluation is not on the request path at all. So a rate below 1.0
// buys nothing on the hot path. What it buys is WORKER cost - fewer OPA
// evaluations per second - which is a real resource on a deployment that
// cannot afford the pool.
//
// It is therefore available, defaulted off, and STAMPED ON EVERY RECORD. A run
// whose sampling rate is unknown cannot have its denominator interpreted: 300
// comparisons at an unknown rate is not a measurement of anything, and gate 18
// is a statement about a population rather than about a sample of unknown
// size. A rate outside (0, 1] is refused rather than clamped: 0 is a deployment
// that believes it is measuring and is not, which is the one state this whole
// package exists to make impossible.
const EnvSampleRate = "AXONFLOW_DECISION_SHADOW_SAMPLE_RATE"

// EnvQueueDepth names the observation queue depth. Absent means
// defaultQueueDepth.
const EnvQueueDepth = "AXONFLOW_DECISION_SHADOW_QUEUE_DEPTH"

// EnvWorkers names the number of evaluation workers. Absent means
// defaultWorkers.
const EnvWorkers = "AXONFLOW_DECISION_SHADOW_WORKERS"

const (
	defaultQueueDepth = 1024
	minQueueDepth     = 1
	maxQueueDepth     = 1 << 16
	defaultWorkers    = 2
	minWorkers        = 1
	maxWorkers        = 64
)

// Config is the resolved deployment configuration.
type Config struct {
	// Mode is the deployment-wide mode. An organization's record composes
	// with it (see Observer.effectiveMode) and wins in both directions.
	Mode Mode
	// Planes is the set of planes that observe. Nil means every implemented
	// plane; an explicit empty set is impossible, because ParsePlanes refuses
	// a list that names nothing.
	Planes map[legacycompile.Plane]bool
	// SampleRate is in (0, 1].
	SampleRate float64
	// QueueDepth bounds the observation queue.
	QueueDepth int
	// Workers is the size of the evaluation pool.
	Workers int
}

// Observes reports whether a plane is in scope for this configuration. A nil
// plane set is every implemented plane, so the zero-configuration deployment
// measures everything rather than nothing.
func (c Config) Observes(p legacycompile.Plane) bool {
	if c.Planes == nil {
		return true
	}
	return c.Planes[p]
}

// ImplementedPlanes returns the planes this package may observe, DERIVED from
// the compiler's plane model rather than listed here.
//
// It is derived because the model is pinned to the tree in both directions -
// legacy_call_sites.tsv names the call sites, a main-module census test proves
// the artifact describes the tree, and TestPlaneModelMatchesTheCensus proves
// the model describes the artifact. A hand-maintained copy here would be a
// third statement with nothing pinning it, and the two failure shapes are both
// silent: an invented plane reads as coverage of a surface that does not
// exist, and a missing one is an enforcement surface nobody diffs.
//
// legacycompile.UnimplementedPlanes is deliberately NOT included.
// connector_execution has no policy-evaluation call site anywhere in the tree,
// and compiling, sampling and counting for it would manufacture a denominator
// out of a surface that does not evaluate policy.
func ImplementedPlanes() []legacycompile.Plane { return legacycompile.AllPlanes() }

// ParsePlanes parses the comma-separated plane list.
func ParsePlanes(raw string) (map[legacycompile.Plane]bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	declared := map[legacycompile.Plane]bool{}
	for _, p := range ImplementedPlanes() {
		declared[p] = true
	}
	out := map[legacycompile.Plane]bool{}
	for _, field := range strings.Split(raw, ",") {
		name := legacycompile.Plane(strings.ToLower(strings.TrimSpace(field)))
		if name == "" {
			continue
		}
		if _, unimplemented := legacycompile.UnimplementedPlanes[name]; unimplemented {
			return nil, fmt.Errorf(
				"planeshadow: %s names plane %q, which ADR-065 Phase 4 lists but which has NO policy-evaluation call site in this tree; there is nothing on it to dual-evaluate (see legacycompile.UnimplementedPlanes and #3564)",
				EnvPlanes, name)
		}
		if !declared[name] {
			return nil, fmt.Errorf(
				"planeshadow: %s names plane %q, which is not a declared enforcement plane; the declared planes are %v",
				EnvPlanes, name, planeNames())
		}
		out[name] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"planeshadow: %s=%q names no plane; leave it unset to observe every plane rather than setting a list that measures nothing",
			EnvPlanes, raw)
	}
	return out, nil
}

func planeNames() []string {
	out := make([]string, 0, len(ImplementedPlanes()))
	for _, p := range ImplementedPlanes() {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}

// ParseSampleRate parses the sampling rate. Empty is 1.0.
func ParseSampleRate(raw string) (float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1.0, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("planeshadow: %s=%q is not a number", EnvSampleRate, raw)
	}
	if v <= 0 || v > 1 {
		return 0, fmt.Errorf(
			"planeshadow: %s=%v is outside (0, 1]; a rate of 0 is a deployment that believes it is measuring and is not, and gate 18 cannot be read off an empty denominator - set %s=off instead",
			EnvSampleRate, v, EnvMode)
	}
	return v, nil
}

// ConfigFromEnv resolves the deployment configuration.
//
// It returns an ERROR rather than falling back for every value that decides
// WHETHER or WHAT is measured - the mode, the plane list, the sampling rate -
// and clamps the two that decide only how the work is scheduled. The wiring
// turns an error into a refusal to boot: a deployment that mistyped its shadow
// configuration must find out at boot, not from a window that turns out to
// have been empty when v11's gate is read.
func ConfigFromEnv() (Config, error) {
	mode, err := identity.ParseDecisionShadowMode(os.Getenv(EnvMode))
	if err != nil {
		return Config{}, err
	}
	planes, err := ParsePlanes(os.Getenv(EnvPlanes))
	if err != nil {
		return Config{}, err
	}
	rate, err := ParseSampleRate(os.Getenv(EnvSampleRate))
	if err != nil {
		return Config{}, err
	}
	return Config{
		Mode:       mode,
		Planes:     planes,
		SampleRate: rate,
		QueueDepth: clampEnvInt(EnvQueueDepth, defaultQueueDepth, minQueueDepth, maxQueueDepth),
		Workers:    clampEnvInt(EnvWorkers, defaultWorkers, minWorkers, maxWorkers),
	}, nil
}

// clampEnvInt reads a bounded integer, falling back to the default on anything
// unparseable. These two decide how the work is SCHEDULED and never whether it
// happens, so a bad value costs throughput rather than evidence - the same
// reasoning identity's resolveOrgSettingsTTL gives for clamping rather than
// refusing.
func clampEnvInt(env string, def, lo, hi int) int {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
