// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package heartbeat is the ONE platform-class telemetry emitter.
//
// # WHY IT EXISTS
//
// platform/agent/startup_telemetry.go and platform/orchestrator/
// startup_telemetry.go were near-duplicates: two copies of the stamp file, the
// rate-limit gate, the opt-out gate, the CI auto-suppress, the environment-class
// detection and the POST. The copies had already drifted — the orchestrator
// omitted org_id, so classifier rules 6 and 7 could never fire on an
// orchestrator row and AxonFlow-operated orchestrators were held internal only
// by the legacy rule 8 that digest.go documents as retiring (#3660 census
// finding 2). The gateway adapters (#2886) were about to become a third
// emitter. Extracting rather than copying is what makes a fix to any of the
// above land in every emitter at once.
//
// # THE PRIVACY COMMITMENTS, VERBATIM FROM #2004 AND UNCHANGED
//
//   - Classification-only payload — no URLs, tokens, secrets, customer data,
//     prompts, schemas, tenant IDs, request IDs, plugin lists, hostnames, or
//     hashes of any of those.
//   - Single opt-out: AXONFLOW_TELEMETRY=off (the same env var the SDKs use).
//   - Transparent on delivery — the disclosure line and the exact JSON payload
//     are printed on every send, so an operator reading stderr can audit what
//     leaves.
//   - Rate-limited per binary — at most one ping per binary per 7 days, gated
//     by a stamp file.
//   - No persistent state beyond that stamp file.
//
// # WHAT CHANGED IN #3660
//
//  1. The community-SaaS early return is GONE. It skipped emission entirely on
//     AxonFlow-operated stacks, which made the platform table's deployment-mode
//     column single-valued by construction — the one value it could hold was
//     the one value it was never asked to report. Those stacks now report, and
//     the receiver classifies them internal from their org_id (`axonflow-`
//     prefix, telemetry-filter rule 6). Suppressing at the emitter destroyed
//     the datum; classifying at the receiver keeps it and labels it.
//  2. Every emitter reports `edition` and `platform_deployment_mode`, so a row
//     can finally say which build, configured which way, produced it.
//
// The CI auto-suppress is NOT one of the things that changed. It is still here
// and still fires: CI runs are not deployments and their pings are noise.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"axonflow/platform/shared/deploymode"
)

// Telemetry destination + cadence. Declared as var (not const) so tests can
// override; production code never mutates them.
var (
	// DefaultEndpoint is the central checkpoint receiver. Override via
	// AXONFLOW_CHECKPOINT_URL — the same env var the language SDKs honor —
	// for staging-checkpoint runtime tests or air-gapped deployments.
	DefaultEndpoint = "https://checkpoint.getaxonflow.com/v1/ping"

	// Interval is the per-binary rate limit. The same 7-day cap the SDK
	// heartbeat uses; together the two give the analytics warehouse one
	// reading per (deployment, week) without flooding.
	Interval = 7 * 24 * time.Hour

	// HTTPTimeout bounds the network call so a wedged checkpoint endpoint never
	// blocks startup. Heartbeat is fire-and-forget — a timeout is logged but
	// does not fail startup.
	HTTPTimeout = 5 * time.Second
)

// Topology deployment-mode buckets — the `deployment_mode` wire field.
//
// THIS IS NOT PlatformDeploymentMode. It is the coarse TOPOLOGY the row was
// emitted from, and it shares its vocabulary with the SDK heartbeats
// (self_hosted | community_saas | unknown), which derive it from the endpoint
// URL they were pointed at. A platform binary knows the answer directly.
const (
	TopologySelfHosted    = "self_hosted"
	TopologyCommunitySaaS = "community_saas"
)

// Component identifiers — the `component` wire field, gated at ingest by
// telemetry.ValidComponents. Mirrored here because the platform module cannot
// import the checkpoint-service module; the two copies are pinned by
// TestComponentVocabularyMatchesTheContract in vocabulary_pin_test.go, which
// meets the receiver through the contract doc. A component the receiver does
// not know is answered with HTTP 400 and this emitter swallows a non-2xx, so
// the symptom of drift here is a binary that never appears in any analytics.
const (
	ComponentAgent           = "agent"
	ComponentOrchestrator    = "orchestrator"
	ComponentGatewayAdapters = "gateway-adapters"
)

// AllComponents returns every platform component identifier, sorted.
//
// It exists so the vocabulary pin can be a CENSUS rather than a list retyped in
// a test: a fourth emitter added to the constants above lands in this slice
// automatically, and the pin then fails until the receiving contract knows
// about it too. A test enumerating the constants by hand would have gone on
// passing while the new component's pings were answered HTTP 400 — which this
// emitter swallows, so nothing would have said so.
func AllComponents() []string {
	out := []string{ComponentAgent, ComponentGatewayAdapters, ComponentOrchestrator}
	sort.Strings(out)
	return out
}

// maxCoarseEnumValueBytes mirrors telemetry.MaxCoarseEnumValueBytes: the
// contract bound on every coarse-enum string.
//
// It is applied HERE, on the emitting side, for a reason the receiver's copy
// cannot cover: the orchestrator does not validate DEPLOYMENT_MODE (only the
// agent refuses to boot on an unrecognised value), so an operator's 10 KB typo
// would otherwise be serialised into a ping. Capping before serialisation
// means an oversized value never leaves the binary; the receiver's copy is the
// backstop for values relayed by clients we do not control.
const maxCoarseEnumValueBytes = 64

// Payload is the wire shape POSTed to /v1/ping. It mirrors the platform-class
// subset of telemetry.PingRequest in
// ee/platform/checkpoint-service/pkg/telemetry/telemetry.go; omitempty matches
// the server-side struct so the bytes are identical for an unset field.
//
// EVERY OPTIONAL FIELD IS omitempty AND EVERY CALLER LEAVES UNKNOWNS EMPTY.
// Absent means "not reported"; it must never be filled with a default. A
// binary that cannot determine its licence tier omits it — writing "Community"
// there would be a false claim about a customer's deployment, and the receiver
// preserves omission precisely so it can be read as "unknown" rather than as
// any particular value.
type Payload struct {
	TelemetryType   string `json:"telemetry_type"`
	SDK             string `json:"sdk"`
	SDKVersion      string `json:"sdk_version"`
	Component       string `json:"component"`
	PlatformVersion string `json:"platform_version,omitempty"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	RuntimeVersion  string `json:"runtime_version"`
	DeploymentMode  string `json:"deployment_mode"`
	// OrgID is the org_id baked into the binary's deployed licence, read once
	// from the ORG_ID env var. Every AxonFlow-operated deployment (customer-
	// facing demos plus internal CI / canary / perf-bench) uses an org_id
	// starting with `axonflow-` (ADR-054, issue #2259), so the receiver's
	// classifier (telemetry-filter IsInternal rule 6) flips the row to
	// source=internal at write time. Empty on community-mode binaries with no
	// licence, and on any deployment that never set the variable.
	OrgID string `json:"org_id,omitempty"`
	// Edition is the build this binary was compiled from. See
	// platform/shared/edition.
	Edition string `json:"edition,omitempty"`
	// PlatformDeploymentMode is this deployment's own DEPLOYMENT_MODE, resolved
	// to its canonical spelling. Omitted when the variable is unset — see
	// PlatformDeploymentMode() for why that is not the same as `community`.
	PlatformDeploymentMode string `json:"platform_deployment_mode,omitempty"`
	LicenseTier            string `json:"license_tier,omitempty"`
	EnvironmentClass       string `json:"environment_class,omitempty"`
	InstanceID             string `json:"instance_id"`
	Stream                 string `json:"stream,omitempty"`
}

// Config is what a caller must supply to send one platform-class ping.
//
// Everything a caller CAN determine, it supplies; everything derivable from
// the process environment is derived here so the three emitters cannot answer
// it differently.
type Config struct {
	// Component is which binary is emitting — one of the Component* constants.
	Component string

	// StampFilename is the per-binary stamp file name inside the resolved stamp
	// directory. Per-binary so a host running the agent AND the orchestrator
	// emits one ping per binary per 7 days rather than one combined ping.
	StampFilename string

	// PlatformVersion is required by the receiver for platform-class pings: a
	// row with no version dimension is unusable for the adoption analysis that
	// is the entire point of platform telemetry, so the wire REJECTS an empty
	// one rather than persisting a useless row.
	PlatformVersion string

	// Edition is the build. Callers compiled from the platform module pass
	// edition.Current; the gateway-adapters binary, which is not built with the
	// enterprise tag despite being Enterprise-only, passes its artifact's
	// edition explicitly.
	Edition string

	// LicenseTier is the RAW runtime-effective tier, normalised here through
	// the same closed enum the receiver applies. Empty when the caller has no
	// way to determine it, which is reported as absent rather than as a tier.
	LicenseTier string

	// InstanceIDPrefix labels the crypto/rand fallback instance id so a
	// catastrophic rand failure is attributable to a binary. Optional.
	InstanceIDPrefix string

	// OrgID overrides the ORG_ID environment variable, and a caller that reads
	// its org from anywhere else MUST set it.
	//
	// THIS FIELD EXISTS BECAUSE ITS ABSENCE WAS A SHIPPED DEFECT, TWICE. The
	// classifier decides internal-vs-external adoption from org_id: an
	// AxonFlow-operated deployment uses an org starting with `axonflow-`
	// (ADR-054, #2259) and telemetry-filter rule 6 flips the row to
	// source=internal. A binary that sends NO org_id is therefore counted as
	// external adoption — a house deployment inflating the customer number it
	// is supposed to be excluded from.
	//
	// #3662 fixed exactly that on the orchestrator. The gateway-adapters binary
	// then reintroduced it from the other side: it reads AXONFLOW_ORG_ID (its
	// whole config is AXONFLOW_-prefixed), while BuildPayload's env fallback
	// reads ORG_ID, so its ping carried an empty org_id in every deployment.
	// The env fallback below is kept for the callers that do use ORG_ID, but a
	// caller whose org lives under a different name must pass it here — the
	// fallback cannot guess the variable a binary happens to use.
	OrgID string
}

// Stamp is the on-disk persisted state: the instance id carried across
// restarts (the #2004 amendment-locked behaviour, which diverges from the SDK
// pattern of regenerating it per call) and the last-sent timestamp for the
// 7-day rate limit. Deliberately simple key=value lines so an operator can
// `cat` the file and audit it.
type Stamp struct {
	InstanceID string
	LastSent   time.Time
}

// ResolveStampPath returns the stamp file path for a binary. An empty return
// means "no persistent home" (e.g. AWS Lambda where HOME is unset); the rate
// limit then degrades to per-process, the same approach the SDKs take.
//
// AXONFLOW_TELEMETRY_STAMP_DIR is the operator control surface and the ONLY
// persistence override: point it at a writable path and the per-binary
// filename is constructed inside it. Production operators use it when the
// host's user-cache dir is ephemeral; runtime-e2e bundles use it to point at a
// tempdir for hermetic tests.
func ResolveStampPath(stampFilename string) string {
	if dir := os.Getenv("AXONFLOW_TELEMETRY_STAMP_DIR"); dir != "" {
		return filepath.Join(dir, stampFilename)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(cacheDir, "axonflow", stampFilename)
}

// ReadStamp loads the persisted stamp. An absent file returns an empty stamp
// and a nil error — that is "send a fresh ping" semantics. A parse error is
// tolerated field-by-field for the same reason: the alternative to a
// best-effort read is silently never pinging again.
func ReadStamp(path string) (Stamp, error) {
	if path == "" {
		return Stamp{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Stamp{}, nil
		}
		return Stamp{}, err
	}
	var stamp Stamp
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "instance_id":
			stamp.InstanceID = v
		case "last_sent":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				stamp.LastSent = t
			}
		}
	}
	return stamp, nil
}

// WriteStamp persists the stamp via tmp+rename so a concurrent reader never
// observes torn state. A failed write is non-fatal — the next process retries
// on schedule, which beats a panic at startup.
func WriteStamp(path string, stamp Stamp) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "startup-telemetry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup on any error path; the rename below removes it on
	// success, so this Remove typically no-ops. Errors here are not actionable.
	defer func() { _ = os.Remove(tmpName) }()
	body := fmt.Sprintf("instance_id=%s\nlast_sent=%s\n",
		stamp.InstanceID, stamp.LastSent.UTC().Format(time.RFC3339))
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// GenerateInstanceID returns a UUIDv4 from crypto/rand, used once per stamp-file
// lifetime. Stamp-file deletion (volume rotation, a container restart with an
// ephemeral filesystem) mints a new id on the next send — an acceptable
// anti-longitudinal property per the #2004 amendment.
func GenerateInstanceID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// A crypto/rand failure is catastrophic — fall back to a timestamp-based
		// id rather than a zero-filled UUID that would collide across every
		// affected host.
		if prefix == "" {
			prefix = "platform"
		}
		return fmt.Sprintf("%s-fallback-%d", prefix, time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Enabled reports whether this process may emit.
//
// AXONFLOW_TELEMETRY=off is the SOLE USER-FACING opt-out — the same lever the
// SDKs honor. Casing-tolerant on "off"; any other value (including "true",
// "0", "no", empty) leaves telemetry on. There is no programmatic disable, no
// DO_NOT_TRACK, and no mode-based suppression for users.
//
// CI-environment auto-suppress (defence in depth, added 2026-05-13): in a
// Continuous Integration environment the platform binary refuses to emit even
// when AXONFLOW_TELEMETRY is not explicitly set. CI runs are not real customer
// deployments and their pings pollute the adoption signal — 300+ rows landed in
// prod-checkpoint-telemetry-events from GitHub Actions runners during one week
// of 2026-05. Honored signals:
//
//   - CI=true             (GitHub Actions, GitLab, CircleCI, Travis, …)
//   - GITHUB_ACTIONS=true (the GitHub Actions runner specifically)
//
// Either disables emission UNLESS the operator explicitly set
// AXONFLOW_TELEMETRY=on, which takes precedence for the rare self-hosted CI
// that legitimately wants to emit. Plain AXONFLOW_TELEMETRY=off still wins.
//
// CI=true / GITHUB_ACTIONS=true are NOT new user-facing opt-outs — operators of
// real deployments should never set them, and standard runners set them
// automatically. The check exists because docker compose / kubectl / ECS task
// defs commonly drop env vars on the floor; CI conventions are a complementary
// signal the binary can detect from inside its own container without trusting
// the deploy pipeline.
func Enabled() bool {
	// Explicit user opt-in / opt-out wins over the CI auto-detect.
	val := strings.TrimSpace(os.Getenv("AXONFLOW_TELEMETRY"))
	if strings.EqualFold(val, "off") {
		return false
	}
	if strings.EqualFold(val, "on") {
		return true
	}
	// Unset (or any non-on/off value) falls through to the CI auto-suppress.
	// Presence-only, not value-equals, because some CI systems set CI=1 / CI=yes
	// / CI=github-actions. An explicit CI=false / GITHUB_ACTIONS=false is
	// treated as "not in CI".
	if v := strings.TrimSpace(os.Getenv("GITHUB_ACTIONS")); v != "" && !strings.EqualFold(v, "false") {
		return false
	}
	if v := strings.TrimSpace(os.Getenv("CI")); v != "" && !strings.EqualFold(v, "false") {
		return false
	}
	return true
}

// PlatformDeploymentMode returns this process's own DEPLOYMENT_MODE, resolved
// to its canonical spelling, for the `platform_deployment_mode` wire field.
//
// THREE OUTCOMES, AND THE FIRST IS THE ONE THAT MATTERS:
//
//   - UNSET → "" (the field is OMITTED from the payload). It does NOT report
//     `community`. deploymode.Unset resolves an empty value to `community` for
//     SCHEMA selection, but that is a decision about which migrations to apply,
//     not a statement about what the operator configured — and the RUNTIME
//     posture for an unset value is the enterprise one, not the community one
//     (the measured divergence in issue #3128). Reporting `community` here
//     would publish a claim the deployment itself disagrees with, on the
//     dimension the field exists to measure.
//   - RECOGNISED → the canonical mode, with aliases folded (`enterprise` →
//     `in-vpc-enterprise`), because counting one population under two spellings
//     is the same defect as not counting it.
//   - UNRECOGNISED → "unknown". The agent refuses to boot on an unrecognised
//     value so it is near-unreachable there; the orchestrator does NOT validate
//     it, so this branch is live for that binary and must not put an operator's
//     arbitrary string on the wire.
//
// It reads the variable through deploymode.Current() rather than reading the
// environment itself — this package deliberately adds no second reader, which
// is also what keeps it off scripts/lint-deployment-mode.sh's radar.
// (deploymode.Current() is not the ONLY env read of DEPLOYMENT_MODE in the
// tree: #3713 narrowed that allow-list to seven files, and the census in
// platform/shared/deploymode names every site that still derives an answer
// from the taxonomy.)
func PlatformDeploymentMode() string {
	raw := deploymode.Current()
	if raw == "" {
		return ""
	}
	mode, recognised := deploymode.Resolve(raw)
	if !recognised {
		return "unknown"
	}
	return capCoarseEnum(mode)
}

// TopologyDeploymentMode returns the coarse topology bucket for the
// `deployment_mode` wire field.
//
// It is DERIVED from the same deploymode read rather than from a second
// is-this-community-SaaS predicate, so the two answers cannot disagree. Since
// #3713 the agent's and the orchestrator's isCommunitySaasMode() helpers are
// both thin names for deploymode.IsCommunitySaasPosture rather than their own
// copies of `DEPLOYMENT_MODE == "community-saas"` — the exact condition below,
// since no alias maps onto that canonical mode.
func TopologyDeploymentMode() string {
	if mode, recognised := deploymode.Resolve(deploymode.Current()); recognised &&
		mode == "community-saas" {
		return TopologyCommunitySaaS
	}
	return TopologySelfHosted
}

// NormalizeLicenseTier mirrors the server-side telemetry.NormalizeLicenseTier
// closed-enum mapping. Defence in depth: the emitter sends a canonical value
// and the receiver normalises again on ingest.
//
// # EMPTY PASSES THROUGH AS EMPTY, AND THAT IS THE WHOLE POINT
//
// "starting" buckets as "unknown" — the never-skip-emission rule locked in the
// #2070 design pass: a ping fired before the licence resolves must still
// surface, saying "this emitter reports the dimension and had not resolved it".
// An EMPTY value is a different fact and keeps a different answer: the caller
// has no way to determine a tier at all, so the field is OMITTED and the row
// says "not reported". Folding the two would be the exact conflation this
// lane's contract is built on refusing.
//
// It also keeps the wire byte-identical for both existing callers, which is
// what makes this extraction a refactor rather than a silent behaviour change:
//
//   - The AGENT passes currentLicenseTier(), which NEVER returns "" — it
//     answers "starting", "community", or a real tier. Its "" branch was dead
//     before the extraction and is dead now.
//   - The ORCHESTRATOR cannot read a tier and passes "". Before the extraction
//     its payload struct left LicenseTier empty and omitempty dropped the key.
//     Passing empty through preserves that exactly; bucketing it as "unknown"
//     would have changed an existing field's value on a shipped emitter.
func NormalizeLicenseTier(raw string) string {
	if raw == "" {
		return ""
	}
	switch strings.ToLower(raw) {
	case "community":
		return "Community"
	case "evaluation":
		return "Evaluation"
	case "professional":
		return "Professional"
	case "enterprise":
		return "Enterprise"
	case "enterpriseplus", "plus":
		return "EnterprisePlus"
	default:
		return "unknown"
	}
}

// DetectEnvironmentClass returns the runtime-environment classification per the
// 8-step precedence locked in the #2004 secondary amendment. Most-specific
// first, so an EKS pod — which may carry AWS_EXECUTION_ENV from a parent task
// definition AND KUBERNETES_SERVICE_HOST — classifies as kubernetes, the
// meaningful product signal, rather than ecs_fargate.
//
// Best-effort: falls through to "unknown" rather than guessing wrong on macOS
// or Windows where /proc is unavailable.
func DetectEnvironmentClass() string {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		return "lambda"
	}
	if os.Getenv("AWS_EXECUTION_ENV") == "AWS_ECS_FARGATE" {
		return "ecs_fargate"
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}
	if os.Getenv("ECS_CONTAINER_METADATA_URI") != "" || os.Getenv("ECS_CONTAINER_METADATA_URI_V4") != "" {
		return "ecs_ec2"
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "container"
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, marker := range []string{"docker", "containerd", "kubepods", "lxc", "podman", "cri-o", "crio"} {
			if strings.Contains(s, marker) {
				return "container"
			}
		}
		// /proc/1/cgroup readable but no container marker → bare-metal Linux.
		return "bare_metal"
	}
	return "unknown"
}

// HealthIdentityMembers returns the platform-identity members a plane adds to
// its /health response: `edition` and `deployment_mode`.
//
// # WHY THIS LIVES WITH THE EMITTER
//
// These members exist to be RELAYED. /health is the one response the four
// SDK heartbeats already fetch, so putting a dimension there is what lets an
// SDK ping report it without making a second request — the design rule for
// #3660's whole lane. They therefore share this package's vocabulary and,
// crucially, its omission semantics; defining them next to the handler that
// serves them would give the platform two answers to the same question.
//
// # THE NAME `deployment_mode` ON /health MEANS SOMETHING DIFFERENT FROM THE
// # FIELD OF THAT NAME ON A PING. READ THIS BEFORE WIRING A CONSUMER.
//
// On /health, the platform is describing ITSELF, so `deployment_mode` is its
// own DEPLOYMENT_MODE setting. On the ping wire, `deployment_mode` is the
// coarse TOPOLOGY (self_hosted | community_saas) an SDK derives from the URL it
// was pointed at. A relaying client must therefore map this member onto
// `platform_deployment_mode`, NOT onto `deployment_mode`. Getting that wrong
// silently overwrites a dimension every existing dashboard reads.
//
// # ABSENT IS NOT EMPTY
//
// A key the platform cannot determine is MISSING from the map, never present
// with an empty value. Relaying clients preserve that: a missing key means
// "the platform did not say", which is a different fact from any value it
// could have said. `edition` is a compile-time constant so it is always
// present; `deployment_mode` is absent when DEPLOYMENT_MODE is unset.
func HealthIdentityMembers(currentEdition string) map[string]string {
	out := map[string]string{}
	if currentEdition != "" {
		out["edition"] = capCoarseEnum(currentEdition)
	}
	if mode := PlatformDeploymentMode(); mode != "" {
		out["deployment_mode"] = mode
	}
	return out
}

// capCoarseEnum bounds a coarse-enum value to maxCoarseEnumValueBytes. See the
// constant for why the bound is applied on this side as well as the receiver's.
func capCoarseEnum(v string) string {
	if len(v) <= maxCoarseEnumValueBytes {
		return v
	}
	return v[:maxCoarseEnumValueBytes]
}

// Endpoint returns the checkpoint URL, honoring the AXONFLOW_CHECKPOINT_URL
// override.
func Endpoint() string {
	if override := os.Getenv("AXONFLOW_CHECKPOINT_URL"); override != "" {
		return override
	}
	return DefaultEndpoint
}

// resolveOrgID prefers the caller's explicit org over the ORG_ID environment
// variable. Empty stays empty: an unset org is a legitimate state (a
// community-mode binary with no licence) and must be reported as ABSENT rather
// than defaulted, because the classifier reads a missing org as "not one of
// ours", which is the correct answer for a binary that genuinely has none.
func resolveOrgID(override string) string {
	if override != "" {
		return override
	}
	return os.Getenv("ORG_ID")
}

// BuildPayload assembles the wire payload for one send. Split out from Send so
// a caller — and a test — can inspect exactly what would go on the wire without
// performing any I/O.
func BuildPayload(cfg Config, instanceID string) Payload {
	return Payload{
		TelemetryType:          "platform",
		SDK:                    "",
		SDKVersion:             "",
		Component:              cfg.Component,
		PlatformVersion:        cfg.PlatformVersion,
		OS:                     runtime.GOOS,
		Arch:                   runtime.GOARCH,
		RuntimeVersion:         strings.TrimPrefix(runtime.Version(), "go"),
		DeploymentMode:         TopologyDeploymentMode(),
		OrgID:                  resolveOrgID(cfg.OrgID),
		Edition:                capCoarseEnum(cfg.Edition),
		PlatformDeploymentMode: PlatformDeploymentMode(),
		LicenseTier:            NormalizeLicenseTier(cfg.LicenseTier),
		EnvironmentClass:       DetectEnvironmentClass(),
		InstanceID:             instanceID,
		Stream:                 "heartbeat",
	}
}

// Send is the single entry point. Side effects, in order:
//
//   - If AXONFLOW_TELEMETRY=off (or the CI auto-suppress fires), returns
//     immediately with no network or disk activity.
//   - Reads the stamp file. If last_sent is inside Interval, returns
//     immediately (rate limit hit).
//   - Otherwise builds the payload, prints the disclosure line and the exact
//     JSON to stderr (the "transparent on startup" commitment), and POSTs to
//     /v1/ping under HTTPTimeout.
//   - On HTTP 2xx, writes the stamp so the next Interval is gated. On any
//     non-2xx or network error the stamp is left unchanged so the next restart
//     retries — stamp-on-delivery, matching the SDKs.
//
// THERE IS NO DEPLOYMENT-SHAPE GATE. A community-SaaS stack emits like any
// other; the receiver classifies it internal from its org_id. See the package
// doc for why suppressing here was the wrong layer.
//
// Errors are logged but must NOT fail startup — the heartbeat is
// fire-and-forget. Callers should run this in a goroutine if startup latency
// matters (it typically completes in under 100ms but can hang up to
// HTTPTimeout on a wedged checkpoint).
//
// Returns (sent, error). sent==true means a ping was attempted and landed
// (HTTP 2xx and the stamp written). sent==false with a nil error means a gate
// fired (opt-out, rate limit). sent==false with a non-nil error means a network
// or write failure.
func Send(ctx context.Context, cfg Config) (bool, error) {
	if !Enabled() {
		return false, nil
	}

	stampPath := ResolveStampPath(cfg.StampFilename)
	stamp, err := ReadStamp(stampPath)
	if err != nil {
		// A read failure must not silently block emission — the worst case is
		// one un-rate-limited extra ping after a corrupted stamp, which beats
		// skipping forever.
		log.Printf("[startup-telemetry] stamp read failed (treating as fresh): %v", err)
	}

	if !stamp.LastSent.IsZero() && time.Since(stamp.LastSent) < Interval {
		return false, nil
	}

	if stamp.InstanceID == "" {
		stamp.InstanceID = GenerateInstanceID(cfg.InstanceIDPrefix)
	}

	payload := BuildPayload(cfg, stamp.InstanceID)

	// Serialised by encoding/json, never assembled by string concatenation.
	// Every field here can carry an operator-controlled value; a value spliced
	// into a hand-built JSON string is how a single quote in one field silently
	// destroys a whole payload (the #3619 plugin-heartbeat finding).
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshal payload: %w", err)
	}

	// Privacy-commitment disclosure: print the URL and the exact JSON about to
	// be sent, so an operator reading stderr can audit what leaves. Fires on
	// every delivery, not just the first — matching SDK behaviour.
	log.Printf("[AxonFlow] Anonymous telemetry enabled. Opt out: AXONFLOW_TELEMETRY=off | https://docs.getaxonflow.com/docs/telemetry")
	log.Printf("[startup-telemetry] payload: %s", body)

	postCtx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, Endpoint(), bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	// Drain so the connection can be reused — Go's http.Client pools idle conns.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}

	// Stamp-on-delivery: only advance last_sent on a confirmed 2xx.
	stamp.LastSent = time.Now().UTC()
	if err := WriteStamp(stampPath, stamp); err != nil {
		// A write failure leaves the stamp at its previous value, so the next
		// restart re-sends. An extra ping rather than no ping — surface the
		// error to the caller for logging.
		return true, fmt.Errorf("stamp write failed (ping landed; will re-send next restart): %w", err)
	}
	return true, nil
}
