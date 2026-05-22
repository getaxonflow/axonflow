// Package agent — anonymous platform-level startup telemetry ping (#2004 PR2).
//
// Modeled on axonflow-sdk-go/heartbeat.go with three differences locked by
// the 2026-05-09 #2004 secondary amendment:
//
//  1. instance_id is PERSISTED in the stamp file (not regenerated per startup
//     like the SDK does), so the 7-day rate limit and the analytics
//     longitudinal-tracking property both hold.
//
//  2. license_tier and environment_class are populated server-bound;
//     defense-in-depth normalization runs both here (closed enum on the
//     emitter, "unknown" fallback) and on the checkpoint Lambda
//     (NormalizeLicenseTier / NormalizeEnvironmentClass).
//
//  3. community_saas mode SKIPS emission — those stacks are AxonFlow-operated
//     and pings would just be self-measurement noise.
//
// Privacy commitments (verbatim from #2004 issue body, holds across this
// package):
//   - Classification-only payload — no URLs, tokens, secrets, customer data,
//     prompts, schemas, tenant IDs, request IDs, plugin lists.
//   - Single opt-out: AXONFLOW_TELEMETRY=off (same env var SDKs use).
//   - Transparent on startup — print exact JSON payload to stdout on first
//     delivery; print disclosure line on every delivery so operators can
//     audit what leaves.
//   - Rate-limited per-machine — at most one ping per binary per 7 days,
//     gated by stamp-file mtime.
//   - No new persistent state beyond the stamp-file pattern used by the SDKs.
//
// See runtime-e2e/agent_startup_ping/ for the runtime proof bundle.
package agent

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
	"strings"
	"time"
)

// Telemetry destination + cadence constants. Declared as var (not const) so
// tests can override; production code never mutates them.
var (
	// startupTelemetryEndpoint is the central checkpoint receiver. Override
	// via AXONFLOW_CHECKPOINT_URL — same env var the language SDKs honor —
	// for staging-checkpoint runtime tests or air-gapped deployments.
	startupTelemetryEndpoint = "https://checkpoint.getaxonflow.com/v1/ping"

	// startupTelemetryInterval is the per-binary rate limit. Same 7-day cap
	// the SDK heartbeat package uses; together with the SDK pings it gives
	// the analytics warehouse one reading per (deployment, week) without
	// flooding.
	startupTelemetryInterval = 7 * 24 * time.Hour

	// startupTelemetryHTTPTimeout bounds the network call so a wedged
	// checkpoint endpoint never blocks agent startup. Heartbeat is
	// fire-and-forget — a timeout is logged but does not fail startup.
	startupTelemetryHTTPTimeout = 5 * time.Second
)

// startupTelemetryComponent is the literal "agent" identifier the checkpoint
// validator gates platform pings on (see ee/platform/checkpoint-service/pkg/
// telemetry/telemetry.go ValidComponents). Mirrored as a constant so a
// future rename of "agent" is a single-point change.
const startupTelemetryComponent = "agent"

// startupTelemetryPayload is the wire shape sent to /v1/ping. Matches
// telemetry.PingRequest on the checkpoint side. omitempty mirrors the
// server-side struct so back-compat with empty fields is byte-identical.
type startupTelemetryPayload struct {
	TelemetryType   string `json:"telemetry_type"`
	SDK             string `json:"sdk"`
	SDKVersion      string `json:"sdk_version"`
	Component       string `json:"component"`
	PlatformVersion string `json:"platform_version,omitempty"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	RuntimeVersion  string `json:"runtime_version"`
	DeploymentMode  string `json:"deployment_mode"`
	// OrgID is the org_id baked into the binary's deployed license, read
	// once at startup from the ORG_ID env var. Every AxonFlow-operated
	// deployment (customer-facing demos + internal CI / canary / perf-
	// bench) uses an org_id starting with telemetryfilter.InternalOrgIDPrefix
	// ("axonflow-" per ADR-054 + issue #2259) so the receiver's classifier
	// (ee/platform/telemetry-filter/classify.go IsInternal rule 6) flips
	// the row to source=internal at write time. Empty on legacy agents
	// + community-mode agents without a license.
	OrgID            string `json:"org_id,omitempty"`
	LicenseTier      string `json:"license_tier,omitempty"`
	EnvironmentClass string `json:"environment_class,omitempty"`
	InstanceID       string `json:"instance_id"`
	Stream           string `json:"stream,omitempty"`
}

// startupTelemetryStamp is the on-disk persisted state. Carries instance_id
// across restarts (the #2004 amendment-locked behavior — diverges from the
// SDK pattern, which regenerates instance_id every call) and last-sent
// timestamp for the 7-day rate limit. Format is deliberately simple
// key=value lines so an operator can `cat` the file to audit.
type startupTelemetryStamp struct {
	InstanceID string
	LastSent   time.Time
}

// stampFilename is the per-binary stamp filename appended inside the
// resolved stamp directory. Keeps the rate limit per-binary so a host
// running both agent + orchestrator emits one ping per binary per 7 days.
const stampFilename = "agent-startup-telemetry-stamp"

// resolveStartupStampPath returns the agent stamp file path. Empty string
// means "no persistent home" (e.g. AWS Lambda where HOME is unset); the
// rate limit then degrades to per-process — same approach the SDK takes.
//
// AXONFLOW_TELEMETRY_STAMP_DIR is the operator control surface — set it to
// the path of a persistent volume (or any writable dir) and the code
// constructs the per-binary filename inside it. This is the ONLY persistence
// override knob; production operators use it when their host's user-cache
// dir is ephemeral (e.g. fresh container per restart) so the rate-limit gate
// survives across restarts. Runtime-e2e bundles also use it to point at a
// tempdir for hermetic tests.
//
// Without the override, falls back to the OS user cache dir
// (~/.cache/axonflow on Linux, ~/Library/Caches/axonflow on macOS) which
// gives a per-user persistent location for dev / unsupervised installs.
func resolveStartupStampPath() string {
	if dir := os.Getenv("AXONFLOW_TELEMETRY_STAMP_DIR"); dir != "" {
		return filepath.Join(dir, stampFilename)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(cacheDir, "axonflow", stampFilename)
}

// readStartupStamp loads the persisted stamp from disk. Returns an
// empty stamp + nil error when the file is absent — that's "send a
// fresh ping" semantics. Any other read or parse error returns the
// error so the caller can decide; in practice we treat parse errors
// as "send fresh" because the alternative is to silently never ping.
func readStartupStamp(path string) (startupTelemetryStamp, error) {
	if path == "" {
		return startupTelemetryStamp{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return startupTelemetryStamp{}, nil
		}
		return startupTelemetryStamp{}, err
	}
	var stamp startupTelemetryStamp
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

// writeStartupStamp persists the stamp via tmp+rename so concurrent readers
// never observe torn state. A failed write is non-fatal — the next process
// retries on schedule, which is preferable to a panic at startup.
func writeStartupStamp(path string, stamp startupTelemetryStamp) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "agent-startup-telemetry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the tmp on any error path; rename below
	// removes it on success, so this Remove typically no-ops. Errors
	// here are not actionable (tmp dir gone, etc) — drop them.
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

// generateStartupInstanceID returns a UUIDv4 from crypto/rand. Used once
// per stamp-file lifetime — written into the stamp on first send, then
// re-read on subsequent sends. Stamp-file deletion (volume rotation,
// container restart with ephemeral filesystem) generates a new ID on
// next send — acceptable anti-longitudinal property per the #2004
// amendment.
func generateStartupInstanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic — fall back to a timestamp-
		// based ID rather than a zero-filled UUID that would collide.
		return fmt.Sprintf("agent-fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// startupTelemetryEnabled determines whether to send.
//
// AXONFLOW_TELEMETRY=off is the SOLE USER-FACING opt-out — same lever the
// SDKs honor. Casing-tolerant on "off"; any other value (including "true",
// "0", "no", empty) leaves telemetry on. No programmatic-disable, no
// DO_NOT_TRACK, no mode-based suppression for users.
//
// CI-environment auto-suppress (defense in depth, added 2026-05-13):
// when running in a Continuous Integration environment, the platform
// binary refuses to emit even when AXONFLOW_TELEMETRY isn't explicitly
// set. CI runs aren't real customer deployments — pings from them
// pollute the adoption signal (300+ rows in prod-checkpoint-telemetry-
// events from GitHub Actions Azure runners during one week of 2026-05).
// Honored signals:
//   - CI=true             (set by most CI systems: GitHub Actions, GitLab,
//     CircleCI, Travis, etc.)
//   - GITHUB_ACTIONS=true (set by GitHub Actions runner specifically)
//
// Either signal disables emission UNLESS the operator has explicitly set
// AXONFLOW_TELEMETRY=on (which takes precedence — for the rare case where
// a customer's self-hosted CI legitimately wants to emit). Plain
// AXONFLOW_TELEMETRY=off still wins as the canonical user opt-out.
//
// CI=true / GITHUB_ACTIONS=true are NOT new user-facing opt-outs —
// operators of real deployments should never set them, and standard CI
// runners set them automatically. The check exists because Docker
// compose / kubectl / ECS task defs commonly drop env vars on the floor;
// CI conventions are a complementary signal the platform binary can
// detect from inside the container without trusting the deploy pipeline.
func startupTelemetryEnabled() bool {
	// Explicit user opt-in / opt-out wins over CI auto-detect.
	val := strings.TrimSpace(os.Getenv("AXONFLOW_TELEMETRY"))
	if strings.EqualFold(val, "off") {
		return false
	}
	if strings.EqualFold(val, "on") {
		return true
	}
	// AXONFLOW_TELEMETRY unset (or any non-on/off value) → fall through
	// to CI auto-suppress. Presence-only check (not value-equals)
	// because some CI systems set CI=1 / CI=yes / CI=github-actions etc.
	// Explicit CI=false / GITHUB_ACTIONS=false is treated as "not in CI."
	if v := strings.TrimSpace(os.Getenv("GITHUB_ACTIONS")); v != "" && !strings.EqualFold(v, "false") {
		return false
	}
	if v := strings.TrimSpace(os.Getenv("CI")); v != "" && !strings.EqualFold(v, "false") {
		return false
	}
	return true
}

// classifyDeploymentMode returns the canonical deployment_mode for the
// platform startup ping. community_saas mode skips emission upstream;
// otherwise everything is "self_hosted" (the topology bucket — Docker,
// K8s, bare-metal all roll up into one). Allowlist matches the
// checkpoint-side ValidDeploymentModes set.
func classifyDeploymentMode() string {
	if isCommunitySaasMode() {
		return "community_saas"
	}
	return "self_hosted"
}

// normalizeStartupLicenseTier mirrors the server-side
// telemetry.NormalizeLicenseTier closed-enum mapping. Defense-in-depth:
// the emitter sends a canonical value, the server normalizes again on
// ingest. See ee/platform/checkpoint-service/pkg/telemetry/telemetry.go
// for the authoritative server-side function.
//
// Empty / "starting" both bucket as "unknown" rather than empty so a ping
// fired before license loads still surfaces in analytics — the never-skip-
// emission rule the user locked during the #2070 design pass.
func normalizeStartupLicenseTier(raw string) string {
	if raw == "" {
		return "unknown"
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

// detectEnvironmentClass returns the runtime-environment classification per
// the 8-step precedence locked in the #2004 secondary amendment. Most-
// specific-first ordering so an EKS pod (which has both AWS_EXECUTION_ENV
// possibly set by parent task def AND KUBERNETES_SERVICE_HOST) classifies
// as kubernetes — the meaningful product signal — rather than ecs_fargate.
//
// Detection is best-effort and falls through to "unknown" rather than
// guessing wrong on macOS / Windows where /proc isn't available.
func detectEnvironmentClass() string {
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

// SetLicenseTierForRuntimeTest is the runtime-e2e bundle's hook for forcing
// a deterministic license tier value into the package-level licenseTier
// atomic so the runtime test's payload assertions don't depend on whatever
// the host environment's license loader happened to populate. Production
// callers MUST NOT use this — license tier is set by the validated-license
// path inside Run(). The function is exported only because the runtime-e2e
// wrapper at runtime-e2e/agent_startup_ping/test.sh lives in a separate
// `package main` and needs cross-package access.
func SetLicenseTierForRuntimeTest(tier string) error {
	if tier == "" {
		return fmt.Errorf("tier must be non-empty")
	}
	licenseTier.Store(tier)
	return nil
}

// MaybeSendStartupTelemetry is the single entry point. Called once at
// agent startup after appReady.Store(true). Side effects:
//
//   - If AXONFLOW_TELEMETRY=off OR deployment is community_saas, returns
//     immediately without network or disk activity.
//   - Reads the stamp file. If last_sent < 7 days ago, returns immediately
//     (rate limit hit).
//   - Otherwise, builds the payload, prints the disclosure line + JSON
//     payload to stderr (per the privacy commitment "transparent on
//     startup"), POSTs to /v1/ping under a 5s timeout.
//   - On HTTP 2xx, writes the stamp (instance_id + last_sent=now) so the
//     next 7 days are gated. On any non-2xx or network error, the stamp
//     is left unchanged so the next agent restart retries — stamp-on-
//     delivery semantics matching the SDK.
//
// Errors are logged but do NOT fail agent startup — heartbeat is
// fire-and-forget. Callers should run this in a goroutine if startup
// time is sensitive (the call typically completes in <100ms but can
// hang up to startupTelemetryHTTPTimeout on a wedged checkpoint).
//
// Returns (sent, error). sent==true means a ping was attempted and
// landed (HTTP 2xx + stamp written). sent==false + nil error means a
// gate fired (opt-out, csaas, rate-limit). sent==false + non-nil
// error means a network or write failure.
func MaybeSendStartupTelemetry(ctx context.Context) (bool, error) {
	if !startupTelemetryEnabled() {
		return false, nil
	}

	deploymentMode := classifyDeploymentMode()
	if deploymentMode == "community_saas" {
		// AxonFlow-operated stacks. Pings would be self-measurement noise.
		return false, nil
	}

	stampPath := resolveStartupStampPath()
	stamp, err := readStartupStamp(stampPath)
	if err != nil {
		// Read failure shouldn't silently block emission — the worst case
		// is one unrate-limited extra ping after a corrupted stamp. Better
		// than skipping forever.
		log.Printf("[startup-telemetry] stamp read failed (treating as fresh): %v", err)
	}

	if !stamp.LastSent.IsZero() && time.Since(stamp.LastSent) < startupTelemetryInterval {
		return false, nil
	}

	if stamp.InstanceID == "" {
		stamp.InstanceID = generateStartupInstanceID()
	}

	payload := startupTelemetryPayload{
		TelemetryType:    "platform",
		SDK:              "",
		SDKVersion:       "",
		Component:        startupTelemetryComponent,
		PlatformVersion:  GetPlatformVersion(),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		RuntimeVersion:   strings.TrimPrefix(runtime.Version(), "go"),
		DeploymentMode:   deploymentMode,
		OrgID:            os.Getenv("ORG_ID"),
		LicenseTier:      normalizeStartupLicenseTier(currentLicenseTier()),
		EnvironmentClass: detectEnvironmentClass(),
		InstanceID:       stamp.InstanceID,
		Stream:           "heartbeat",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshal payload: %w", err)
	}

	// Privacy-commitment disclosure: print the disclosure URL + the exact
	// JSON we're about to send so an operator running with AXONFLOW_DEBUG=1
	// or just reading stderr can audit what leaves. This fires on every
	// delivery (not just first), matching SDK behavior.
	log.Printf("[AxonFlow] Anonymous telemetry enabled. Opt out: AXONFLOW_TELEMETRY=off | https://docs.getaxonflow.com/docs/telemetry")
	log.Printf("[startup-telemetry] payload: %s", body)

	endpoint := startupTelemetryEndpoint
	if override := os.Getenv("AXONFLOW_CHECKPOINT_URL"); override != "" {
		endpoint = override
	}

	postCtx, cancel := context.WithTimeout(ctx, startupTelemetryHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: startupTelemetryHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	// Drain body so the connection can be reused — Go's http.Client
	// pools idle conns by default.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}

	// Stamp-on-delivery: only update last_sent on confirmed 2xx.
	stamp.LastSent = time.Now().UTC()
	if err := writeStartupStamp(stampPath, stamp); err != nil {
		// Write failure leaves the stamp at the previous value, so next
		// restart re-sends. Acceptable degenerate case — extra ping
		// rather than no ping. Surface the error to caller for logging.
		return true, fmt.Errorf("stamp write failed (ping landed; will re-send next restart): %w", err)
	}
	return true, nil
}
