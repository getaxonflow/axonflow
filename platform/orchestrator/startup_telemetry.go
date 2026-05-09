// Package orchestrator — anonymous platform-level startup telemetry ping
// (#2004 PR3, the orchestrator half of the agent+orchestrator pair).
//
// Mirrors platform/agent/startup_telemetry.go with two differences:
//
//  1. component="orchestrator" — gates the checkpoint Lambda's
//     ValidComponents allowlist on the orchestrator value rather than the
//     agent value. Server-side accepts both equally; the analytics
//     warehouse uses this dimension to slice deployments by which
//     binaries are running.
//
//  2. Stamp file path uses an "orchestrator-" prefix so each binary
//     independently rate-limits — a host running both agent + orchestrator
//     emits ONE ping per binary per 7 days, not one combined ping.
//
//  3. license_tier defaults to "unknown" — the orchestrator package
//     reads license tier through the per-Service licenseChecker instance
//     rather than a package-level atomic, so a startup-time helper
//     can't query it without coupling to handler initialization. The
//     omission is acceptable: agent pings carry the tier; orchestrator
//     pings carry component=orchestrator + everything else.
//
// All other privacy commitments + stamp semantics + opt-out gates +
// detection logic match the agent implementation. See
// platform/agent/startup_telemetry.go for the canonical comments.
package orchestrator

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

// startupTelemetryEndpoint, startupTelemetryInterval, startupTelemetryHTTPTimeout
// — see platform/agent/startup_telemetry.go for the full rationale on each.
var (
	startupTelemetryEndpoint    = "https://checkpoint.getaxonflow.com/v1/ping"
	startupTelemetryInterval    = 7 * 24 * time.Hour
	startupTelemetryHTTPTimeout = 5 * time.Second
)

const startupTelemetryComponent = "orchestrator"

// startupTelemetryPayload mirrors the agent-side struct verbatim. Field
// shape is locked by the #2004 wire schema (PingRequest in
// ee/platform/checkpoint-service/pkg/telemetry/telemetry.go) and shared
// across all platform-class emitters.
type startupTelemetryPayload struct {
	TelemetryType    string `json:"telemetry_type"`
	SDK              string `json:"sdk"`
	SDKVersion       string `json:"sdk_version"`
	Component        string `json:"component"`
	PlatformVersion  string `json:"platform_version,omitempty"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	RuntimeVersion   string `json:"runtime_version"`
	DeploymentMode   string `json:"deployment_mode"`
	LicenseTier      string `json:"license_tier,omitempty"`
	EnvironmentClass string `json:"environment_class,omitempty"`
	InstanceID       string `json:"instance_id"`
	Stream           string `json:"stream,omitempty"`
}

type startupTelemetryStamp struct {
	InstanceID string
	LastSent   time.Time
}

// stampFilename is the per-binary stamp filename appended inside the
// resolved stamp directory. Keeps the rate limit per-binary so a host
// running both agent + orchestrator emits one ping per binary per 7 days.
const stampFilename = "orchestrator-startup-telemetry-stamp"

// resolveStartupStampPath returns the orchestrator stamp file path.
//
// AXONFLOW_TELEMETRY_STAMP_DIR is the operator control surface — set it to
// the path of a persistent volume (or any writable dir) and the code
// constructs the per-binary filename inside it. This is the ONLY persistence
// override knob; production operators use it when their host's user-cache
// dir is ephemeral (e.g. fresh container per restart). Runtime-e2e bundles
// also use it to point at a tempdir for hermetic tests.
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

func writeStartupStamp(path string, stamp startupTelemetryStamp) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "orchestrator-startup-telemetry-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort tmp cleanup on any error path; rename below removes it
	// on success so this Remove typically no-ops. Errors here are not
	// actionable.
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

func generateStartupInstanceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("orchestrator-fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// startupTelemetryEnabled mirrors agent semantics: AXONFLOW_TELEMETRY=off
// is the SOLE opt-out. Casing-tolerant; no programmatic disable.
func startupTelemetryEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("AXONFLOW_TELEMETRY")), "off")
}

// classifyDeploymentMode — orchestrator equivalent of the agent helper.
// Delegates to isCommunitySaasMode (the canonical csaas predicate, see
// platform/orchestrator/run.go) which reads DEPLOYMENT_MODE — the SAME
// env var docker-compose.community-saas.yml + the ECS task-def set, and
// the SAME var platform/agent/run.go's isCommunitySaasMode reads.
//
// Pre-fix this function checked AXONFLOW_BUILD + COMMUNITY_SAAS_MODE,
// neither wired in any deployment shape — so the orchestrator emitted
// telemetry from try.getaxonflow.com (csaas prod) despite the user-
// locked design suppressing self-pings. Surfaced post-merge by the user
// reading the actual compose file.
//
// Calling the helper instead of duplicating the env-var read also
// satisfies scripts/lint-deployment-mode.sh — which forbids raw env-
// var reads outside the canonical helpers.
func classifyDeploymentMode() string {
	if isCommunitySaasMode() {
		return "community_saas"
	}
	return "self_hosted"
}

// detectEnvironmentClass — verbatim port of the agent precedence list.
// Most-specific-first: lambda → ecs_fargate → kubernetes → ecs_ec2 →
// /.dockerenv → /proc/1/cgroup substring → bare_metal → unknown.
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
		return "bare_metal"
	}
	return "unknown"
}

// MaybeSendStartupTelemetry is the single entry point. Wired into
// platform/orchestrator/run.go in a goroutine before ListenAndServe.
// Algorithm matches agent's MaybeSendStartupTelemetry verbatim — see
// platform/agent/startup_telemetry.go for the full doc.
//
// Returns (sent, error). sent==true means a ping was attempted and
// landed (HTTP 2xx + stamp written). sent==false + nil err means a
// gate fired (opt-out, csaas, rate-limit). sent==false + non-nil err
// means a network or write failure.
func MaybeSendStartupTelemetry(ctx context.Context) (bool, error) {
	if !startupTelemetryEnabled() {
		return false, nil
	}

	deploymentMode := classifyDeploymentMode()
	if deploymentMode == "community_saas" {
		return false, nil
	}

	stampPath := resolveStartupStampPath()
	stamp, err := readStartupStamp(stampPath)
	if err != nil {
		log.Printf("[startup-telemetry] stamp read failed (treating as fresh): %v", err)
	}

	if !stamp.LastSent.IsZero() && time.Since(stamp.LastSent) < startupTelemetryInterval {
		return false, nil
	}

	if stamp.InstanceID == "" {
		stamp.InstanceID = generateStartupInstanceID()
	}

	// license_tier — see package doc. Orchestrator has no global accessor;
	// emit empty (omitempty drops it from the wire payload). Agent pings
	// from the same deployment carry the tier signal for analytics.
	licenseTier := ""
	if override := os.Getenv("AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE"); override != "" {
		// Runtime-e2e bundle hook — production should never set this env
		// var. Lets the proof script seed a deterministic tier value
		// without coupling to per-Service licenseChecker initialization.
		licenseTier = override
	}

	payload := startupTelemetryPayload{
		TelemetryType:    "platform",
		SDK:              "",
		SDKVersion:       "",
		Component:        startupTelemetryComponent,
		PlatformVersion:  getPlatformVersion(),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		RuntimeVersion:   strings.TrimPrefix(runtime.Version(), "go"),
		DeploymentMode:   deploymentMode,
		LicenseTier:      licenseTier,
		EnvironmentClass: detectEnvironmentClass(),
		InstanceID:       stamp.InstanceID,
		Stream:           "heartbeat",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("marshal payload: %w", err)
	}

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
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}

	stamp.LastSent = time.Now().UTC()
	if err := writeStartupStamp(stampPath, stamp); err != nil {
		return true, fmt.Errorf("stamp write failed (ping landed; will re-send next restart): %w", err)
	}
	return true, nil
}
