package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"axonflow/platform/decision/contract"
)

// allowedBuiltins is the complete set of OPA built-in functions a generated
// bundle and the platform-owned helpers may use.
//
// It is an ALLOW list, not a deny list. A deny list has to be updated every
// time OPA ships a new built-in, and the failure mode of forgetting is that a
// new built-in becomes reachable from policy without anyone deciding it should
// be. With an allow list the failure mode is a compile error naming the
// built-in, which is a decision point rather than a silent capability grant.
//
// Nothing here performs I/O, reads the clock, consumes randomness, or reads
// mutable process state, which is what makes evaluation replayable: the same
// normalized input and the same bundle reproduce the same decision offline.
// http.send, net.*, time.*, rand.*, opa.runtime, trace and print are absent by
// construction rather than by exclusion.
var allowedBuiltins = []string{
	// Assignment, equality and comparison.
	ast.Assign.Name,
	ast.Equality.Name,
	ast.Equal.Name,
	ast.NotEqual.Name,
	ast.LessThan.Name,
	ast.LessThanEq.Name,
	ast.GreaterThan.Name,
	ast.GreaterThanEq.Name,
	// Aggregates and array handling used by the tri-state helpers.
	ast.Count.Name,
	ast.ArrayConcat.Name,
	// Type predicates, used to classify a value BEFORE comparing it so a
	// wrongly typed attribute becomes a tagged unknown instead of a built-in
	// error.
	ast.IsNumber.Name,
	ast.IsString.Name,
	ast.IsBoolean.Name,
	ast.IsArray.Name,
	ast.IsObject.Name,
	ast.IsNull.Name,
}

// ForbiddenBuiltinExamples are built-ins that must never be reachable. The
// capabilities test asserts each is absent from the restricted document, so
// that a future change widening the allow list trips a named assertion rather
// than passing quietly.
var ForbiddenBuiltinExamples = []string{
	"http.send",
	"net.lookup_ip_addr",
	"time.now_ns",
	"rand.intn",
	"opa.runtime",
	"trace",
	"print",
	"io.jwt.decode_verify",
}

// RestrictedCapabilities returns the capabilities document the compiler runs
// with.
func RestrictedCapabilities() *ast.Capabilities {
	all := ast.CapabilitiesForThisVersion()
	allowed := make(map[string]struct{}, len(allowedBuiltins))
	for _, n := range allowedBuiltins {
		allowed[n] = struct{}{}
	}
	out := &ast.Capabilities{
		Builtins:        nil,
		FutureKeywords:  all.FutureKeywords,
		WasmABIVersions: nil,
		Features:        all.Features,
	}
	for _, b := range all.Builtins {
		if _, ok := allowed[b.Name]; ok {
			out.Builtins = append(out.Builtins, b)
		}
	}
	sort.Slice(out.Builtins, func(i, j int) bool { return out.Builtins[i].Name < out.Builtins[j].Name })
	return out
}

// Limits bound one evaluation.
type Limits struct {
	// EvalTimeout bounds a single evaluation. Exceeding it is Indeterminate,
	// never a permit.
	EvalTimeout time.Duration
	// MaxResultBytes bounds the size of the canonical result object.
	MaxResultBytes int
}

// DefaultLimits are the limits used when none are supplied.
func DefaultLimits() Limits {
	return Limits{EvalTimeout: 2 * time.Second, MaxResultBytes: 1 << 20}
}

// Verdict is the tri-state result of one policy.
type Verdict string

const (
	VerdictMatch   Verdict = "MATCH"
	VerdictNoMatch Verdict = "NO_MATCH"
	VerdictUnknown Verdict = "UNKNOWN"
)

// UnknownCause is one attribute path and reason behind an UNKNOWN verdict.
type UnknownCause struct {
	Path   string                 `json:"path"`
	Reason contract.UnknownReason `json:"reason"`
}

// PolicyOutcome is the evaluated state of one policy.
type PolicyOutcome struct {
	PolicyID  string
	Authority contract.Authority
	Root      Root
	Verdict   Verdict
	Causes    []UnknownCause
}

// EvalResult is the complete, validated result of evaluating one bundle root.
type EvalResult struct {
	Root     Root
	Outcomes map[string]PolicyOutcome
}

// Runtime is a prepared, in-process OPA evaluator for one bundle root.
//
// It is prepared once and evaluated many times. Preparation is where strict
// compilation, the restricted capabilities document and the bundle lint run, so
// a defective bundle fails at activation rather than at the first request that
// happens to touch the broken policy.
type Runtime struct {
	root     Root
	prepared rego.PreparedEvalQuery
	manifest []PolicyDeclaration
	limits   Limits
}

// PolicyDeclaration is the manifest entry for one compiled policy. The manifest
// is what makes completeness checkable: the Go boundary knows which policy IDs
// MUST appear in the result object, so a policy that vanished through a Rego
// undefined is detected instead of being read as "did not apply".
type PolicyDeclaration struct {
	ID        string             `json:"id"`
	Authority contract.Authority `json:"authority"`
}

// ManifestOf returns the declaration list for a document, sorted by ID.
func ManifestOf(d *Document) []PolicyDeclaration {
	out := make([]PolicyDeclaration, 0, len(d.Policies))
	for _, p := range d.Policies {
		out = append(out, PolicyDeclaration{ID: p.ID, Authority: p.Authority})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// NewRuntime compiles a bundle and prepares it for evaluation.
func NewRuntime(ctx context.Context, b *Bundle, limits Limits) (*Runtime, error) {
	if b == nil {
		return nil, fmt.Errorf("pdp: bundle is nil")
	}
	if limits.EvalTimeout <= 0 || limits.MaxResultBytes <= 0 {
		limits = DefaultLimits()
	}
	modules := map[string]string{
		"axonflow/decision/tri/tristate.rego": HelperSource,
		"axonflow/decision/bundle.rego":       b.Module,
	}
	if err := LintBundleModule(b.Module, BundlePackage(b.Root)); err != nil {
		return nil, err
	}

	query := fmt.Sprintf("data.%s.result", BundlePackage(b.Root))
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Capabilities(RestrictedCapabilities()),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Strict(true),
		rego.StrictBuiltinErrors(true),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}
	r := rego.New(opts...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("pdp: bundle %s failed strict compilation: %w", b.Digest, err)
	}
	return &Runtime{root: b.Root, prepared: pq, manifest: b.Manifest, limits: limits}, nil
}

// Eval evaluates one request against the prepared bundle.
//
// Every failure mode below returns an error, and the caller maps an error to
// Indeterminate. Nothing here can return a partial result that a caller might
// read as "these policies did not apply": a missing policy, an unrecognised
// verdict, an oversized result and an evaluation error are all errors.
func (rt *Runtime) Eval(ctx context.Context, attrs contract.AttributeSet) (*EvalResult, error) {
	ctx, cancel := context.WithTimeout(ctx, rt.limits.EvalTimeout)
	defer cancel()

	input := map[string]any{"attributes": attrs}
	rs, err := rt.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("pdp: evaluation failed: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return nil, fmt.Errorf("pdp: sealed entrypoint produced no complete result object (%d result sets)", len(rs))
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("pdp: result is not encodable: %w", err)
	}
	if len(raw) > rt.limits.MaxResultBytes {
		return nil, fmt.Errorf("pdp: result object is %d bytes, over the %d byte limit", len(raw), rt.limits.MaxResultBytes)
	}

	var parsed struct {
		SchemaVersion string `json:"schema_version"`
		Root          string `json:"root"`
		Policies      map[string]struct {
			V       string `json:"v"`
			Reasons []struct {
				Path   string `json:"path"`
				Reason string `json:"reason"`
			} `json:"reasons"`
		} `json:"policies"`
		Authorities map[string]string `json:"authorities"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("pdp: result object is malformed: %w", err)
	}
	if parsed.SchemaVersion != contract.SchemaVersion {
		return nil, fmt.Errorf("pdp: bundle emits schema version %q, evaluator expects %q", parsed.SchemaVersion, contract.SchemaVersion)
	}
	if parsed.Root != string(rt.root) {
		return nil, fmt.Errorf("pdp: bundle emits root %q, runtime prepared root %q", parsed.Root, rt.root)
	}

	out := &EvalResult{Root: rt.root, Outcomes: make(map[string]PolicyOutcome, len(rt.manifest))}
	for _, decl := range rt.manifest {
		entry, ok := parsed.Policies[decl.ID]
		if !ok {
			// This is the case the whole tri-state design exists to catch. A
			// policy declared in the manifest that is missing from the result
			// went undefined inside Rego, and reading its absence as "did not
			// apply" is the silent fail-open.
			return nil, fmt.Errorf("pdp: policy %q is declared in the bundle manifest but absent from the result object; a policy that went undefined is not a policy that did not apply", decl.ID)
		}
		verdict := Verdict(entry.V)
		switch verdict {
		case VerdictMatch, VerdictNoMatch, VerdictUnknown:
		default:
			return nil, fmt.Errorf("pdp: policy %q returned verdict %q, which is not MATCH, NO_MATCH or UNKNOWN", decl.ID, entry.V)
		}
		gotAuthority := contract.Authority(parsed.Authorities[decl.ID])
		if gotAuthority != decl.Authority {
			return nil, fmt.Errorf("pdp: policy %q is declared with authority %q in the manifest but %q in the bundle", decl.ID, decl.Authority, gotAuthority)
		}
		oc := PolicyOutcome{PolicyID: decl.ID, Authority: decl.Authority, Root: rt.root, Verdict: verdict}
		for _, c := range entry.Reasons {
			reason := contract.UnknownReason(c.Reason)
			if !isDeclaredReason(reason) {
				return nil, fmt.Errorf("pdp: policy %q reported unknown reason %q, which is not a declared reason code", decl.ID, c.Reason)
			}
			oc.Causes = append(oc.Causes, UnknownCause{Path: c.Path, Reason: reason})
		}
		if verdict == VerdictUnknown && len(oc.Causes) == 0 {
			return nil, fmt.Errorf("pdp: policy %q is UNKNOWN with no reason; an unknown without a cause cannot be diagnosed or acted on", decl.ID)
		}
		sort.Slice(oc.Causes, func(i, j int) bool {
			if oc.Causes[i].Path != oc.Causes[j].Path {
				return oc.Causes[i].Path < oc.Causes[j].Path
			}
			return oc.Causes[i].Reason < oc.Causes[j].Reason
		})
		out.Outcomes[decl.ID] = oc
	}
	if len(parsed.Policies) != len(rt.manifest) {
		extra := make([]string, 0)
		for id := range parsed.Policies {
			if _, ok := out.Outcomes[id]; !ok {
				extra = append(extra, id)
			}
		}
		sort.Strings(extra)
		return nil, fmt.Errorf("pdp: result object carries %d policies not declared in the manifest: %s", len(extra), strings.Join(extra, ", "))
	}
	return out, nil
}

func isDeclaredReason(r contract.UnknownReason) bool {
	for _, k := range contract.AllUnknownReasons() {
		if k == r {
			return true
		}
	}
	return false
}
