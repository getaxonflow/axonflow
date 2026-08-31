package contract

import (
	"context"
	"fmt"
	"time"
)

// SchemaVersion is the version of the canonical request, decision and trace
// contract carried in Snapshot.SchemaVersion. It changes when the shape
// changes, never when a value changes.
const SchemaVersion = "2026-08-29"

// Snapshot pins every version a decision is computed against. It is what makes
// a decision replayable offline: the same normalized input plus the same
// snapshot must reproduce the same decision and the same safe reason codes,
// with no network access.
type Snapshot struct {
	// IdentityEpoch is the REALM REGISTRY epoch: it moves when a trust realm
	// is registered, re-registered or removed.
	//
	// It is deliberately NOT the membership version. Directory membership
	// travels on the source version of the attribute that carries it, and the
	// two move independently: a directory re-sync changes group membership
	// without touching a realm declaration, and a realm being disabled changes
	// what a principal means without any directory changing. Binding only one
	// of them lets a decision replay clean against the other's staleness, so
	// both are bound, in different places.
	IdentityEpoch int64 `json:"identity_epoch"`
	// ResourceEpoch increments on resource graph change.
	ResourceEpoch int64 `json:"resource_epoch"`
	// PolicyBundle is the digest of the signed, immutable bundle evaluated.
	PolicyBundle string `json:"policy_bundle"`
	// RegistryVersion is the action and tool registry version.
	RegistryVersion int64 `json:"registry_version"`
	// SchemaVersion is the contract version, see SchemaVersion.
	SchemaVersion string `json:"schema_version"`
	// PolicyEpoch increments on activation or rollback of a bundle. A change
	// invalidates outstanding challenges and decision proofs.
	PolicyEpoch int64 `json:"policy_epoch"`
}

// Validate rejects an incomplete snapshot. Every field is mandatory because a
// decision that cannot name what it was computed against cannot be replayed,
// and an unreplayable decision cannot be audited.
func (s Snapshot) Validate() error {
	if s.SchemaVersion == "" {
		return fmt.Errorf("snapshot: schema_version is required")
	}
	if s.PolicyBundle == "" {
		return fmt.Errorf("snapshot: policy_bundle digest is required")
	}
	if s.IdentityEpoch < 0 || s.ResourceEpoch < 0 || s.RegistryVersion < 0 || s.PolicyEpoch < 0 {
		return fmt.Errorf("snapshot: epochs and versions must not be negative")
	}
	return nil
}

// ToolCall records the invoked tool and a digest of its canonicalized
// arguments. The digest, not the arguments, is what binds a decision: full
// argument content can carry secrets and prompt text, which ADR-065 excludes
// from decision proofs.
type ToolCall struct {
	RegistryID      ID     `json:"registry_id"`
	RegistryVersion int64  `json:"registry_version"`
	ArgumentsDigest string `json:"arguments_digest"`
}

// Validate checks the tool call.
func (t ToolCall) Validate() error {
	if t.RegistryID.Kind != KindTool {
		return fmt.Errorf("tool_call: registry_id must be a tool identifier, got kind %q", t.RegistryID.Kind)
	}
	if err := t.RegistryID.Validate(); err != nil {
		return fmt.Errorf("tool_call: %w", err)
	}
	if t.RegistryVersion <= 0 {
		return fmt.Errorf("tool_call: registry_version must be positive")
	}
	if t.ArgumentsDigest == "" {
		return fmt.Errorf("tool_call: arguments_digest is required")
	}
	return nil
}

// Actor is one hop of the delegation chain together with the identity
// attributes that resolve for it.
//
// Each hop carries its OWN identity attributes because each identity resolves
// in its own realm before the meet, and chains spanning realms are the normal
// case rather than an edge one: a human in a directory-backed realm invoking an
// agent whose workload identity lives in a cloud IAM realm is the ordinary
// shape of an agent request.
type Actor struct {
	ID ID `json:"id"`
	// Attributes are this hop's identity attributes. Only the principal
	// namespace may appear here, which is what makes per-hop evaluation
	// structural rather than a convention: there is nowhere to put a shared
	// attribute that would silently apply to one hop only.
	Attributes AttributeSet `json:"attributes"`
}

// Context carries the addressing fields that are not the subject, action or
// resource themselves.
type Context struct {
	// ActorChain is the ordered, cycle-free chain of intermediaries, ROOT
	// FIRST: the principal on whose behalf access is requested comes first and
	// each subsequent entry acted on behalf of the one before it. RFC 8693
	// nests `act` the other way round; ingestion reverses it exactly once, at
	// the edge, so that everything inward reads one direction.
	//
	// Effective authority is the intersection over the chain. Union across the
	// chain is the confused deputy: place an agent in a powerful group, have
	// any low-privilege user invoke it, and that user inherits the agent's
	// reach while every individual policy still looks correct in isolation.
	ActorChain []Actor `json:"actor_chain"`
	// Client identifies the authenticated application or credential. It is
	// attribution, never a policy-selected organization or human identity
	// (ADR-065 invariant 2).
	Client *ID `json:"client,omitempty"`
	// Session identifies the caller session.
	Session *ID `json:"session,omitempty"`
	// ToolCall is present when the action is a tool invocation.
	ToolCall *ToolCall `json:"tool_call,omitempty"`
}

// Request is the immutable, normalized authorization request the PDP evaluates.
//
// The external wire contract is AuthZEN SARC; this is what AxonFlow normalizes
// it into. Adapters never copy arbitrary caller JSON into trusted context: the
// only surface a policy can read is Attributes, and every entry there carries a
// state, a provenance class and a source version.
type Request struct {
	RequestID    string   `json:"request_id"`
	Organization ID       `json:"organization"`
	Principal    ID       `json:"principal"`
	Action       ID       `json:"action"`
	Resource     ID       `json:"resource"`
	Context      Context  `json:"context"`
	Snapshot     Snapshot `json:"snapshot"`
	// Attributes is the SHARED policy-visible surface: the action, the
	// resource, the caller arguments, the environment, platform state and
	// detector signals. Identity attributes do NOT live here; they live on the
	// actor they belong to, so an identity attribute cannot leak across hops.
	Attributes AttributeSet `json:"attributes"`
	// EvaluatedAt is the decision instant. Freshness bounds are applied
	// against it rather than against wall-clock time inside the evaluator, so
	// that a replay reproduces the original staleness verdicts exactly.
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Validate rejects a request that cannot be evaluated. ADR-065 invariant 4:
// unknown or malformed authorization input never becomes a permit, so a
// validation failure is an authorization error and the caller maps it to
// Indeterminate rather than to a request with missing optional data.
func (r *Request) Validate() error {
	if r == nil {
		return fmt.Errorf("request: is nil")
	}
	if r.RequestID == "" {
		return fmt.Errorf("request: request_id is required")
	}
	if r.EvaluatedAt.IsZero() {
		return fmt.Errorf("request: evaluated_at is required")
	}
	for _, f := range []struct {
		name string
		kind Kind
		id   ID
	}{
		{"organization", KindOrganization, r.Organization},
		{"principal", KindPrincipal, r.Principal},
		{"action", KindAction, r.Action},
		{"resource", KindResource, r.Resource},
	} {
		if f.id.Kind != f.kind {
			return fmt.Errorf("request: %s must be a %s identifier, got kind %q", f.name, f.kind, f.id.Kind)
		}
		if err := f.id.Validate(); err != nil {
			return fmt.Errorf("request: %s: %w", f.name, err)
		}
	}
	if err := r.Snapshot.Validate(); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if len(r.Context.ActorChain) == 0 {
		return fmt.Errorf("request: actor_chain must contain at least the principal")
	}
	if r.Context.ActorChain[0].ID != r.Principal {
		return fmt.Errorf("request: actor_chain must be root first and begin with the principal %q, got %q",
			r.Principal, r.Context.ActorChain[0].ID)
	}
	seen := make(map[string]struct{}, len(r.Context.ActorChain))
	for i, a := range r.Context.ActorChain {
		if a.ID.Kind != KindPrincipal {
			return fmt.Errorf("request: actor_chain[%d] must be a principal identifier, got kind %q", i, a.ID.Kind)
		}
		if err := a.ID.Validate(); err != nil {
			return fmt.Errorf("request: actor_chain[%d]: %w", i, err)
		}
		if _, dup := seen[a.ID.String()]; dup {
			return fmt.Errorf("request: actor_chain contains a cycle at %q", a.ID)
		}
		seen[a.ID.String()] = struct{}{}
		if err := a.Attributes.Validate(); err != nil {
			return fmt.Errorf("request: actor_chain[%d] %q: %w", i, a.ID, err)
		}
		for _, p := range a.Attributes.Paths() {
			if NamespaceOf(p) != NsPrincipal {
				return fmt.Errorf("request: actor_chain[%d] %q carries attribute %q; an actor may carry only principal attributes, because anything else would apply to one hop and not the others", i, a.ID, p)
			}
		}
	}
	for _, p := range r.Attributes.Paths() {
		if NamespaceOf(p) == NsPrincipal {
			return fmt.Errorf("request: shared attribute %q is in the principal namespace; identity attributes belong to the actor they describe, so that each hop is evaluated against its own identity", p)
		}
	}
	if r.Context.Client != nil {
		if r.Context.Client.Kind != KindClient {
			return fmt.Errorf("request: context.client must be a client identifier, got kind %q", r.Context.Client.Kind)
		}
		if err := r.Context.Client.Validate(); err != nil {
			return fmt.Errorf("request: context.client: %w", err)
		}
	}
	if r.Context.Session != nil {
		if r.Context.Session.Kind != KindSession {
			return fmt.Errorf("request: context.session must be a session identifier, got kind %q", r.Context.Session.Kind)
		}
		if err := r.Context.Session.Validate(); err != nil {
			return fmt.Errorf("request: context.session: %w", err)
		}
	}
	if r.Context.ToolCall != nil {
		if err := r.Context.ToolCall.Validate(); err != nil {
			return fmt.Errorf("request: %w", err)
		}
	}
	if err := r.Attributes.Validate(); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	return nil
}

// Decider evaluates a normalized request. It is the single seam the conformance
// suite drives, so that the corpus is an executable specification rather than a
// description of one implementation.
//
// A Decider must never return a nil Decision together with a nil error. It
// returns an error only for a defect in the evaluator itself; every
// authorization outcome, including an unevaluable one, is expressed as a
// Decision with Authorization Indeterminate.
type Decider interface {
	Decide(ctx context.Context, req *Request) (*Decision, error)
}
