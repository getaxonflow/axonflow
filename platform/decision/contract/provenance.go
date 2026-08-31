package contract

import (
	"fmt"
	"sort"
	"strings"
)

// Provenance is the class of source that produced an attribute value.
//
// ADR-065 "Canonical authorization request": each field records provenance as
// authentication-derived, directory-derived, resource-derived, platform-derived,
// detector-derived, or caller-supplied. Policy uses only attributes allowed by
// the action schema and provenance rules.
type Provenance string

const (
	// ProvAuthentication is derived from a validated credential: issuer,
	// subject, audience, authorized party, session.
	ProvAuthentication Provenance = "authentication"
	// ProvDirectory is derived from the normalized identity graph.
	ProvDirectory Provenance = "directory"
	// ProvResource is fetched from the governed system for the resource under
	// decision, including its resolver-materialized ancestors.
	ProvResource Provenance = "resource"
	// ProvPlatform is observed by AxonFlow itself: environment, registries,
	// counters.
	ProvPlatform Provenance = "platform"
	// ProvDetector is produced by an inspection control.
	ProvDetector Provenance = "detector"
	// ProvCaller is whatever the caller sent. It is untrusted.
	ProvCaller Provenance = "caller"
)

// AllProvenances returns every declared provenance class in a stable order.
func AllProvenances() []Provenance {
	return []Provenance{
		ProvAuthentication, ProvDirectory, ProvResource,
		ProvPlatform, ProvDetector, ProvCaller,
	}
}

// Validate rejects an undeclared provenance class.
func (p Provenance) Validate() error {
	for _, known := range AllProvenances() {
		if known == p {
			return nil
		}
	}
	if p == "" {
		return fmt.Errorf("provenance is required")
	}
	return fmt.Errorf("provenance %q is not a declared class", p)
}

// Trusted reports whether the class may establish authority.
//
// Exactly one class is untrusted. That asymmetry is the whole authority rule:
// the model chooses which ticket to ask about, and it cannot choose what is
// true about that ticket.
func (p Provenance) Trusted() bool { return p != ProvCaller }

// Namespace is the first segment of an attribute path. Namespaces exist so the
// trust class of a term is lexically visible in the policy text: if arguments
// and fetched attributes both lived under one bag, no author and no reviewer
// could tell by reading a policy whether a term is authoritative or forged, and
// the static authority check below would be impossible to write.
type Namespace string

const (
	// NsPrincipal is the authority on whose behalf access is requested.
	NsPrincipal Namespace = "principal"
	// NsAgent is the calling agent or client, established by attestation.
	NsAgent Namespace = "agent"
	// NsResource is the resource under decision and its resolver-materialized
	// named ancestors and containment closure.
	NsResource Namespace = "resource"
	// NsAction is the registered action and its registry metadata.
	NsAction Namespace = "action"
	// NsEnv is gateway observation: time, network zone, device posture.
	NsEnv Namespace = "env"
	// NsArgs is caller-supplied argument data. Untrusted.
	NsArgs Namespace = "args"
	// NsState is platform counter state, for example a reserved budget total.
	NsState Namespace = "state"
	// NsSignal is detector output.
	NsSignal Namespace = "signal"
	// NsUnknown is returned for a path with no declared namespace.
	NsUnknown Namespace = ""
)

// namespaceProvenance declares which provenance classes may populate each
// namespace. A value arriving in a namespace it is not allowed to occupy is a
// contract violation, not a policy question: it is how caller-supplied context
// would otherwise overwrite a trusted identity or resource field.
var namespaceProvenance = map[Namespace][]Provenance{
	NsPrincipal: {ProvAuthentication, ProvDirectory},
	NsAgent:     {ProvAuthentication, ProvDirectory, ProvPlatform},
	NsResource:  {ProvResource},
	NsAction:    {ProvPlatform},
	NsEnv:       {ProvPlatform},
	NsArgs:      {ProvCaller},
	NsState:     {ProvPlatform},
	NsSignal:    {ProvDetector},
}

// AllNamespaces returns every declared namespace in a stable order. The
// tri-state corpus enumerates this so that a new namespace without corpus
// coverage fails the completeness test.
func AllNamespaces() []Namespace {
	out := make([]Namespace, 0, len(namespaceProvenance))
	for ns := range namespaceProvenance {
		out = append(out, ns)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// NamespaceOf returns the namespace of an attribute path.
func NamespaceOf(path string) Namespace {
	head, _, _ := strings.Cut(path, ".")
	ns := Namespace(head)
	if _, ok := namespaceProvenance[ns]; ok {
		return ns
	}
	return NsUnknown
}

// Trusted reports whether attributes in this namespace may establish authority.
func (n Namespace) Trusted() bool {
	allowed, ok := namespaceProvenance[n]
	if !ok {
		return false
	}
	for _, p := range allowed {
		if !p.Trusted() {
			return false
		}
	}
	return true
}

// DefaultProvenance is the provenance recorded for a synthesised unknown in
// this namespace, so that an attribute the Policy Information Point never
// produced still carries a correct source class in the trace.
func (n Namespace) DefaultProvenance() Provenance {
	allowed, ok := namespaceProvenance[n]
	if !ok || len(allowed) == 0 {
		return ProvPlatform
	}
	return allowed[0]
}

// ValidateProvenance rejects a value whose provenance class is not permitted in
// its namespace.
func (n Namespace) ValidateProvenance(path string, p Provenance) error {
	allowed, ok := namespaceProvenance[n]
	if !ok {
		return fmt.Errorf("attribute %q: %q is not a declared namespace", path, strings.SplitN(path, ".", 2)[0])
	}
	for _, a := range allowed {
		if a == p {
			return nil
		}
	}
	return fmt.Errorf("attribute %q: provenance %q is not permitted in namespace %q (permitted: %v)", path, p, n, allowed)
}

// ValidateAttributePath rejects a path that is not a dotted path rooted in a
// declared namespace.
func ValidateAttributePath(path string) error {
	if path == "" {
		return fmt.Errorf("attribute path is empty")
	}
	if NamespaceOf(path) == NsUnknown {
		head, _, _ := strings.Cut(path, ".")
		return fmt.Errorf("attribute path %q: %q is not a declared namespace", path, head)
	}
	segments := strings.Split(path, ".")
	if len(segments) < 2 {
		return fmt.Errorf("attribute path %q: a namespace alone is not an attribute", path)
	}
	for _, s := range segments {
		if s == "" {
			return fmt.Errorf("attribute path %q: contains an empty segment", path)
		}
		if strings.TrimSpace(s) != s {
			return fmt.Errorf("attribute path %q: segment %q has surrounding whitespace", path, s)
		}
	}
	return nil
}
