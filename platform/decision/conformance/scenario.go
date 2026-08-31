package conformance

import (
	"context"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
)

// Scenario names a request in fixture terms. Everything is a fixture key rather
// than a literal so that a case reads as the source case it transcribes.
type Scenario struct {
	// Principal is the fixture principal key.
	Principal string
	// Chain is the actor chain in fixture keys, ROOT FIRST. Empty means the
	// principal acting alone.
	Chain []string
	// Action is the fixture tool key, for example "T1".
	Action string
	// Resource is the fixture resource key. Empty uses the action's own
	// identifier as the resource, which is what a tool that declares no
	// resource mapping gets.
	Resource string
	// Args are the caller-supplied arguments.
	Args map[string]any
	// RiskScore is the accumulated inspection score. Nil means zero.
	RiskScore any
	// ExtraGroupEdges add directory edges, used to build a cyclic graph.
	ExtraGroupEdges map[string][]string
	// ExtraDirectGroups add direct memberships to the acting principal.
	ExtraDirectGroups []string
	// Overrides replace or remove individual attributes after the fixture has
	// built them. A nil value removes the attribute entirely, which is how the
	// corpus produces the "the Policy Information Point never produced this at
	// all" family.
	Overrides map[string]*contract.Attribute
	// RequestID overrides the derived request identifier.
	RequestID string
}

// Request builds the normalized request for a scenario.
func (w *World) Request(s Scenario) (*contract.Request, error) {
	p, ok := Principals[s.Principal]
	if !ok {
		return nil, fmt.Errorf("conformance: no fixture principal %q", s.Principal)
	}
	entry, ok := Actions[s.Action]
	if !ok {
		return nil, fmt.Errorf("conformance: no fixture action %q", s.Action)
	}

	_ = p
	attrs := contract.AttributeSet{
		PathActionID:   contract.Known(entry.ID.String(), contract.ProvPlatform, 18, Now),
		PathActionTags: contract.Known(toAnySlice(entry.Tags), contract.ProvPlatform, 18, Now),
		PathSignalRisk: contract.Known(0, contract.ProvDetector, 1, Now),
		PathAgentTrust: contract.Known("trusted", contract.ProvAuthentication, 7, Now),
	}
	if s.RiskScore != nil {
		attrs[PathSignalRisk] = contract.Known(s.RiskScore, contract.ProvDetector, 1, Now)
	}
	for k, v := range s.Args {
		attrs["args."+k] = contract.Known(v, contract.ProvCaller, 0, Now)
	}

	resourceID := contract.MustParseID(contract.KindResource, "Tool::"+RealmConnector+":"+entry.ID.Local)
	if s.Resource != "" {
		r, ok := Resources[s.Resource]
		if !ok {
			return nil, fmt.Errorf("conformance: no fixture resource %q", s.Resource)
		}
		resourceID = r.ID
		// Absent rather than missing: the resolver established that this
		// resource type declares no such level, which is a fact about the type
		// and not a failure to resolve.
		attrs[PathResourceOwner] = knownOrAbsent(r.Owner)
		attrs[PathResourceProject] = knownOrAbsent(r.Project)
		attrs[PathResourceClass] = knownOrAbsent(r.ProjectClassification)
		attrs[PathResourceRisk] = knownOrAbsent(r.CustomerRiskTier)
		if r.HasClosure {
			attrs[PathResourceClosure] = contract.Known(toAnySlice(r.Closure), contract.ProvResource, 14, Now)
		} else {
			attrs[PathResourceClosure] = contract.Absent(contract.ProvResource, 14, Now)
		}
	} else {
		attrs[PathResourceOwner] = contract.Absent(contract.ProvResource, 14, Now)
		attrs[PathResourceProject] = contract.Absent(contract.ProvResource, 14, Now)
		attrs[PathResourceClass] = contract.Absent(contract.ProvResource, 14, Now)
		attrs[PathResourceRisk] = contract.Absent(contract.ProvResource, 14, Now)
		attrs[PathResourceClosure] = contract.Absent(contract.ProvResource, 14, Now)
	}
	attrs[PathStateVelocity] = contract.Absent(contract.ProvPlatform, 1, Now)
	attrs[PathStateAnomaly] = contract.Absent(contract.ProvPlatform, 1, Now)
	attrs[PathEnvNewDevice] = contract.Absent(contract.ProvPlatform, 1, Now)

	chainKeys := s.Chain
	if len(chainKeys) == 0 {
		chainKeys = []string{s.Principal}
	}
	var chain []contract.Actor
	for _, key := range chainKeys {
		cp, ok := Principals[key]
		if !ok {
			return nil, fmt.Errorf("conformance: no fixture principal %q in the actor chain", key)
		}
		// Each hop carries its own identity attributes and its own closure.
		// A realm with no group concept yields an AUTHORITATIVE empty set; a
		// realm that has one but could not answer yields an unknown, and the
		// two must not share a representation.
		if key == s.Principal && len(s.ExtraDirectGroups) > 0 {
			cp.DirectGroups = append(append([]string(nil), cp.DirectGroups...), s.ExtraDirectGroups...)
		}
		hop := contract.AttributeSet{
			PathPrincipalID:     contract.Known(cp.ID.String(), contract.ProvAuthentication, 83, Now),
			PathPrincipalGroups: contract.Known(toAnySlice(cp.Closure(s.ExtraGroupEdges)), contract.ProvDirectory, 83, Now),
		}
		chain = append(chain, contract.Actor{ID: cp.ID, Attributes: hop})
	}

	// Overrides are applied last and may target either the shared surface or a
	// principal attribute; a principal path is applied to EVERY hop, because a
	// corpus entry that perturbs identity resolution is perturbing the
	// directory, which every hop in that realm reads.
	for path, a := range s.Overrides {
		if contract.NamespaceOf(path) == contract.NsPrincipal {
			for i := range chain {
				if a == nil {
					delete(chain[i].Attributes, path)
					continue
				}
				chain[i].Attributes[path] = *a
			}
			continue
		}
		if a == nil {
			delete(attrs, path)
			continue
		}
		attrs[path] = *a
	}

	requestID := s.RequestID
	if requestID == "" {
		requestID = "req_" + s.Principal + "_" + s.Action + "_" + s.Resource
	}
	req := &contract.Request{
		RequestID:    requestID,
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    chain[0].ID,
		Action:       entry.ID,
		Resource:     resourceID,
		Context: contract.Context{
			ActorChain: chain,
			ToolCall: &contract.ToolCall{
				RegistryID:      contract.MustParseID(contract.KindTool, "Tool::"+entry.ID.Local),
				RegistryVersion: 18,
				ArgumentsDigest: mustDigest(s.Args),
			},
		},
		Snapshot: contract.Snapshot{
			IdentityEpoch: 83, ResourceEpoch: 14, RegistryVersion: 18, PolicyEpoch: 1,
			PolicyBundle:  w.Bundles[0].Digest,
			SchemaVersion: contract.SchemaVersion,
		},
		Attributes:  attrs,
		EvaluatedAt: Now,
	}
	return req, nil
}

// Decide builds the request for a scenario and evaluates it.
func (w *World) Decide(ctx context.Context, s Scenario) (*contract.Decision, error) {
	req, err := w.Request(s)
	if err != nil {
		return nil, err
	}
	return w.Engine.Decide(ctx, req)
}

// UnknownAttr builds an unknown attribute carrying the provenance class its
// namespace declares. Building it from the PATH rather than by hand is what
// stops a corpus entry accidentally asserting a provenance violation instead of
// the tri-state property it meant to exercise.
func UnknownAttr(path string, reason contract.UnknownReason) *contract.Attribute {
	a := contract.Unknown(reason, contract.NamespaceOf(path).DefaultProvenance(), 1, Now)
	return &a
}

// AbsentAttr builds an authoritatively absent attribute for a path.
func AbsentAttr(path string) *contract.Attribute {
	a := contract.Absent(contract.NamespaceOf(path).DefaultProvenance(), 1, Now)
	return &a
}

// KnownAttr builds a resolved attribute for a path.
func KnownAttr(path string, value any) *contract.Attribute {
	a := contract.Known(value, contract.NamespaceOf(path).DefaultProvenance(), 1, Now)
	return &a
}

// StaleAttr builds a resolved attribute that is outside its declared freshness
// bound at the fixed evaluation instant, so the evaluator itself downgrades it
// to unknown rather than the fixture pre-cooking the answer.
func StaleAttr(path string, value any, maxAgeSeconds int64) *contract.Attribute {
	a := contract.Known(value, contract.NamespaceOf(path).DefaultProvenance(), 1, Now.Add(-2*time.Duration(maxAgeSeconds)*time.Second))
	a.MaxAgeSeconds = maxAgeSeconds
	return &a
}

func knownOrAbsent(v string) contract.Attribute {
	if v == "" {
		return contract.Absent(contract.ProvResource, 14, Now)
	}
	return contract.Known(v, contract.ProvResource, 14, Now)
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

func mustDigest(args map[string]any) string {
	d, err := contract.Digest(args)
	if err != nil {
		panic(err)
	}
	return d
}

// ObligationKeys renders a decision's obligations as stable comparison keys.
func ObligationKeys(d *contract.Decision) []string {
	out := make([]string, 0, len(d.Obligations))
	for _, o := range d.Obligations {
		key := string(o.Type)
		if o.Target != "" {
			key += "@" + o.Target
		}
		if keep, ok := o.Params["keep"]; ok {
			key += "[keep=" + keep + "]"
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ApprovalKeys renders an approval requirement as stable comparison keys, one
// per clause. Clauses are compared individually rather than as one collapsed
// pool, which is the whole point of the conjunction.
func ApprovalKeys(d *contract.Decision) []string {
	if d.Approval == nil {
		return nil
	}
	out := make([]string, 0, len(d.Approval.AllOf))
	for _, c := range d.Approval.AllOf {
		key := fmt.Sprintf("%d of", c.Quorum)
		names := make([]string, 0, len(c.Eligible))
		for _, e := range c.Eligible {
			names = append(names, e.Local)
		}
		sort.Strings(names)
		for _, n := range names {
			key += " " + n
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
