package registry

import "fmt"

// RecursionDeclaration is whether a resource type's hierarchy admits a
// transitive containment closure.
//
// Three-valued for the usual reason, and here the permissive reading is the
// UNAVAILABLE one rather than the permissive one, which is worth stating
// because it inverts the usual argument. A type wrongly recorded as
// non-recursive makes CheckContainmentScope refuse a containment scope that is
// in fact meaningful, and an author then denormalizes the ancestor onto every
// leaf to work around it. The failure is a worse policy, not a wider one, and
// it is silent either way, which is why the flag is declared rather than
// defaulted in both directions.
type RecursionDeclaration int

const (
	// RecursionUnspecified is the zero value and is never valid.
	RecursionUnspecified RecursionDeclaration = iota
	// RecursionNone means the hierarchy is exactly the declared named levels.
	RecursionNone
	// RecursionBounded means containment continues below the innermost named
	// level, to a declared maximum depth.
	RecursionBounded
)

// String renders the declaration.
func (r RecursionDeclaration) String() string {
	switch r {
	case RecursionNone:
		return "none"
	case RecursionBounded:
		return "bounded"
	case RecursionUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("RecursionDeclaration(%d)", int(r))
	}
}

// IsValid reports whether the declaration is one of the declared members.
func (r RecursionDeclaration) IsValid() bool {
	switch r {
	case RecursionNone, RecursionBounded:
		return true
	case RecursionUnspecified:
		return false
	default:
		return false
	}
}

// Recursive reports whether the type admits a transitive closure.
func (r RecursionDeclaration) Recursive() bool { return r == RecursionBounded }

// ResourceTypeRecord is one registered resource type and its hierarchy.
//
// The field names match platform/decision/authoring.ResourceType deliberately,
// so the authoring plane can be derived from this registry rather than
// maintaining a second table of the same facts. MaxDepth is the field this
// record adds: the authoring shape has no depth, and without one neither the
// bounded closure nor a depth-aware save-time check can be expressed.
type ResourceTypeRecord struct {
	// Type is the entity type segment of a resource identifier.
	Type string `json:"type"`
	// Ancestors are the declared hierarchy level names, innermost first. A
	// policy may read a named level only if it appears here.
	Ancestors []string `json:"ancestors"`
	// Recursion declares whether containment continues below the innermost
	// named level.
	Recursion RecursionDeclaration `json:"recursion"`
	// MaxDepth bounds the containment closure. It is required for a recursive
	// type and refused on a non-recursive one, where it would be a bound on a
	// traversal that does not happen.
	MaxDepth int `json:"max_depth,omitempty"`
	// PayloadLeaves are the canonical leaf field paths of this type's
	// representation.
	PayloadLeaves []string `json:"payload_leaves,omitempty"`
}

// Validate checks one resource type.
func (r ResourceTypeRecord) Validate() Findings {
	var out Findings
	subject := r.Type
	if r.Type == "" {
		subject = "(empty resource type)"
		out = out.errorf(CodeUnknownResourceType, subject, "a resource type record carries an empty type")
	}
	if !r.Recursion.IsValid() {
		out = out.errorf(CodeRecursionNotDeclared, subject,
			"recursion is %s; whether containment continues below the innermost named level is declared, not inferred from whether a depth was filled in",
			r.Recursion)
	}
	switch {
	case r.Recursion == RecursionBounded && r.MaxDepth <= 0:
		out = out.errorf(CodeMaxDepthInvalid, subject,
			"a recursive resource type declares a positive maximum depth, got %d; an unbounded closure is how a graph walk becomes a denial of service against the evaluator",
			r.MaxDepth)
	case r.Recursion == RecursionNone && r.MaxDepth != 0:
		out = out.errorf(CodeMaxDepthInvalid, subject,
			"a non-recursive resource type carries maximum depth %d, which bounds a traversal that never happens; the depth and the recursion flag disagree and one of them is wrong",
			r.MaxDepth)
	}
	seen := map[string]bool{}
	for _, level := range r.Ancestors {
		if level == "" {
			out = out.errorf(CodeLevelNotDeclared, subject, "an ancestor level name is empty")
			continue
		}
		if seen[level] {
			out = out.errorf(CodeLevelNotDeclared, subject,
				"ancestor level %q is declared more than once; the levels are an ordered projection, so a duplicate makes the order ambiguous", level)
		}
		seen[level] = true
	}
	return out
}

// clone returns a deep copy of the record. See ActionRecord.clone.
func (r ResourceTypeRecord) clone() ResourceTypeRecord {
	out := r
	out.Ancestors = append([]string(nil), r.Ancestors...)
	out.PayloadLeaves = append([]string(nil), r.PayloadLeaves...)
	return out
}

// DeclaresLevel reports whether the type declares a named ancestor level.
func (r ResourceTypeRecord) DeclaresLevel(level string) bool {
	for _, have := range r.Ancestors {
		if have == level {
			return true
		}
	}
	return false
}
