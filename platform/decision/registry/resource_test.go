package registry

import (
	"strings"
	"testing"
)

// TestRecursiveResourceTypeRequiresABoundedDepth is AXC-305.
func TestRecursiveResourceTypeRequiresABoundedDepth(t *testing.T) {
	MarkConformanceCase("AXC-305")

	c := NewCatalog(fixtureNow)
	for name, depth := range map[string]int{"no depth": 0, "a negative depth": -1} {
		t.Run(name, func(t *testing.T) {
			err := c.RegisterResourceType(ResourceTypeRecord{
				Type: "Page", Ancestors: []string{"space"}, Recursion: RecursionBounded, MaxDepth: depth,
			})
			refusal(t, err, CodeMaxDepthInvalid)
		})
	}
	accepted(t, c.RegisterResourceType(ResourceTypeRecord{
		Type: "Page", Ancestors: []string{"space"}, Recursion: RecursionBounded, MaxDepth: 32,
	}))

	// An undeclared recursion class is refused too. Whether containment
	// continues below the innermost named level decides whether a truncated
	// closure is even possible, so it cannot be inferred from whether somebody
	// filled in a depth.
	fresh := NewCatalog(fixtureNow)
	refusal(t, fresh.RegisterResourceType(ResourceTypeRecord{Type: "Page", Ancestors: []string{"space"}}),
		CodeRecursionNotDeclared)
}

// TestNonRecursiveResourceTypeRefusesADepth is AXC-306.
func TestNonRecursiveResourceTypeRefusesADepth(t *testing.T) {
	MarkConformanceCase("AXC-306")

	c := NewCatalog(fixtureNow)
	err := c.RegisterResourceType(ResourceTypeRecord{
		Type: "Ticket", Ancestors: []string{"project"}, Recursion: RecursionNone, MaxDepth: 32,
	})
	refusal(t, err, CodeMaxDepthInvalid)
	if !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("the refusal does not say the two fields disagree: %v", err)
	}
	accepted(t, c.RegisterResourceType(ResourceTypeRecord{
		Type: "Ticket", Ancestors: []string{"project"}, Recursion: RecursionNone,
	}))
}

// TestContainmentScopeRequiresRecursion is AXC-307.
func TestContainmentScopeRequiresRecursion(t *testing.T) {
	MarkConformanceCase("AXC-307")

	c := newFixtureCatalog(t)

	// The recursive type passes.
	if got := c.CheckContainmentScope("Page"); got != nil {
		t.Fatalf("a containment scope over a recursive type was refused: %v", got)
	}

	got := c.CheckContainmentScope("Ticket")
	if got == nil {
		t.Fatalf("a containment scope over a non-recursive type was accepted")
	}
	if got.Code != CodeScopeRequiresRecursion {
		t.Fatalf("the finding names %s", got.Code)
	}

	// An unknown type is a finding, never a pass. A check that answers "fine"
	// on a type it has never heard of stops running the moment a catalog is
	// loaded empty, and reads as coverage the whole time.
	unknown := c.CheckContainmentScope("NeverRegistered")
	if unknown == nil {
		t.Fatalf("a containment scope over an unregistered type was accepted")
	}
	if unknown.Code != CodeUnknownResourceType {
		t.Fatalf("an unregistered type produced %s", unknown.Code)
	}
	empty := NewCatalog(fixtureNow)
	if empty.CheckContainmentScope("Page") == nil {
		t.Fatalf("an empty catalog accepted a containment scope")
	}
}

// TestUndeclaredAncestorLevelIsRefused is AXC-308.
func TestUndeclaredAncestorLevelIsRefused(t *testing.T) {
	MarkConformanceCase("AXC-308")

	c := newFixtureCatalog(t)
	for _, level := range []string{"project", "instance"} {
		if got := c.CheckAncestorLevel("Ticket", level); got != nil {
			t.Fatalf("declared level %q was refused: %v", level, got)
		}
	}

	got := c.CheckAncestorLevel("Ticket", "space")
	if got == nil {
		t.Fatalf("an undeclared level was accepted")
	}
	if got.Code != CodeLevelNotDeclared {
		t.Fatalf("the finding names %s", got.Code)
	}
	// The message has to say WHY this is a save-time check, because the
	// runtime symptom is a policy that is deployed, green and inert.
	if !strings.Contains(got.Message, "never matches and never errors") {
		t.Fatalf("the finding does not explain the runtime symptom: %s", got.Message)
	}

	unknown := c.CheckAncestorLevel("NeverRegistered", "project")
	if unknown == nil || unknown.Code != CodeUnknownResourceType {
		t.Fatalf("an unregistered type produced %v", unknown)
	}
}

// TestResourceTypeAncestorsAreAnOrderedProjection proves a duplicate level is
// refused: the levels are ordered innermost first, so a repeat makes the order
// ambiguous.
func TestResourceTypeAncestorsAreAnOrderedProjection(t *testing.T) {
	c := NewCatalog(fixtureNow)
	refusal(t, c.RegisterResourceType(ResourceTypeRecord{
		Type: "Page", Ancestors: []string{"space", "space"}, Recursion: RecursionNone,
	}), CodeLevelNotDeclared)
	refusal(t, c.RegisterResourceType(ResourceTypeRecord{
		Type: "Page", Ancestors: []string{"space", ""}, Recursion: RecursionNone,
	}), CodeLevelNotDeclared)
}

// TestRecursionDeclarationIsValidatedByMembership is the #3576 discipline over
// this enumeration.
func TestRecursionDeclarationIsValidatedByMembership(t *testing.T) {
	for _, r := range []RecursionDeclaration{RecursionUnspecified, RecursionDeclaration(99), RecursionDeclaration(-1)} {
		if r.IsValid() {
			t.Errorf("RecursionDeclaration(%d) reported itself a declared member", int(r))
		}
		if r.Recursive() {
			t.Errorf("RecursionDeclaration(%d) reported itself recursive", int(r))
		}
		c := NewCatalog(fixtureNow)
		refusal(t, c.RegisterResourceType(ResourceTypeRecord{Type: "X", Recursion: r}), CodeRecursionNotDeclared)
	}
	if !RecursionBounded.Recursive() || RecursionNone.Recursive() {
		t.Fatalf("the declared members disagree with Recursive")
	}
}
