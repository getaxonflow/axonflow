package pdp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// LintViolation is one bundle lint finding.
type LintViolation struct {
	Rule     string
	Location string
	Detail   string
}

func (v LintViolation) String() string {
	return fmt.Sprintf("%s at %s: %s", v.Rule, v.Location, v.Detail)
}

// Bundle lint rule names.
const (
	LintRawAttributeDereference = "RAW_ATTRIBUTE_DEREFERENCE"
	LintUnexpectedPackage       = "UNEXPECTED_PACKAGE"
	LintForeignImport           = "FOREIGN_IMPORT"
	LintUnparseable             = "UNPARSEABLE_MODULE"
	LintUnexpectedRule          = "UNEXPECTED_RULE"
	LintUnexpectedShape         = "UNEXPECTED_SHAPE"
)

// generatedRules are the only rules a compiled bundle may declare.
var generatedRules = map[string]bool{"policy_result": true, "authorities": true, "result": true}

// LintBundleModule rejects a generated module that is not the shape the
// compiler emits.
//
// It is a WHITELIST on structure, not a blacklist on one spelling, and the
// difference is the whole rule. An earlier version refused a reference rooted
// at `input` with more than two terms, which catches
// `input.attributes["x"].value` written literally and catches nothing at all
// once the same value is bound to a local variable or passed as a function
// argument, because the reference is then rooted somewhere else. A guard is
// only as wide as the syntax it matches, and the syntax an author can use is
// unbounded.
//
// So the module is checked against what Compile actually emits: three named
// rules, each a complete assignment with no body, whose values are built from
// scalars, collections, and calls into the platform-owned helper package. The
// single legal position for `input.attributes` is as a direct argument to one
// of those calls. Anything else, including a rule of its own, a helper of its
// own, a comprehension, or a variable, is refused.
//
// The lint runs on the module SOURCE at bundle load, not only at authoring
// time, so a bundle hand edited after compilation fails to activate.
func LintBundleModule(src, wantPackage string) error {
	module, err := ast.ParseModuleWithOpts("bundle.rego", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return fmt.Errorf("%s: %w", LintUnparseable, err)
	}
	var violations []LintViolation
	add := func(rule, loc, detail string) {
		violations = append(violations, LintViolation{Rule: rule, Location: loc, Detail: detail})
	}

	if got, want := module.Package.Path.String(), "data."+wantPackage; got != want {
		add(LintUnexpectedPackage, module.Package.Loc().String(),
			fmt.Sprintf("module declares package %q, expected exactly %q", got, want))
	}

	allowedImport := "data." + HelperPackage
	for _, imp := range module.Imports {
		if imp.Path.String() != allowedImport {
			add(LintForeignImport, imp.Loc().String(), fmt.Sprintf(
				"module imports %q; a generated bundle may import only the platform-owned helper package %q",
				imp.Path.String(), allowedImport))
		}
	}

	for _, rule := range module.Rules {
		loc := "unknown"
		if rule.Loc() != nil {
			loc = rule.Loc().String()
		}
		name := string(rule.Head.Name)
		if !generatedRules[name] {
			add(LintUnexpectedRule, loc, fmt.Sprintf(
				"module declares rule %q; a generated bundle declares only %s", name, sortedRuleNames()))
			continue
		}
		if rule.Else != nil {
			add(LintUnexpectedShape, loc, fmt.Sprintf("rule %q declares an else branch", name))
		}
		// A generated rule is a complete assignment: no body, no arguments, no
		// key. A body is where a hand edit would put a condition the combiner
		// never sees.
		if len(rule.Head.Args) > 0 {
			add(LintUnexpectedShape, loc, fmt.Sprintf("rule %q takes arguments; a generated rule is a value, not a function", name))
		}
		if rule.Head.Key != nil {
			add(LintUnexpectedShape, loc, fmt.Sprintf("rule %q is a partial rule; a generated rule assigns one complete value", name))
		}
		if !isTrivialBody(rule.Body) {
			add(LintUnexpectedShape, loc, fmt.Sprintf(
				"rule %q has a body; a generated rule is an unconditional assignment, so a body is a condition nothing validated", name))
		}
		if rule.Head.Value == nil {
			add(LintUnexpectedShape, loc, fmt.Sprintf("rule %q assigns no value", name))
			continue
		}
		violations = append(violations, lintTerm(rule.Head.Value, name)...)
	}
	for name := range generatedRules {
		found := false
		for _, rule := range module.Rules {
			if string(rule.Head.Name) == name {
				found = true
			}
		}
		if !found {
			add(LintUnexpectedRule, module.Package.Loc().String(),
				fmt.Sprintf("module declares no rule %q; the sealed result object would be incomplete", name))
		}
	}

	if len(violations) == 0 {
		return nil
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	msgs := make([]string, 0, len(violations))
	for _, v := range violations {
		msgs = append(msgs, v.String())
	}
	return fmt.Errorf("bundle lint rejected the module:\n  %s", strings.Join(msgs, "\n  "))
}

func sortedRuleNames() string {
	out := make([]string, 0, len(generatedRules))
	for n := range generatedRules {
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// isTrivialBody reports whether a rule body is the implicit `true` the parser
// gives an unconditional assignment.
func isTrivialBody(body ast.Body) bool {
	if len(body) == 0 {
		return true
	}
	if len(body) != 1 {
		return false
	}
	term, ok := body[0].Terms.(*ast.Term)
	if !ok {
		return false
	}
	b, ok := term.Value.(ast.Boolean)
	return ok && bool(b)
}

// lintTerm walks one value of a generated rule and refuses anything the
// compiler does not emit.
func lintTerm(term *ast.Term, ruleName string) []LintViolation {
	loc := "unknown"
	if term.Loc() != nil {
		loc = term.Loc().String()
	}
	switch v := term.Value.(type) {
	case ast.String, ast.Number, ast.Boolean, ast.Null:
		return nil
	case ast.Object:
		var out []LintViolation
		for _, pair := range v.Keys() {
			out = append(out, lintTerm(pair, ruleName)...)
			out = append(out, lintTerm(v.Get(pair), ruleName)...)
		}
		return out
	case *ast.Array:
		var out []LintViolation
		for i := 0; i < v.Len(); i++ {
			out = append(out, lintTerm(v.Elem(i), ruleName)...)
		}
		return out
	case ast.Call:
		return lintCall(v, ruleName, loc)
	case ast.Ref:
		// A helper CONSTANT, for example the unconditional verdict, is a
		// reference into the platform-owned package rather than a read of
		// anything the caller supplied, and the compiler does emit one.
		if isHelperRef(v) {
			return nil
		}
		// Any other bare reference is a read of input.attributes outside a
		// helper call, or a read of something else entirely. Neither is
		// emitted.
		return []LintViolation{{
			Rule: LintRawAttributeDereference, Location: loc,
			Detail: fmt.Sprintf("rule %q reads %q directly; every attribute read must be an argument to a %s helper so its state is inspected before its value",
				ruleName, v.String(), HelperPackage),
		}}
	case ast.Var:
		// The sealed result names the other two generated rules, which the
		// parser presents as bare variables because they resolve within the
		// package. Every other variable is refused: binding one is how an
		// attribute read is smuggled past a reference check.
		if generatedRules[v.String()] {
			return nil
		}
		return []LintViolation{{
			Rule: LintUnexpectedShape, Location: loc,
			Detail: fmt.Sprintf("rule %q reads the variable %q; a generated value binds no variables, and a variable is how an attribute read is smuggled past a reference check",
				ruleName, v.String()),
		}}
	default:
		return []LintViolation{{
			Rule: LintUnexpectedShape, Location: loc,
			Detail: fmt.Sprintf("rule %q contains a %T, which the compiler does not emit", ruleName, v),
		}}
	}
}

// lintCall refuses any call that is not into the platform-owned helper package,
// and refuses an attribute reference anywhere except as a whole argument to one.
func lintCall(call ast.Call, ruleName, loc string) []LintViolation {
	if len(call) == 0 {
		return []LintViolation{{Rule: LintUnexpectedShape, Location: loc, Detail: "an empty call"}}
	}
	operator, ok := call[0].Value.(ast.Ref)
	if !ok || !isHelperRef(operator) {
		return []LintViolation{{
			Rule: LintUnexpectedShape, Location: loc,
			Detail: fmt.Sprintf("rule %q calls %q; a generated value calls only into %s", ruleName, call[0].String(), HelperPackage),
		}}
	}
	var out []LintViolation
	for _, arg := range call[1:] {
		if ref, isRef := arg.Value.(ast.Ref); isRef {
			// input.attributes as a whole, or a helper constant. Nothing else:
			// an argument that is any other reference is the read this lint
			// exists to refuse, whatever it is rooted at.
			if isExactInputAttributes(ref) || isHelperRef(ref) {
				continue
			}
			out = append(out, LintViolation{
				Rule: LintRawAttributeDereference, Location: loc,
				Detail: fmt.Sprintf("rule %q passes %q to a helper; the only reference a generated value may pass is input.attributes as a whole",
					ruleName, ref.String()),
			})
			continue
		}
		out = append(out, lintTerm(arg, ruleName)...)
	}
	return out
}

func isHelperRef(r ast.Ref) bool {
	// data.axonflow.decision.tri.<fn>, or tri.<fn> after the import alias.
	s := r.String()
	return strings.HasPrefix(s, "data."+HelperPackage+".") || strings.HasPrefix(s, "tri.")
}

// isExactInputAttributes accepts the one legal reference and nothing near it.
func isExactInputAttributes(r ast.Ref) bool {
	if len(r) != 2 {
		return false
	}
	v, ok := r[0].Value.(ast.Var)
	if !ok || v.String() != "input" {
		return false
	}
	s, ok := r[1].Value.(ast.String)
	return ok && string(s) == "attributes"
}
