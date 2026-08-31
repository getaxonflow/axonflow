# Platform-owned tri-state condition helpers.
#
# ADR-065 "Explicit tri-state compilation model": native Rego undefined
# behaviour is not AxonFlow's third truth value. A missing reference or a
# runtime-undefined rule must never be interpreted as a constraint that did not
# apply. Every condition in a generated bundle is a call into this package, and
# every function here returns an OBJECT carrying an explicit verdict plus its
# reasons. There is no code path in this file that produces `undefined` for a
# tagged input, and there is no code path that reads `.value` before inspecting
# `.state`.
#
# This file is hand written and platform owned. The bundle lint rejects any
# generated module that dereferences `input.attributes` outside a call into
# this package, which is what stops an authored policy reintroducing a bare
# dereference the compiler was written to prevent.
package axonflow.decision.tri

# Verdicts. They are data, not booleans, precisely so that "unknown" cannot
# collapse into "false" at any point in the fold.
MATCH := "MATCH"

NO_MATCH := "NO_MATCH"

UNKNOWN := "UNKNOWN"

# ok wraps a determinate verdict.
ok(v) := {"v": v, "reasons": []}

# unk wraps an indeterminate verdict with the attribute path and reason that
# produced it. The reasons travel with the verdict so the Go boundary can
# report WHY a policy was unknown without re-deriving it.
unk(path, reason) := {"v": UNKNOWN, "reasons": [{"path": path, "reason": reason}]}

# attr resolves a tagged attribute. An attribute the Policy Information Point
# never produced becomes a tagged unknown here, so the caller cannot observe a
# Rego undefined reference. This single rule is the reason a policy referencing
# a typo'd path denies-or-errors rather than silently never matching.
attr(attrs, path) := v if {
	v := attrs[path]
} else := {"state": "unknown", "reason": "attribute_not_supplied"}

# type_ok checks a resolved value against the declared attribute type. It runs
# BEFORE any comparison, so a string arriving where the schema declared a
# number becomes a tagged unknown instead of a built-in error.
type_ok(v, "number") if is_number(v)

type_ok(v, "string") if is_string(v)

type_ok(v, "boolean") if is_boolean(v)

type_ok(v, "array") if is_array(v)

type_ok(v, "any") if v == v

# apply_op is the comparison itself, reached only for a value of the declared
# type.
apply_op("eq", v, lit) if v == lit

apply_op("ne", v, lit) if v != lit

apply_op("lt", v, lit) if v < lit

apply_op("le", v, lit) if v <= lit

apply_op("gt", v, lit) if v > lit

apply_op("ge", v, lit) if v >= lit

# state_verdict is the shared state discipline: unknown propagates with its own
# reason, a type mismatch is unknown rather than an error, and any state this
# file does not recognise is unknown rather than anything else.
#
# Absence is a NO_MATCH only where the caller passes `optional` true, and the
# compiler passes the POLICY's declared absence handling there, not the schema's
# optional flag. ADR-065 requires both conjuncts: the schema must mark the
# attribute optional AND the policy must say what absence means. The authoring
# validator enforces the pairing, so a generated call reaching this rule with
# `optional` true carries an author's explicit decision rather than a default.
#
# The final else is not dead code. It is what a value carrying a state string
# this build does not know about resolves to, which is the case a future
# Policy Information Point version produces against an older evaluator.
state_verdict(a, path, typ, optional, matched) := r if {
	a.state == "unknown"
	r := unk(path, a.reason)
} else := r if {
	a.state == "absent"
	optional == true
	r := ok(NO_MATCH)
} else := r if {
	a.state == "absent"
	r := unk(path, "required_attribute_absent")
} else := r if {
	a.state == "known"
	not type_ok(a.value, typ)
	r := unk(path, "schema_mismatch")
} else := r if {
	a.state == "known"
	matched == true
	r := ok(MATCH)
} else := r if {
	a.state == "known"
	r := ok(NO_MATCH)
} else := unk(path, "malformed_value")

# cmp compares one attribute against a literal.
cmp(attrs, path, op, lit, typ, optional) := r if {
	a := attr(attrs, path)
	r := state_verdict(a, path, typ, optional, op_matched(a, op, lit, typ))
}

# op_matched is guarded so it is only true for a known value of the declared
# type. Without the guard a comparison against a wrongly typed value would be
# evaluated before state_verdict had a chance to classify it.
op_matched(a, op, lit, typ) if {
	a.state == "known"
	type_ok(a.value, typ)
	apply_op(op, a.value, lit)
} else := false

# member checks that a literal is a member of an attribute collection.
member(attrs, path, lit, optional) := r if {
	a := attr(attrs, path)
	r := state_verdict(a, path, "array", optional, member_matched(a, lit))
}

member_matched(a, lit) if {
	a.state == "known"
	is_array(a.value)
	some i
	a.value[i] == lit
} else := false

# superset checks that an attribute collection contains every literal. This is
# the conjunctive selector: a constraint scoped to actions tagged BOTH
# irreversible AND pii_egress expresses something that no combination of
# single-tag constraints can express.
superset(attrs, path, lits, optional) := r if {
	a := attr(attrs, path)
	r := state_verdict(a, path, "array", optional, superset_matched(a, lits))
}

superset_matched(a, lits) if {
	a.state == "known"
	is_array(a.value)
	missing := {l | some j; l := lits[j]; not array_has(a.value, l)}
	count(missing) == 0
} else := false

array_has(arr, l) if {
	some i
	arr[i] == l
}

# intersects checks that an attribute collection shares at least one member
# with the literal set.
intersects(attrs, path, lits, optional) := r if {
	a := attr(attrs, path)
	r := state_verdict(a, path, "array", optional, intersects_matched(a, lits))
}

intersects_matched(a, lits) if {
	a.state == "known"
	is_array(a.value)
	some j
	array_has(a.value, lits[j])
} else := false

# attr_cmp compares two attributes. Both operands must resolve; if either is
# unresolvable the comparison is unknown, and the reasons of BOTH are carried so
# an operator sees every cause rather than only the first one.
#
# Absence on either side is unknown rather than NO_MATCH regardless of the
# optional flag. An optional attribute compared against a literal has a
# meaningful answer when it is absent; two attributes compared against each
# other do not, because "no value" is not equal to, less than, or greater than
# anything.
attr_cmp(attrs, left_path, right_path, op, typ) := r if {
	l := attr(attrs, left_path)
	rr := attr(attrs, right_path)
	r := pair_verdict(l, rr, left_path, right_path, op, typ)
}

pair_verdict(l, r, lp, rp, op, typ) := v if {
	l.state == "unknown"
	r.state == "unknown"
	v := {"v": UNKNOWN, "reasons": [{"path": lp, "reason": l.reason}, {"path": rp, "reason": r.reason}]}
} else := v if {
	l.state == "unknown"
	v := unk(lp, l.reason)
} else := v if {
	r.state == "unknown"
	v := unk(rp, r.reason)
} else := v if {
	l.state == "absent"
	v := unk(lp, "required_attribute_absent")
} else := v if {
	r.state == "absent"
	v := unk(rp, "required_attribute_absent")
} else := v if {
	l.state == "known"
	not type_ok(l.value, typ)
	v := unk(lp, "schema_mismatch")
} else := v if {
	r.state == "known"
	not type_ok(r.value, typ)
	v := unk(rp, "schema_mismatch")
} else := v if {
	l.state == "known"
	r.state == "known"
	apply_op(op, l.value, r.value)
	v := ok(MATCH)
} else := v if {
	l.state == "known"
	r.state == "known"
	v := ok(NO_MATCH)
} else := unk(lp, "malformed_value")

# k_and, k_or and k_not are Kleene's strong three-valued connectives.
#
# The load-bearing cell is FALSE and UNKNOWN yielding FALSE. A condition with a
# known-false conjunct is determinately false even when another term is
# unavailable, so short-circuiting is sound and removes a great deal of
# spurious indeterminacy during a partial dependency outage.
k_and(x, y) := r if {
	x.v == NO_MATCH
	r := ok(NO_MATCH)
} else := r if {
	y.v == NO_MATCH
	r := ok(NO_MATCH)
} else := r if {
	x.v == MATCH
	y.v == MATCH
	r := ok(MATCH)
} else := {"v": UNKNOWN, "reasons": array.concat(x.reasons, y.reasons)}

k_or(x, y) := r if {
	x.v == MATCH
	r := ok(MATCH)
} else := r if {
	y.v == MATCH
	r := ok(MATCH)
} else := r if {
	x.v == NO_MATCH
	y.v == NO_MATCH
	r := ok(NO_MATCH)
} else := {"v": UNKNOWN, "reasons": array.concat(x.reasons, y.reasons)}

k_not(x) := r if {
	x.v == MATCH
	r := ok(NO_MATCH)
} else := r if {
	x.v == NO_MATCH
	r := ok(MATCH)
} else := {"v": UNKNOWN, "reasons": x.reasons}

# k_true is the identity for k_and and the value of an unconditional policy.
k_true := ok(MATCH)

# k_false is the identity for k_or.
k_false := ok(NO_MATCH)
