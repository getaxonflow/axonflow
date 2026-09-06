#!/usr/bin/env bash
# Regression test for examples/integrations/spring-boot/pom.xml (#3678).
#
# WHAT THIS PINS
# --------------
# The spring-boot example overrides Spring Boot's managed Tomcat through the
# <tomcat.version> property because the managed version has carried
# CRITICAL/HIGH CVEs on every recent scan (ten ids in the pom's own comment,
# then CVE-2026-65182 / -65905 / -68525 on 2026-09-03). The override is one
# line, and a dependency sweep that resets the parent's managed version, or a
# refactor that drops the property, silently reopens every one of them: the
# example still compiles, and the only thing that notices is the Trivy scan,
# after the fact, on someone else's PR.
#
# So this asserts the property itself:
#
#   1. the property is PRESENT (an absent override is the managed version)
#   2. its value is at or above the floor below, compared as a version, not
#      as a string ("10.1.6" is older than "10.1.59"; sort -V knows that)
#   3. the check is not vacuous: the same check run against a copy of the pom
#      carrying the pre-fix value FAILS, and against a copy with the property
#      removed FAILS. A guard that cannot go red is a comment.
#
# Raise TOMCAT_FLOOR when the pin moves for the next advisory; never lower it.
#
# Exit codes are read from the command directly. `out=$(cmd)` would move the
# status into a subshell and the assertions below would pass unconditionally.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POM="$REPO_ROOT/examples/integrations/spring-boot/pom.xml"
TOMCAT_FLOOR="10.1.59"

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); echo "  PASS: $1"; }
fail() { fail_count=$((fail_count + 1)); echo "  FAIL: $1"; }

# tomcat_override_ok <pom> -> 0 when <tomcat.version> is present and >= floor.
# One function, used by the real assertion and by both negative controls, so
# the controls exercise the exact predicate the assertion trusts.
tomcat_override_ok() {
  local pom="$1" value lowest
  value="$(grep -o '<tomcat.version>[^<]*</tomcat.version>' "$pom" | head -1 | sed 's/<[^>]*>//g')"
  [ -n "$value" ] || return 1
  lowest="$(printf '%s\n%s\n' "$TOMCAT_FLOOR" "$value" | sort -V | head -1)"
  [ "$lowest" = "$TOMCAT_FLOOR" ]
}

echo "spring-boot example Tomcat override floor ($TOMCAT_FLOOR)"

[ -f "$POM" ] || { fail "pom not found at $POM"; echo "RESULT: FAIL"; exit 1; }

# 1 + 2: the real pom.
if tomcat_override_ok "$POM"; then
  pass "<tomcat.version> present and >= $TOMCAT_FLOOR in examples/integrations/spring-boot/pom.xml"
else
  fail "<tomcat.version> missing or below $TOMCAT_FLOOR: $(grep -o '<tomcat.version>[^<]*</tomcat.version>' "$POM" || echo '<absent>')"
fi

# 3a: negative control, pre-fix value.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
sed 's#<tomcat.version>[^<]*</tomcat.version>#<tomcat.version>10.1.55</tomcat.version>#' "$POM" > "$tmp/old.xml"
if tomcat_override_ok "$tmp/old.xml"; then
  fail "negative control: a pom pinned to 10.1.55 passed the floor check (the predicate cannot go red)"
else
  pass "negative control: 10.1.55 is refused"
fi

# 3b: negative control, property removed.
grep -v '<tomcat.version>' "$POM" > "$tmp/absent.xml"
if tomcat_override_ok "$tmp/absent.xml"; then
  fail "negative control: a pom with NO <tomcat.version> passed (absent override reads as managed version)"
else
  pass "negative control: an absent override is refused"
fi

# 3c: positive control on the comparison, so a string compare cannot pass 1+2 by accident.
sed 's#<tomcat.version>[^<]*</tomcat.version>#<tomcat.version>10.1.6</tomcat.version>#' "$POM" > "$tmp/short.xml"
if tomcat_override_ok "$tmp/short.xml"; then
  fail "version compare is lexical: 10.1.6 passed a $TOMCAT_FLOOR floor"
else
  pass "version compare is numeric: 10.1.6 is refused"
fi

echo "RESULT: $pass_count passed, $fail_count failed"
[ "$fail_count" -eq 0 ]
