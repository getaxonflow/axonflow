#!/usr/bin/env bash
# Regression test for examples/integrations/spring-boot/pom.xml (#3678).
#
# WHAT THIS PINS
# --------------
# The Spring Boot 3 example used an explicit <tomcat.version> override because
# that parent's managed Tomcat 10.1 line carried CRITICAL/HIGH CVEs. The v11.3
# dependency sweep moved the example to Spring Boot 4.0.9, whose effective POM
# manages Tomcat 11.0.27, and correctly removed the obsolete 10.1 override. The
# old guard still required the removed property, making main permanently red
# even though the resolved dependency was newer.
#
# So this asserts the effective source of the Tomcat floor without reaching the
# network:
#
#   1. when <tomcat.version> is present, it is at least 11.0.27;
#   2. otherwise the Spring Boot parent is at least 4.0.9, the first reviewed
#      parent in this repository whose managed Tomcat is 11.0.27;
#   3. both comparisons are version comparisons, not string comparisons;
#   4. controls prove an old parent, an old override, and short versions fail.
#
# Raise either floor when the reviewed managed line moves; never lower one.
#
# Exit codes are read from the command directly. `out=$(cmd)` would move the
# status into a subshell and the assertions below would pass unconditionally.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POM="$REPO_ROOT/examples/integrations/spring-boot/pom.xml"
TOMCAT_FLOOR="11.0.27"
SPRING_BOOT_FLOOR="4.0.9"

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); echo "  PASS: $1"; }
fail() { fail_count=$((fail_count + 1)); echo "  FAIL: $1"; }

# version_at_least <actual> <floor>
version_at_least() {
  local actual="$1" floor="$2" lowest
  [ -n "$actual" ] || return 1
  lowest="$(printf '%s\n%s\n' "$floor" "$actual" | sort -V | head -1)"
  [ "$lowest" = "$floor" ]
}

# pom_versions <pom> -> one TSV row: Spring Boot parent, Tomcat override.
# Parse XML rather than matching text: Maven ignores comments, so a commented
# safe-looking element must never hide an unsafe effective value.
pom_versions() {
  python3 - "$1" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
ns = {"m": "http://maven.apache.org/POM/4.0.0"}
parent = root.find("m:parent", ns)
if parent is None:
    raise SystemExit("missing Maven parent")

group = parent.findtext("m:groupId", default="", namespaces=ns).strip()
artifact = parent.findtext("m:artifactId", default="", namespaces=ns).strip()
version = parent.findtext("m:version", default="", namespaces=ns).strip()
if (group, artifact) != ("org.springframework.boot", "spring-boot-starter-parent"):
    raise SystemExit("parent is not org.springframework.boot:spring-boot-starter-parent")

properties = root.find("m:properties", ns)
override = ""
if properties is not None:
    override = properties.findtext("m:tomcat.version", default="", namespaces=ns).strip()
print(f"{version}\t{override}")
PY
}

# tomcat_floor_ok <pom> -> 0 when an explicit override is safe, or when the
# reviewed Spring Boot parent supplies the safe managed line.
tomcat_floor_ok() {
  local pom="$1" values override parent
  values="$(pom_versions "$pom")" || return 1
  case "$values" in
    *$'\t'*) ;;
    *) return 1 ;;
  esac
  parent="${values%%$'\t'*}"
  override="${values#*$'\t'}"
  if [ -n "$override" ]; then
    version_at_least "$override" "$TOMCAT_FLOOR"
    return
  fi
  version_at_least "$parent" "$SPRING_BOOT_FLOOR"
}

echo "spring-boot example Tomcat floor (explicit >= $TOMCAT_FLOOR or Spring Boot >= $SPRING_BOOT_FLOOR)"

[ -f "$POM" ] || { fail "pom not found at $POM"; echo "RESULT: FAIL"; exit 1; }

# 1 + 2: the real pom. Maven resolves Spring Boot 4.0.9 to Tomcat 11.0.27;
# this hermetic guard pins the reviewed parent-to-managed-version boundary.
if tomcat_floor_ok "$POM"; then
  pass "Tomcat floor is supplied by a safe override or Spring Boot parent"
else
  fail "neither <tomcat.version> >= $TOMCAT_FLOOR nor Spring Boot parent >= $SPRING_BOOT_FLOOR"
fi

# 3a: an explicit override wins over dependency management and must itself be
# safe. Plant the pre-fix value into the current POM.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
sed '/<java.version>/a\
        <tomcat.version>10.1.55</tomcat.version>' "$POM" > "$tmp/old-override.xml"
if tomcat_floor_ok "$tmp/old-override.xml"; then
  fail "negative control: an explicit 10.1.55 override passed the floor check"
else
  pass "negative control: an explicit 10.1.55 override is refused"
fi

# 3b: without an override, an older parent is refused.
sed 's#<version>4\.0\.9</version>#<version>3.5.14</version>#' "$POM" > "$tmp/old-parent.xml"
if tomcat_floor_ok "$tmp/old-parent.xml"; then
  fail "negative control: Spring Boot 3.5.14 passed the managed-version floor"
else
  pass "negative control: Spring Boot 3.5.14 without an override is refused"
fi

# 3c: a short override must not pass lexically.
sed '/<java.version>/a\
        <tomcat.version>11.0.6</tomcat.version>' "$POM" > "$tmp/short-override.xml"
if tomcat_floor_ok "$tmp/short-override.xml"; then
  fail "version compare is lexical: 11.0.6 passed a $TOMCAT_FLOOR floor"
else
  pass "version compare is numeric: an explicit 11.0.6 is refused"
fi

# 3d: and the parent comparison uses the same numeric semantics.
sed 's#<version>4\.0\.9</version>#<version>4.0.8</version>#' "$POM" > "$tmp/short-parent.xml"
if tomcat_floor_ok "$tmp/short-parent.xml"; then
  fail "parent comparison is lexical: Spring Boot 4.0.8 passed"
else
  pass "parent comparison refuses Spring Boot 4.0.8"
fi

# 3e: XML comments are not Maven configuration. The old grep-based predicate
# accepted the first text-shaped match even when Maven ignored it.
python3 - "$POM" "$tmp/commented-override.xml" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
needle = "        <java.version>17</java.version>"
replacement = """        <!-- <tomcat.version>11.0.27</tomcat.version> -->
        <java.version>17</java.version>
        <tomcat.version>10.1.55</tomcat.version>"""
assert needle in src
open(sys.argv[2], "w", encoding="utf-8").write(src.replace(needle, replacement, 1))
PY
if tomcat_floor_ok "$tmp/commented-override.xml"; then
  fail "a commented safe override hid an unsafe effective override"
else
  pass "a commented safe override cannot hide an unsafe effective override"
fi

# 3f: the parent must also be the real XML element, not a commented decoy.
python3 - "$POM" "$tmp/commented-parent.xml" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
safe = """    <!--
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>4.0.9</version>
    </parent>
    -->
"""
src = src.replace("<version>4.0.9</version>", "<version>3.5.14</version>", 1)
src = src.replace("    <parent>", safe + "    <parent>", 1)
open(sys.argv[2], "w", encoding="utf-8").write(src)
PY
if tomcat_floor_ok "$tmp/commented-parent.xml"; then
  fail "a commented safe parent hid an unsafe effective parent"
else
  pass "a commented safe parent cannot hide an unsafe effective parent"
fi

echo "RESULT: $pass_count passed, $fail_count failed"
[ "$fail_count" -eq 0 ]
