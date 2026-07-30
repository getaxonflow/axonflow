#!/usr/bin/env bash
# Regression test for .github/scripts/compile-java-examples.sh (#3158, #3185).
#
# WHAT THIS PINS
# --------------
# The gate exists because `mvn dependency:go-offline` RESOLVES without
# COMPILING, so three shipped examples stayed broken across four SDK majors
# with CI green. A replacement gate is only worth having if it cannot itself
# report success without doing the work, so each fail-closed property is
# asserted here behaviourally rather than described in a comment.
#
#   1. discovery of zero projects fails                      -> scenario 3
#   2. a project whose build fails, fails the run             -> scenario 2
#   3. discovered != attempted fails, independently of the
#      loop that would lose the entry (mutation-tested)       -> scenario 6
#   4. a Java level with no installed JDK fails, and is NOT
#      built with the default JDK instead                     -> scenario 5
#   5. a missing tree fails rather than passing vacuously     -> scenario 4
#   6. the goal really is `compile`                           -> scenario 1
#   7. a build emitting no class files fails                  -> scenario 8
#   8. a <mainClass> with no matching class file fails        -> scenario 8
#   9. JAVA_HOME is only trusted when its version matches     -> scenario 9
#  10. the real examples/ tree is discoverable, fully
#      resolvable, and reached through the script's OWN
#      default discovery root                                 -> scenario 7
#
# The goal assertion (6) is the one that took a hostile review to surface. The
# first version of this suite recorded only `JAVA_HOME` and the `-f` argument,
# so `compile` could be changed to `dependency:go-offline` — literally the
# behaviour the gate exists to replace — and all 21 assertions still passed.
# The stub now records full argv.
#
# Exit codes are read from the command directly. `out=$(cmd)` would move the
# status into a subshell and every assertion below would then pass
# unconditionally — the defect class this suite exists to catch.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$REPO_ROOT/.github/scripts/compile-java-examples.sh"

failures=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }

if [ ! -f "$GATE" ]; then
    echo "FAIL: gate script not found at $GATE"
    exit 1
fi

WORK="$(mktemp -d)"

# ---------------------------------------------------------------------------
# Hermetic environment.
#
# The gate discovers JDKs from JAVA_HOME_<version>_<ARCH> and, as a last
# resort, from JAVA_HOME. A GitHub-hosted runner exports several of those
# globally (the ubuntu-latest image ships JDKs 11/17/21), so a scenario that
# merely declines to SET one is not isolated from them — it silently measures
# the runner's JDK instead of its fixture.
#
# That is not hypothetical: scenario 9 below passed locally, where no
# JAVA_HOME_* variable exists, and failed on CI, where JAVA_HOME_17_X64 points
# at a real JDK 17 and satisfied the very request the scenario expects to be
# refused. Every scenario is therefore run from a cleared slate and sets
# exactly the variables it means to test.
for _jh in ${!JAVA_HOME@}; do
    unset "$_jh"
done
unset _jh

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A stub Maven that records, per invocation, the JAVA_HOME it was handed and
# its FULL argv, so both JDK selection and the invoked goal can be asserted on
# evidence rather than on what the gate prints about itself. On the `ok`
# outcome it also emits a class file for every source file, because the gate
# asserts class output — a stub that exits 0 without producing anything would
# be testing a state real Maven never reaches.
make_stub_mvn() {
    local dir="$1" outcome="$2" emit="${3:-emit}"   # outcome: ok|fail   emit: emit|no-emit
    cat > "$dir/mvn" <<STUB
#!/usr/bin/env bash
pom=""
args=("\$@")
for ((i=0; i<\${#args[@]}; i++)); do
    if [ "\${args[i]}" = "-f" ]; then pom="\${args[i+1]}"; fi
done
echo "\${JAVA_HOME:-unset}|\$pom|\$*" >> "$dir/invocations.txt"

# Per-path overrides, so a scenario can drive ONE project of a real tree into
# each failure mode without editing that tree. STUB_FAIL_FOR makes the build
# fail; STUB_NO_EMIT_FOR makes it succeed while emitting nothing; and
# STUB_WRONG_CLASS_FOR makes it emit a class at a path no <mainClass> names.
if [ -n "\${STUB_FAIL_FOR:-}" ] && [[ "\$pom" == *"\$STUB_FAIL_FOR"* ]]; then
    echo "simulated compilation failure for \$pom" >&2
    exit 1
fi
if [ -n "\${STUB_NO_EMIT_FOR:-}" ] && [[ "\$pom" == *"\$STUB_NO_EMIT_FOR"* ]]; then
    exit 0
fi
if [ -n "\${STUB_WRONG_CLASS_FOR:-}" ] && [[ "\$pom" == *"\$STUB_WRONG_CLASS_FOR"* ]]; then
    mkdir -p "\$(dirname "\$pom")/target/classes/zz"
    : > "\$(dirname "\$pom")/target/classes/zz/Unrelated.class"
    exit 0
fi
STUB
    if [ "$outcome" = "fail" ]; then
        echo 'echo "simulated compilation failure" >&2; exit 1' >> "$dir/mvn"
    else
        if [ "$emit" = "emit" ]; then
            cat >> "$dir/mvn" <<'STUB'
proj="$(dirname "$pom")"
while IFS= read -r src; do
    rel="${src#"$proj"/src/main/java/}"
    out="$proj/target/classes/${rel%.java}.class"
    mkdir -p "$(dirname "$out")"
    : > "$out"
done < <(find "$proj/src/main/java" -name '*.java' 2>/dev/null)
STUB
        fi
        echo 'exit 0' >> "$dir/mvn"
    fi
    chmod +x "$dir/mvn"
}

# Writes a minimal pom declaring $2 as its Java level via property $3, plus one
# trivial source file so a successful stub build has something to emit.
make_pom() {
    local dir="$1" level="$2" prop="${3:-maven.compiler.release}"
    local name; name="$(basename "$dir")"
    mkdir -p "$dir/src/main/java/demo"
    cat > "$dir/pom.xml" <<POM
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>${name}</artifactId><version>1</version>
  <properties><${prop}>${level}</${prop}></properties>
</project>
POM
    printf 'package demo;\npublic class Main { public static void main(String[] a) {} }\n' \
        > "$dir/src/main/java/demo/Main.java"
}

# Fake JDK homes. The gate requires bin/javac to be executable before it will
# accept a JAVA_HOME_* value, so the stub has to be a real executable file, and
# it must report its own feature version for the version-match guard.
make_fake_jdk() {
    local home="$1" version="$2"
    mkdir -p "$home/bin"
    printf '#!/usr/bin/env bash\necho "javac %s.0.1" >&2\n' "$version" > "$home/bin/javac"
    chmod +x "$home/bin/javac"
}

JDK17="$WORK/jdk17"; make_fake_jdk "$JDK17" 17
JDK21="$WORK/jdk21"; make_fake_jdk "$JDK21" 21

# A COPY of the real examples tree, sources only.
#
# Scenarios 7 and 10 run the real gate over the real pom set. Doing that in the
# repository itself is not acceptable: the stub Maven writes zero-byte .class
# files into examples/**/target/classes, Maven's incremental compiler then sees
# them as up to date and skips recompiling, and the next real `mvn exec:java`
# dies with `ClassFormatError: Truncated class file`. A test that leaves the
# working tree unable to build is worse than the defect it guards.
#
# target/ is excluded so the copy is small and starts clean. The pom set, the
# directory layout and the relative discovery root are all identical, so what
# those scenarios assert is unchanged.
REAL_ROOT="$WORK/real-root"
mkdir -p "$REAL_ROOT"
tar -cf - -C "$REPO_ROOT" --exclude='target' examples | tar -xf - -C "$REAL_ROOT"

# Runs the gate with the fixture environment. Writes combined output to $2 and
# returns the gate's own exit status.
run_gate() {
    local examples_dir="$1" logfile="$2" stubdir="$3" supported="${4:-17 21}" script="${5:-$GATE}"
    # POM_INTROSPECT is passed explicitly so a mutated COPY of the gate, which
    # lives in a scratch directory, still finds the real introspector. Without
    # it a mutant fails on "pom_introspect.py not found" and the mutation test
    # proves nothing — which is exactly what the scenario-6 message caught.
    POM_INTROSPECT="$REPO_ROOT/.github/scripts/pom_introspect.py" \
    JAVA_HOME_17_X64="$JDK17" \
    JAVA_HOME_21_X64="$JDK21" \
    JAVA_HOME="" \
    EXAMPLES_DIR="$examples_dir" \
    MVN_BIN="$stubdir/mvn" \
    SUPPORTED_JDKS="$supported" \
    bash "$script" > "$logfile" 2>&1
}

# ---------------------------------------------------------------------------
echo "Scenario 1: everything builds, on the JDK each pom asks for, with the right goal"
# ---------------------------------------------------------------------------
S1="$WORK/s1"; mkdir -p "$S1/tree"
make_stub_mvn "$S1" ok
make_pom "$S1/tree/legacy" 11
make_pom "$S1/tree/current" 17 maven.compiler.target
make_pom "$S1/tree/modern" 21
make_pom "$S1/tree/springish" 17 java.version
# The maven-compiler-plugin <configuration> idiom, and 1.8-style spellings.
mkdir -p "$S1/tree/plugincfg/src/main/java/demo"
cat > "$S1/tree/plugincfg/pom.xml" <<'POM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>plugincfg</artifactId><version>1</version>
  <build><plugins><plugin>
    <artifactId>maven-compiler-plugin</artifactId>
    <configuration><release>17</release></configuration>
  </plugin></plugins></build>
</project>
POM
printf 'package demo;\npublic class Main {}\n' > "$S1/tree/plugincfg/src/main/java/demo/Main.java"

run_gate "$S1/tree" "$S1/log" "$S1"
rc=$?

if [ "$rc" -eq 0 ]; then pass "exit 0 when every project builds"; else
    fail "expected exit 0, got $rc"; sed -n '1,40p' "$S1/log"; fi

if [ "$(wc -l < "$S1/invocations.txt" | tr -d ' ')" = "5" ]; then
    pass "all 5 projects were actually handed to maven"
else
    fail "expected 5 maven invocations, got $(wc -l < "$S1/invocations.txt" | tr -d ' ')"
fi

# THE assertion the first version of this suite was missing. Without it the
# gate can be reverted to `dependency:go-offline` — the exact behaviour its
# header condemns as the reason #3158 was invisible — and stay green.
# Matched against the ARGV FIELD ONLY (field 3 of JAVA_HOME|pom|argv), not the
# whole record: the record also holds two filesystem paths, so a scratch
# directory named ".../compile/..." would satisfy a whole-line match for
# entirely the wrong reason.
noncompile="$(cut -d'|' -f3- "$S1/invocations.txt" | grep -cvE '(^| )compile( |$)' || true)"
# `clean` must be there too: without it Maven's incremental build emits nothing
# on a re-run and the class-output assertion has to be weakened to survive.
nonclean="$(cut -d'|' -f3- "$S1/invocations.txt" | grep -cvE '(^| )clean( |$)' || true)"
if [ "$noncompile" = "0" ]; then
    pass "every invocation ran the 'compile' goal, not a resolve-only goal"
else
    fail "$noncompile invocation(s) did not run 'compile'"; cat "$S1/invocations.txt"
fi
if [ "$nonclean" = "0" ]; then
    pass "every invocation ran 'clean' first, so class output means THIS build"
else
    fail "$nonclean invocation(s) did not run 'clean'"; cat "$S1/invocations.txt"
fi
if cut -d'|' -f3- "$S1/invocations.txt" | grep -qE 'dependency:go-offline|dependency:resolve|dependency:tree|validate|(^| )-o( |$)|maven\.main\.skip|maven\.compiler\.skip'; then
    fail "a resolve-only goal or offline flag reached maven"; cat "$S1/invocations.txt"
else
    pass "no resolve-only goal and no offline flag reached maven"
fi

# Java 11 and 17 must go to JDK 17 (smallest installed JDK that can build
# them); Java 21 must go to JDK 21. A gate that sent everything to JDK 21
# would stop exercising the level 57 of the 58 real projects declare, and one
# that sent everything to JDK 17 is the `invalid target release: 21` failure.
if grep -q "^${JDK17}|.*legacy/pom.xml|" "$S1/invocations.txt"; then
    pass "Java 11 project built with JDK 17"
else
    fail "Java 11 project was not built with JDK 17"; cat "$S1/invocations.txt"
fi
if grep -q "^${JDK21}|.*modern/pom.xml|" "$S1/invocations.txt"; then
    pass "Java 21 project built with JDK 21"
else
    fail "Java 21 project was not built with JDK 21"; cat "$S1/invocations.txt"
fi
if grep -q "^${JDK17}|.*springish/pom.xml|" "$S1/invocations.txt"; then
    pass "java.version property is honoured (spring-boot-starter-parent shape)"
else
    fail "java.version property was not honoured"; cat "$S1/invocations.txt"
fi
if grep -q "^${JDK17}|.*plugincfg/pom.xml|" "$S1/invocations.txt"; then
    pass "maven-compiler-plugin <configuration><release> is honoured"
else
    fail "the maven-compiler-plugin configuration idiom was not honoured"; cat "$S1/invocations.txt"
fi

# A commented-out level must not select a JDK — an explanatory comment in a pom
# reddening the gate is its own defect.
S1B="$WORK/s1b"; mkdir -p "$S1B/tree"
make_stub_mvn "$S1B" ok
make_pom "$S1B/tree/commented" 17
python3 - "$S1B/tree/commented/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text().replace("<properties>",
    "<!-- was <maven.compiler.release>25</maven.compiler.release> before we downgraded -->\n  <properties>")
p.write_text(t)
PY
run_gate "$S1B/tree" "$S1B/log" "$S1B"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "a commented-out Java level is ignored"
else
    fail "a comment in a pom failed the gate"; sed -n '1,25p' "$S1B/log"
fi

# ---------------------------------------------------------------------------
echo "Scenario 2: one failing build fails the run, and the others still run"
# ---------------------------------------------------------------------------
S2="$WORK/s2"; mkdir -p "$S2/tree"
make_stub_mvn "$S2" fail
make_pom "$S2/tree/aaa" 17
make_pom "$S2/tree/bbb" 17

run_gate "$S2/tree" "$S2/log" "$S2"
rc=$?

if [ "$rc" -ne 0 ]; then pass "non-zero exit when a build fails"; else
    fail "a failing build did not fail the run"; sed -n '1,40p' "$S2/log"; fi
if [ "$(wc -l < "$S2/invocations.txt" | tr -d ' ')" = "2" ]; then
    pass "the second project still ran after the first failed"
else
    fail "the run stopped early; one failure hid the rest"
fi
# The summary must NAME the failures. Dropping the FAILURES bookkeeping while
# keeping the exit code produces "0 of 2 ... failed:" with nothing under it.
#
# Anchored on the summary's own `  - ` bullet prefix, NOT on the project name
# anywhere in the log. The first version of this assertion was a bare
# `grep -q aaa/pom.xml "$S2/log"`, which matched the per-project
# `::error file=...` line instead — so deleting the FAILURES bookkeeping left
# it green. It was mutation-testing this very suite that found it.
if grep -qE '^  - .*aaa/pom\.xml' "$S2/log" && grep -qE '^  - .*bbb/pom\.xml' "$S2/log"; then
    pass "the failure summary itself names every failed project"
else
    fail "the failure summary does not name the failed projects"; sed -n '1,40p' "$S2/log"
fi
if grep -qE '^::error::2 of 2 Java example project\(s\) failed' "$S2/log"; then
    pass "the failure count matches the number of failed projects"
else
    fail "the failure count is wrong or missing"; grep -n 'failed' "$S2/log" | head -5
fi

# ---------------------------------------------------------------------------
echo "Scenario 3: discovering zero projects is a failure, not a no-op pass"
# ---------------------------------------------------------------------------
S3="$WORK/s3"; mkdir -p "$S3/tree/empty"
make_stub_mvn "$S3" ok

run_gate "$S3/tree" "$S3/log" "$S3"
rc=$?

if [ "$rc" -ne 0 ]; then pass "non-zero exit when no project is discovered"; else
    fail "an empty tree reported success"; sed -n '1,40p' "$S3/log"; fi
if grep -q "No pom.xml found" "$S3/log"; then
    pass "the reason is stated in the log"
else
    fail "no diagnostic explaining the empty discovery"
fi

# ---------------------------------------------------------------------------
echo "Scenario 4: a missing tree fails rather than passing vacuously"
# ---------------------------------------------------------------------------
S4="$WORK/s4"; mkdir -p "$S4"
make_stub_mvn "$S4" ok

run_gate "$S4/does-not-exist" "$S4/log" "$S4"
rc=$?

if [ "$rc" -ne 0 ]; then pass "non-zero exit when the tree is missing"; else
    fail "a missing tree reported success"; sed -n '1,40p' "$S4/log"; fi
if grep -q "Examples directory not found" "$S4/log"; then
    pass "the reason is stated in the log"
else
    fail "no diagnostic explaining the missing tree"; sed -n '1,25p' "$S4/log"
fi

# ---------------------------------------------------------------------------
echo "Scenario 5: an unbuildable Java level fails and is NOT silently built"
# ---------------------------------------------------------------------------
# This is the property that separates this gate from the failure it replaces.
# examples/llm-providers/azure-openai/hello-world/java fails on JDK 17 with
# `invalid target release: 21`; the wrong repair is to build everything with
# whatever JDK is default. Here the level (25) has no installed JDK, so the
# run must fail AND maven must never be invoked for that project. Each fixture
# carries a second, buildable pom so `invocations.txt` exists — otherwise the
# "never invoked" assertion would pass against a missing file and would hold
# even if the gate exited on its first line.
S5="$WORK/s5"; mkdir -p "$S5/tree"
make_stub_mvn "$S5" ok
make_pom "$S5/tree/ok17" 17
make_pom "$S5/tree/future" 25

run_gate "$S5/tree" "$S5/log" "$S5"
rc=$?

if [ "$rc" -ne 0 ]; then pass "non-zero exit for a level with no installed JDK"; else
    fail "a project needing an absent JDK reported success"; sed -n '1,40p' "$S5/log"; fi
if [ ! -s "$S5/invocations.txt" ]; then
    fail "the control pom was never built, so 'never invoked' below proves nothing"
elif grep -q "future/pom.xml" "$S5/invocations.txt"; then
    fail "the project was built with a fallback JDK it never asked for"
else
    pass "maven was never invoked for the unbuildable project (control pom was)"
fi
if grep -q "requires Java 25" "$S5/log"; then
    pass "the error names the missing version"
else
    fail "the error does not name the missing version"
fi

# A project declaring no level at all is the same class: the gate cannot know
# which toolchain it wants, so it must refuse rather than guess.
S5B="$WORK/s5b"; mkdir -p "$S5B/tree"
make_stub_mvn "$S5B" ok
make_pom "$S5B/tree/ok17" 17
mkdir -p "$S5B/tree/nolevel/src/main/java/demo"
cat > "$S5B/tree/nolevel/pom.xml" <<'POM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>nolevel</artifactId><version>1</version>
</project>
POM
printf 'package demo;\npublic class Main {}\n' > "$S5B/tree/nolevel/src/main/java/demo/Main.java"

run_gate "$S5B/tree" "$S5B/log" "$S5B"
rc=$?

if [ "$rc" -ne 0 ]; then pass "non-zero exit for a pom declaring no Java level"; else
    fail "a pom with no declared Java level reported success"; sed -n '1,40p' "$S5B/log"; fi
if [ ! -s "$S5B/invocations.txt" ]; then
    fail "the control pom was never built, so 'never invoked' below proves nothing"
elif grep -q "nolevel/pom.xml" "$S5B/invocations.txt"; then
    fail "a pom with no declared level was built with a guessed JDK"
else
    pass "maven was never invoked for the pom with no declared level (control pom was)"
fi
# The DIAGNOSIS, not just the refusal: with the level-less branch deleted the
# pom is still refused, but by the JDK lookup, which tells the author to install
# a JDK for a version the pom never named. Refusal for the wrong stated reason
# sends them after the wrong thing.
if grep -q "declares no Java level" "$S5B/log"; then
    pass "the level-less pom is refused for the stated reason"
else
    fail "the level-less pom was refused, but not as a missing declaration"; sed -n '1,25p' "$S5B/log"
fi

# ---------------------------------------------------------------------------
echo "Scenario 6: the discovered-vs-attempted guard fires (mutation test)"
# ---------------------------------------------------------------------------
# The guard is only worth having if it is independent of the loop that would
# lose an entry, so it is exercised against a deliberately mutated copy that
# reports one more discovered project than it dispatches. Every build in this
# scenario succeeds — the mutant must still fail.
S6="$WORK/s6"; mkdir -p "$S6/tree"
make_stub_mvn "$S6" ok
make_pom "$S6/tree/a" 17
make_pom "$S6/tree/b" 17

MUTANT="$S6/mutant.sh"
sed 's/^discovered="\${#POMS\[@\]}"$/discovered=$(( ${#POMS[@]} + 1 ))/' "$GATE" > "$MUTANT"
if ! grep -q 'discovered=$(( ${#POMS\[@\]} + 1 ))' "$MUTANT"; then
    fail "mutation did not apply — the guard was never exercised, so scenario 6 proves nothing"
else
    run_gate "$S6/tree" "$S6/log" "$S6" "17 21" "$MUTANT"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "the mutant fails even though every build passed"
    else
        fail "a lost dispatch entry reported success"; sed -n '1,40p' "$S6/log"
    fi
    if grep -q "attempted" "$S6/log"; then
        pass "the divergence is named in the log"
    else
        fail "the mutant failed for some other reason than the count guard"
    fi
fi

# The unmutated gate must pass on the same fixtures, or scenario 6 would be
# proving nothing more than "this script always fails".
run_gate "$S6/tree" "$S6/log-control" "$S6"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "the unmutated gate passes on the same fixtures (control)"
else
    fail "control run failed, so the mutation result is not attributable"; sed -n '1,40p' "$S6/log-control"
fi

# ---------------------------------------------------------------------------
echo "Scenario 7: the real examples/ tree, through the script's OWN default root"
# ---------------------------------------------------------------------------
# Runs the real gate over the real tree with a stub Maven, and deliberately
# does NOT set EXAMPLES_DIR — the workflow does not set it either, so the
# default is production configuration. An earlier version of this scenario
# passed `EXAMPLES_DIR=examples` explicitly, which meant mutating the default
# to a subdirectory left the suite green while CI would have compiled six
# projects and reported "All 6 ... compiled."
#
# This compiles nothing. It asserts that discovery finds every pom that is
# actually there, that each declares a level the gate can map to a JDK, and
# that none declares a custom output directory that would silence the
# post-build checks.
S7="$WORK/s7"; mkdir -p "$S7"
make_stub_mvn "$S7" ok

expected_poms="$(find "$REPO_ROOT/examples" -name pom.xml -type f | wc -l | tr -d ' ')"
copied_poms="$(find "$REAL_ROOT/examples" -name pom.xml -type f | wc -l | tr -d ' ')"
if [ "$copied_poms" != "$expected_poms" ]; then
    fail "the tree copy is incomplete ($copied_poms of $expected_poms poms); scenarios 7 and 10 would prove nothing"
fi

( cd "$REAL_ROOT" && \
  POM_INTROSPECT="$REPO_ROOT/.github/scripts/pom_introspect.py" \
  JAVA_HOME_17_X64="$JDK17" JAVA_HOME_21_X64="$JDK21" JAVA_HOME="" \
  MVN_BIN="$S7/mvn" SUPPORTED_JDKS="17 21" \
  bash "$GATE" ) > "$S7/log" 2>&1
rc=$?

if [ "$rc" -eq 0 ]; then
    pass "the real tree resolves end to end through the default discovery root"
else
    fail "the real tree does not resolve"; sed -n '1,60p' "$S7/log"
fi

actual_invocations="$(wc -l < "$S7/invocations.txt" 2>/dev/null | tr -d ' ')"
if [ "${actual_invocations:-0}" = "$expected_poms" ]; then
    pass "every one of the $expected_poms real poms was dispatched"
else
    fail "found $expected_poms poms under examples/ but dispatched ${actual_invocations:-0}"
fi

# The JDK-21 outlier must still be routed to JDK 21 in the real tree — the
# whole reason this gate selects per project rather than pinning one JDK.
if grep -q "^${JDK21}|" "$S7/invocations.txt" 2>/dev/null; then
    pass "the real tree still contains a project routed to JDK 21"
else
    fail "no real project routed to JDK 21; the per-project selection is untested against the tree it guards"
fi

# ---------------------------------------------------------------------------
echo "Scenario 8: maven exiting 0 is not accepted as evidence of a build"
# ---------------------------------------------------------------------------
# `mvn compile` on a pom with no source root is BUILD SUCCESS. That is green
# over zero work, and it is directly reachable — #3185 moves a source file
# between package directories, and a move landing outside src/main/java leaves
# exactly this state.
S8="$WORK/s8"; mkdir -p "$S8/tree"
make_stub_mvn "$S8" ok no-emit
make_pom "$S8/tree/nosources" 17

run_gate "$S8/tree" "$S8/log" "$S8"
rc=$?

if [ "$rc" -ne 0 ]; then
    pass "a build that emits no class files fails"
else
    fail "a project that compiled nothing reported success"; sed -n '1,40p' "$S8/log"
fi
if [ "$(wc -l < "$S8/invocations.txt" | tr -d ' ')" = "1" ]; then
    pass "maven really was invoked (so the failure is the class-output check)"
else
    fail "maven was not invoked; the failure is not attributable to the class-output check"
fi
if grep -q "emitted no class files" "$S8/log"; then
    pass "the reason is stated in the log"
else
    fail "no diagnostic explaining the missing class output"
fi

# Class files left by an EARLIER build must not satisfy the check. `target/` is
# gitignored so CI always starts clean, but a developer running this twice would
# otherwise have the second run pass on the first run's output even though this
# build compiled nothing — the check would be measuring history, not this build.
S8E="$WORK/s8e"; mkdir -p "$S8E/tree"
make_stub_mvn "$S8E" ok no-emit
make_pom "$S8E/tree/stale" 17
mkdir -p "$S8E/tree/stale/target/classes/demo"
: > "$S8E/tree/stale/target/classes/demo/Main.class"
# Make certain the artefact predates the run on any filesystem granularity.
touch -t 202001010000 "$S8E/tree/stale/target/classes/demo/Main.class"

run_gate "$S8E/tree" "$S8E/log" "$S8E"
rc=$?
if [ "$rc" -ne 0 ] && grep -q "emitted no class files" "$S8E/log"; then
    pass "a stale class file from an earlier build does not satisfy the check"
else
    fail "a previous build's output was accepted as this build's"; sed -n '1,30p' "$S8E/log"
fi

# Control: the same fixture with a stub that DOES emit passes, so the assertion
# above is about freshness and not about the fixture being unbuildable.
S8F="$WORK/s8f"; mkdir -p "$S8F/tree"
make_stub_mvn "$S8F" ok
make_pom "$S8F/tree/stale" 17
mkdir -p "$S8F/tree/stale/target/classes/demo"
: > "$S8F/tree/stale/target/classes/demo/Main.class"
touch -t 202001010000 "$S8F/tree/stale/target/classes/demo/Main.class"
run_gate "$S8F/tree" "$S8F/log" "$S8F"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "the same fixture passes when the build does emit (control)"
else
    fail "the freshness control failed, so the assertion above is not attributable"; sed -n '1,30p' "$S8F/log"
fi

# A <mainClass> naming a package the class does not declare is #3158's adjacent
# defect: it compiles, and `mvn exec:java` still cannot run it.
S8B="$WORK/s8b"; mkdir -p "$S8B/tree"
make_stub_mvn "$S8B" ok
make_pom "$S8B/tree/badmain" 17
python3 - "$S8B/tree/badmain/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text().replace("</project>", """  <build><plugins><plugin>
    <artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>com.wrong.package.Main</mainClass></configuration>
  </plugin></plugins></build>
</project>""")
p.write_text(t)
PY

run_gate "$S8B/tree" "$S8B/log" "$S8B"
rc=$?

if [ "$rc" -ne 0 ]; then
    pass "a <mainClass> with no matching class file fails"
else
    fail "a pom whose mainClass names a nonexistent class reported success"; sed -n '1,40p' "$S8B/log"
fi
if grep -q "com.wrong.package.Main" "$S8B/log"; then
    pass "the error names the unresolvable mainClass"
else
    fail "the error does not name the unresolvable mainClass"; sed -n '1,30p' "$S8B/log"
fi

# A custom <outputDirectory> sends the two post-build assertions to the wrong
# path, which would turn both of them into silent no-ops — the class-output and
# mainClass checks would look at an empty `target/classes` that Maven never
# wrote to. The gate refuses such a pom rather than quietly stopping checking.
S8D="$WORK/s8d"; mkdir -p "$S8D/tree"
make_stub_mvn "$S8D" ok
make_pom "$S8D/tree/customout" 17
python3 - "$S8D/tree/customout/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace(
    "</project>", "  <build><outputDirectory>build/classes</outputDirectory></build>\n</project>"))
PY

run_gate "$S8D/tree" "$S8D/log" "$S8D"
rc=$?
if [ "$rc" -ne 0 ]; then
    pass "a pom with a custom <outputDirectory> is refused"
else
    fail "a custom <outputDirectory> silently disabled the post-build checks"; sed -n '1,40p' "$S8D/log"
fi
if grep -q "outputDirectory" "$S8D/log"; then
    pass "the error names the unsupported element"
else
    fail "the error does not name <outputDirectory>"; sed -n '1,30p' "$S8D/log"
fi

# The same fixture with a CORRECT mainClass must pass, or scenario 8b would be
# proving only that the extra pom is rejected for some other reason.
S8C="$WORK/s8c"; mkdir -p "$S8C/tree"
make_stub_mvn "$S8C" ok
make_pom "$S8C/tree/goodmain" 17
python3 - "$S8C/tree/goodmain/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text().replace("</project>", """  <build><plugins><plugin>
    <artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>demo.Main</mainClass></configuration>
  </plugin></plugins></build>
</project>""")
p.write_text(t)
PY

run_gate "$S8C/tree" "$S8C/log" "$S8C"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "a correct mainClass passes (control for the check above)"
else
    fail "the mainClass check rejects a correct declaration"; sed -n '1,40p' "$S8C/log"
fi

# ---------------------------------------------------------------------------
echo "Scenario 9: JAVA_HOME is trusted only when its own version matches"
# ---------------------------------------------------------------------------
# The script may fall back to the shell's JAVA_HOME, but only when that JDK's
# feature version is the one being asked for. Relaxing that to an unconditional
# fallback is precisely "built against a toolchain it did not ask for, reported
# green", and until this scenario existed nothing exercised the branch at all.
S9="$WORK/s9"; mkdir -p "$S9/tree"
make_stub_mvn "$S9" ok
make_pom "$S9/tree/needs17" 17

# JDK 21 offered as JAVA_HOME while the project needs 17, and every
# JAVA_HOME_17_* explicitly blanked so a runner-provided JDK 17 cannot satisfy
# the request instead. Blanking is belt-and-braces on top of the global unset
# above: this is the one scenario whose whole point is that no JDK 17 exists.
JAVA_HOME="$JDK21" \
JAVA_HOME_17_X64="" JAVA_HOME_17_ARM64="" JAVA_HOME_17_X86="" JAVA_HOME_17_ARM="" \
EXAMPLES_DIR="$S9/tree" MVN_BIN="$S9/mvn" SUPPORTED_JDKS="17" \
bash "$GATE" > "$S9/log" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    pass "a JAVA_HOME of the wrong version is refused"
else
    fail "a JDK 21 JAVA_HOME was accepted for a Java 17 request"; sed -n '1,30p' "$S9/log"
fi
if [ -s "$S9/invocations.txt" ]; then
    fail "maven was invoked with a JAVA_HOME whose version does not match"
else
    pass "maven was never invoked with the mismatched JAVA_HOME"
fi

# Control: the SAME JAVA_HOME is accepted when the versions do agree, so the
# assertion above is about the version check and not about the fallback being
# dead in general.
S9B="$WORK/s9b"; mkdir -p "$S9B/tree"
make_stub_mvn "$S9B" ok
make_pom "$S9B/tree/needs21" 21
JAVA_HOME="$JDK21" \
JAVA_HOME_21_X64="" JAVA_HOME_21_ARM64="" JAVA_HOME_21_X86="" JAVA_HOME_21_ARM="" \
EXAMPLES_DIR="$S9B/tree" MVN_BIN="$S9B/mvn" SUPPORTED_JDKS="21" \
bash "$GATE" > "$S9B/log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q "^${JDK21}|" "$S9B/invocations.txt" 2>/dev/null; then
    pass "a matching JAVA_HOME is accepted and used (control)"
else
    fail "the JAVA_HOME fallback is dead in both directions, so scenario 9 proves nothing"
    sed -n '1,30p' "$S9B/log"
fi

# ---------------------------------------------------------------------------
echo "Scenario 10: the failure properties hold against REAL example paths"
# ---------------------------------------------------------------------------
# Every other scenario drives the gate over synthetic fixtures, and scenario 7
# drives it over the real tree with a stub that ALWAYS succeeds. That left a
# hole a hostile review walked straight through: a `case "$pom" in
# */llm-providers/*|*/cost-controls/*) continue ;; esac` inserted into the
# dispatch loop turns the build-failure, class-output and mainClass properties
# off for the real examples — the shape a future "skip the one known-broken
# example" weakening would take — and the suite stayed green, because no
# scenario ever made a REAL path fail.
#
# These three drive one real project into each failure mode via the stub, and
# assert the gate reddens NAMING THAT PATH. A path-scoped skip fails them.
S10="$WORK/s10"; mkdir -p "$S10"
make_stub_mvn "$S10" ok

real_target_fail="examples/llm-providers/mistral/hello-world/java"
real_target_emit="examples/mcp-connectors/cloud-storage/java"
real_target_main="examples/cost-controls/enforcement/java"

run_real_gate() {  # $1=logfile, rest=env assignments
    local logfile="$1"; shift
    ( cd "$REAL_ROOT" && env "$@" \
        POM_INTROSPECT="$REPO_ROOT/.github/scripts/pom_introspect.py" \
        JAVA_HOME_17_X64="$JDK17" JAVA_HOME_21_X64="$JDK21" JAVA_HOME="" \
        MVN_BIN="$S10/mvn" SUPPORTED_JDKS="17 21" \
        bash "$GATE" ) > "$logfile" 2>&1
}

run_real_gate "$S10/log-fail" "STUB_FAIL_FOR=$real_target_fail"
rc=$?
if [ "$rc" -ne 0 ] && grep -qE "^  - .*${real_target_fail}/pom\.xml" "$S10/log-fail"; then
    pass "a failing build on a REAL example path fails the run and is named"
else
    fail "a failing build on $real_target_fail did not fail the run"; sed -n '1,30p' "$S10/log-fail"
fi
# ...and it must be ATTRIBUTED to the build, not merely caught downstream.
#
# A path-scoped swallow of the build-failure branch is still caught today by
# the class-output backstop — a failed build emits nothing fresh — so the
# verdict assertion above passes either way and would not notice. That is
# defence in depth working, but the hole is real for a project where javac
# emits SOME classes before failing on another source: the backstop then sees
# fresh output and lets it through. Pinning the branch, not just the outcome.
if grep -qE "::error file=${real_target_fail}/pom\.xml::mvn .* failed" "$S10/log-fail"; then
    pass "the failure is attributed to the build itself, not to a downstream backstop"
else
    fail "a failing build was reported as something else; the build-failure branch may be bypassed"
    grep -E "::error file=${real_target_fail}" "$S10/log-fail" | head -3
fi

run_real_gate "$S10/log-emit" "STUB_NO_EMIT_FOR=$real_target_emit"
rc=$?
if [ "$rc" -ne 0 ] && grep -qE "^  - .*${real_target_emit}/pom\.xml" "$S10/log-emit"; then
    pass "a REAL example emitting no classes fails the run and is named"
else
    fail "$real_target_emit emitting nothing did not fail the run"; sed -n '1,30p' "$S10/log-emit"
fi

run_real_gate "$S10/log-main" "STUB_WRONG_CLASS_FOR=$real_target_main"
rc=$?
if [ "$rc" -ne 0 ] && grep -qE "^  - .*${real_target_main}/pom\.xml" "$S10/log-main"; then
    pass "a REAL example whose <mainClass> is not produced fails the run and is named"
else
    fail "$real_target_main missing its mainClass did not fail the run"; sed -n '1,30p' "$S10/log-main"
fi

# Control: with no override, the same invocation over the same real tree passes.
# Without this, the three assertions above would hold even for a gate that
# always fails.
run_real_gate "$S10/log-control"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "the same real-tree invocation passes with no override (control)"
else
    fail "the real-tree control failed, so scenario 10 is not attributable"; sed -n '1,40p' "$S10/log-control"
fi

# ---------------------------------------------------------------------------
echo "Scenario 11: pom shapes that a pattern-matcher gets wrong"
# ---------------------------------------------------------------------------
# Every one of these was demonstrated against the grep/sed version of the
# parser and is the reason .github/scripts/pom_introspect.py exists.
S11="$WORK/s11"; mkdir -p "$S11/tree"
make_stub_mvn "$S11" ok

# (a) <mainClass> across lines, naming a class that does not exist. The
#     line-oriented extractor found nothing here and passed — a fail-OPEN on
#     the property it was added to close.
make_pom "$S11/tree/multiline_main" 17
python3 - "$S11/tree/multiline_main/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("</project>", """  <build><plugins><plugin>
    <artifactId>exec-maven-plugin</artifactId>
    <configuration>
      <mainClass>
        com.totally.Wrong
      </mainClass>
    </configuration>
  </plugin></plugins></build>
</project>"""))
PY
run_gate "$S11/tree/multiline_main" "$S11/log-a" "$S11"
rc=$?
if [ "$rc" -ne 0 ] && grep -q "com.totally.Wrong" "$S11/log-a"; then
    pass "a <mainClass> written across lines is still checked"
else
    fail "a multi-line <mainClass> was not checked"; sed -n '1,25p' "$S11/log-a"
fi

# (b) A MULTI-LINE comment holding an old level must not select a JDK. The sed
#     that split on comment delimiters only dropped lines BEGINNING with `<!--`.
mkdir -p "$S11/tree2"
make_pom "$S11/tree2/multiline_comment" 17
python3 - "$S11/tree2/multiline_comment/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("<properties>", """<!--
  Historical note: this used to build on
  <maven.compiler.release>25</maven.compiler.release>
  before we downgraded it.
-->
  <properties>"""))
PY
run_gate "$S11/tree2" "$S11/log-b" "$S11"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "a level inside a multi-line comment is ignored"
else
    fail "a multi-line comment selected the JDK"; sed -n '1,25p' "$S11/log-b"
fi

# (c) A <release> belonging to another plugin must not choose the JDK. An
#     unscoped search let maven-javadoc-plugin hard-fail a Java 17 project.
mkdir -p "$S11/tree3/otherplugin/src/main/java/demo"
printf 'package demo;\npublic class Main {}\n' > "$S11/tree3/otherplugin/src/main/java/demo/Main.java"
cat > "$S11/tree3/otherplugin/pom.xml" <<'POM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>otherplugin</artifactId><version>1</version>
  <!-- maven-javadoc-plugin FIRST, deliberately: with the compiler plugin first,
       an UNSCOPED search still reads the compiler config first and the fixture
       cannot distinguish scoped from unscoped. Mutation-tested. -->
  <build><plugins>
    <plugin><artifactId>maven-javadoc-plugin</artifactId>
      <configuration><release>25</release></configuration></plugin>
    <plugin><artifactId>maven-compiler-plugin</artifactId>
      <configuration><target>17</target><source>17</source></configuration></plugin>
  </plugins></build>
</project>
POM
run_gate "$S11/tree3" "$S11/log-c" "$S11"
rc=$?
if [ "$rc" -eq 0 ] && grep -q "^${JDK17}|.*otherplugin/pom.xml|" "$S11/invocations.txt"; then
    pass "another plugin's <release> does not choose the JDK"
else
    fail "maven-javadoc-plugin's <release> selected the JDK"; sed -n '1,25p' "$S11/log-c"
fi

# (d) A plugin's own <outputDirectory> (maven-dependency-plugin's
#     copy-dependencies is the common case) is NOT <build><outputDirectory>
#     and must not be refused.
mkdir -p "$S11/tree4"
make_pom "$S11/tree4/plugin_outdir" 17
python3 - "$S11/tree4/plugin_outdir/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("</project>", """  <build><plugins><plugin>
    <artifactId>maven-dependency-plugin</artifactId>
    <configuration><outputDirectory>${project.build.directory}/lib</outputDirectory></configuration>
  </plugin></plugins></build>
</project>"""))
PY
run_gate "$S11/tree4" "$S11/log-d" "$S11"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "a plugin's own <outputDirectory> is not mistaken for the build's"
else
    fail "a plugin <outputDirectory> was refused"; sed -n '1,25p' "$S11/log-d"
fi

# (e) ...but <build><outputDirectory> IS refused, or the two post-build
#     assertions would silently look at an empty directory. Control for (d).
mkdir -p "$S11/tree5"
make_pom "$S11/tree5/build_outdir" 17
python3 - "$S11/tree5/build_outdir/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace(
    "</project>", "  <build><outputDirectory>build/classes</outputDirectory></build>\n</project>"))
PY
run_gate "$S11/tree5" "$S11/log-e" "$S11"
rc=$?
if [ "$rc" -ne 0 ] && grep -q "outputDirectory" "$S11/log-e"; then
    pass "<build><outputDirectory> is still refused (control for the above)"
else
    fail "<build><outputDirectory> was accepted"; sed -n '1,25p' "$S11/log-e"
fi

# (f) A ${...} placeholder is DISCLOSED, not silently skipped and not failed.
#     Refusing would red a valid pom whose property comes from a parent; saying
#     nothing would let the reader believe the entry point was verified.
mkdir -p "$S11/tree6"
make_pom "$S11/tree6/placeholder" 17
python3 - "$S11/tree6/placeholder/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("</project>", """  <build><plugins><plugin>
    <artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>${inherited.main.class}</mainClass></configuration>
  </plugin></plugins></build>
</project>"""))
PY
run_gate "$S11/tree6" "$S11/log-f" "$S11"
rc=$?
if [ "$rc" -eq 0 ] && grep -q "NOT verified" "$S11/log-f"; then
    pass "an unresolvable \${...} mainClass is disclosed, not failed and not silent"
else
    fail "an unresolvable placeholder was mishandled"; sed -n '1,25p' "$S11/log-f"
fi

# (g) ...but a placeholder the pom CAN resolve is resolved and checked.
mkdir -p "$S11/tree7"
make_pom "$S11/tree7/resolvable" 17
python3 - "$S11/tree7/resolvable/pom.xml" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
t = p.read_text()
t = t.replace("</properties>", "<main.class>com.totally.Wrong</main.class></properties>")
t = t.replace("</project>", """  <build><plugins><plugin>
    <artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>${main.class}</mainClass></configuration>
  </plugin></plugins></build>
</project>""")
p.write_text(t)
PY
run_gate "$S11/tree7" "$S11/log-g" "$S11"
rc=$?
if [ "$rc" -ne 0 ] && grep -q "com.totally.Wrong" "$S11/log-g"; then
    pass "a resolvable \${...} mainClass is resolved and checked"
else
    fail "a resolvable placeholder was not resolved"; sed -n '1,25p' "$S11/log-g"
fi

# (g2) `1.8` is a level spelling Maven accepts; it must normalise to 8 and
#      route to the smallest JDK that can build it.
mkdir -p "$S11/tree9"
make_pom "$S11/tree9/legacy_spelling" "1.8" maven.compiler.source
run_gate "$S11/tree9" "$S11/log-g2" "$S11"
rc=$?
if [ "$rc" -eq 0 ] && grep -q "(Java 8 " "$S11/log-g2"; then
    pass "a 1.8-style level normalises to 8 and builds"
else
    fail "the 1.8 spelling was not normalised"; sed -n '1,25p' "$S11/log-g2"
fi

# (g3) Maven's precedence: `release` beats `target` beats `source`. A pom
#      declaring release=17 and source=21 is a Java 17 project. Nothing
#      exercised the ORDER until this fixture — every other pom declares one
#      level, so inverting the precedence list changed no outcome.
mkdir -p "$S11/tree10/precedence/src/main/java/demo"
printf 'package demo;\npublic class Main {}\n' > "$S11/tree10/precedence/src/main/java/demo/Main.java"
cat > "$S11/tree10/precedence/pom.xml" <<'POM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId><artifactId>precedence</artifactId><version>1</version>
  <properties>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.release>17</maven.compiler.release>
  </properties>
</project>
POM
run_gate "$S11/tree10" "$S11/log-g3" "$S11"
rc=$?
if [ "$rc" -eq 0 ] && grep -q "^${JDK17}|.*precedence/pom.xml|" "$S11/invocations.txt"; then
    pass "maven.compiler.release outranks maven.compiler.source"
else
    fail "the level precedence order is wrong"; sed -n '1,25p' "$S11/log-g3"
fi

# (h) A pom that is not well-formed XML is a hard failure naming the reason,
#     never a silently level-less one.
mkdir -p "$S11/tree8/broken"
printf '<project><modelVersion>4.0.0</modelVersion>\n' > "$S11/tree8/broken/pom.xml"
run_gate "$S11/tree8" "$S11/log-h" "$S11"
rc=$?
if [ "$rc" -ne 0 ] && grep -q "could not be parsed as XML" "$S11/log-h"; then
    pass "an unparseable pom fails, naming the parse error"
else
    fail "an unparseable pom was not reported as such"; sed -n '1,25p' "$S11/log-h"
fi

# ---------------------------------------------------------------------------
echo
if [ "$failures" -eq 0 ]; then
    echo "java_examples_compile_gate_test: PASS"
    exit 0
fi
echo "java_examples_compile_gate_test: FAIL ($failures assertion(s))"
exit 1
