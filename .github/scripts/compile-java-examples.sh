#!/usr/bin/env bash
# Compiles every Java example project under examples/.
#
# WHY THIS EXISTS (#3158 / #3185)
# -------------------------------
# `examples/` rsyncs to the public community mirror, so an example that does
# not compile is a shipped artifact that fails on a reader's first `mvn
# compile`. Three of them had been in that state across four SDK majors and
# nothing noticed, because nothing in CI compiled them:
#
#     grep -rn "mvn|setup-java" .github/workflows/    ->  no hits, pre-#3155
#
# #3155 then added a Maven warm-up to `security.yml`, but that step runs
# `dependency:go-offline`. RESOLVING IS NOT COMPILING. A project whose sources
# reference symbols the SDK deleted resolves perfectly and still cannot be
# built. That distinction is the entire reason #3158 stayed invisible.
#
# This script asserts the property directly: every discovered project compiles,
# and the compiler actually produced something.
#
# WHY IT CANNOT REPORT SUCCESS WITHOUT DOING THE WORK
# ---------------------------------------------------
# Ten fail-closed properties, each pinned by a behavioural assertion in
# tests/regression-test-required/java_examples_compile_gate_test.sh — and each
# of the ten mutation-tested, i.e. the property was deliberately removed and
# the suite confirmed to go red. A property nobody tried to break is a property
# nobody has shown is guarded.
#
#   1. Zero projects discovered fails the run. "Nothing to build" is never a
#      pass — that is how a moved directory or a bad glob turns into a green
#      check over no work at all.
#   2. A project whose build exits non-zero fails the run, and the run keeps
#      going so one breakage does not hide the rest.
#   3. Discovered count and attempted count are compared at the end. If they
#      diverge the run fails even when every attempted build passed. This is
#      the #3098 defect class — a dispatch loop losing entries while printing
#      a green summary — and the guard is independent of the loop that would
#      be doing the losing.
#   4. A project declaring a Java level with no matching JDK on this runner
#      fails the run. It is NOT quietly built with whichever JDK happens to be
#      default: that would report success for a build the declared toolchain
#      was never asked to perform, and `invalid target release: 21` is exactly
#      the failure this repo already has one live instance of.
#   5. `$MAVEN_GOALS` is asserted to contain `compile` by the self-test, against
#      the recorded argv of every invocation. Without that, this script could be
#      quietly reverted to the `dependency:go-offline` behaviour the header
#      above spends sixteen lines condemning and its own guard would stay
#      green. Resolving is not compiling, and a test that cannot tell the two
#      apart is not testing the thing this file exists for.
#   6. A build that emits NO class files fails, even when maven exits 0.
#      `mvn compile` on a pom whose source root is empty or missing is
#      BUILD SUCCESS — green over zero work, the same defect class as (1) one
#      level down. This is directly reachable: #3185 itself moves a source
#      file between package directories, and a move that lands outside the
#      source root leaves exactly that state.
#   7. A declared `<mainClass>` that produced no matching class file fails.
#      #3158's adjacent defect was `examples/cost-controls/enforcement/java`
#      declaring `com.getaxonflow.examples.enforcement.EnforcementExample`
#      against a class in `com.axonflow.examples`, so `mvn exec:java` could
#      not work. Compilation alone never notices that; the class-output check
#      does.
#   8. Both post-build checks demand output NEWER than a per-project stamp, and
#      `clean` runs first, so a PREVIOUS build's artefacts can never stand in
#      for this one's. `target/` is gitignored, so CI is clean either way; this
#      is what makes the checks honest on a developer machine.
#   9. A pom that is not well-formed XML is a hard failure naming the parse
#      error, never a silently level-less one — those two send an author after
#      completely different things.
#  10. A `<build><outputDirectory>` is refused rather than silently sending
#      checks 6-8 to a directory Maven never wrote to. A PLUGIN's own
#      `<outputDirectory>` (maven-dependency-plugin's copy-dependencies is the
#      common case) is a different parameter and is correctly ignored.
#
# JDK SELECTION — AND WHAT IT DOES AND DOES NOT PROVE
# ---------------------------------------------------
# 57 of the 58 example projects declare Java 11 or 17; `examples/llm-providers/
# azure-openai/hello-world/java` declares 21 and is the sole outlier (it uses
# text blocks). Rather than pin one JDK — which either fails that project or
# stops exercising the declared level of the other 57 — the required level is
# read from each pom and the smallest JDK that can build it is selected. The
# workflow installs every JDK named in `SUPPORTED_JDKS`; a level with no
# installed JDK is property 4 above.
#
# Be precise about what that buys. Today every pom declares its level through
# `maven.compiler.source`/`target` (or `java.version`), and NONE uses
# `maven.compiler.release`. `-source 11 -target 11` on JDK 17 compiles against
# the JDK 17 class library, so a project declaring 11 can still call a Java 16
# API and build clean here. What this selection guarantees is that no project
# is asked of a JDK that cannot emit its declared target — which is the
# `invalid target release: 21` failure, and the reason a single-JDK job is
# wrong. It does NOT guarantee the declared level's API surface. Closing that
# means moving the poms to `maven.compiler.release`; tracked in #3197.
#
# Levels are read in Maven's own precedence order:
#     maven.compiler.release > maven.compiler.target > maven.compiler.source
# with `java.version` last, because spring-boot-starter-parent derives
# `maven.compiler.release` from it (examples/integrations/spring-boot). Both
# the property form and `maven-compiler-plugin/<configuration>` are read — the
# latter scoped to that plugin, because an unscoped search finds `<release>` on
# maven-javadoc-plugin. All of this is done by pom_introspect.py against a
# parsed tree, so comments, multi-line values and namespaces are handled by the
# parser rather than by patterns that each have to be guessed correctly.
#
# A project declaring NO level at all is a hard failure, not a default. The
# script cannot know which toolchain such a project expects, and guessing is
# how a check starts passing for the wrong reason.
#
# ENV OVERRIDES (used by the regression test to drive synthetic fixtures)
#   EXAMPLES_DIR   directory to scan            (default: examples)
#   MVN_BIN        maven executable             (default: mvn)
#   MAVEN_GOALS    goals to invoke              (default: "clean compile")
#   SUPPORTED_JDKS space-separated feature versions to accept (default: 17 21)

set -uo pipefail

EXAMPLES_DIR="${EXAMPLES_DIR:-examples}"
MVN_BIN="${MVN_BIN:-mvn}"
# `clean` is not decoration. Maven's incremental compilation means a project
# whose target/ is already up to date emits NOTHING on a second `compile`, so
# the "did this build actually produce classes" assertion below false-fails on
# every local re-run — and without `clean` the only way to stop it false-failing
# is to weaken it to mere existence, which a PREVIOUS build satisfies. Starting
# from an empty target/ makes existence and freshness the same question, so the
# check can be strict without being flaky. CI checks out clean either way; this
# is what makes the gate usable locally, and what makes the freshness assertion
# honest rather than approximate.
MAVEN_GOALS="${MAVEN_GOALS:-clean compile}"
read -ra MAVEN_GOAL_ARGV <<< "$MAVEN_GOALS"
SUPPORTED_JDKS="${SUPPORTED_JDKS:-17 21}"

if [ ! -d "$EXAMPLES_DIR" ]; then
    echo "::error::Examples directory not found: $EXAMPLES_DIR"
    echo "Refusing to report success for a tree this job cannot see."
    exit 2
fi

# ---------------------------------------------------------------------------
# Resolve one JAVA_HOME per supported feature version, up front.
#
# actions/setup-java exports JAVA_HOME_<version>_<ARCH> for every installed
# version. Resolving these BEFORE any build means a missing JDK is reported as
# a setup error naming the version, rather than surfacing later as a confusing
# `invalid target release` from javac.
# ---------------------------------------------------------------------------
declare -A JDK_HOME=()
for v in $SUPPORTED_JDKS; do
    home=""
    for arch in X64 ARM64 X86 ARM; do
        var="JAVA_HOME_${v}_${arch}"
        candidate="${!var:-}"
        if [ -n "$candidate" ] && [ -x "$candidate/bin/javac" ]; then
            home="$candidate"
            break
        fi
    done
    # Local-developer fallback: the JDK the shell already points at, but ONLY
    # when its own feature version matches. Never a blind fallback — that would
    # build a project against a toolchain it did not ask for and call it green.
    if [ -z "$home" ] && [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/javac" ]; then
        default_v="$("${JAVA_HOME}/bin/javac" -version 2>&1 | sed -E 's/^javac ([0-9]+).*/\1/')"
        if [ "$default_v" = "$v" ]; then
            home="$JAVA_HOME"
        fi
    fi
    if [ -n "$home" ]; then
        JDK_HOME["$v"]="$home"
        echo "JDK $v -> $home"
    else
        echo "JDK $v -> (not installed)"
    fi
done
echo

# ---------------------------------------------------------------------------
# Discovery.
# ---------------------------------------------------------------------------
mapfile -t POMS < <(find "$EXAMPLES_DIR" -name pom.xml -type f -print | sort)
discovered="${#POMS[@]}"

if [ "$discovered" -eq 0 ]; then
    echo "::error::No pom.xml found under $EXAMPLES_DIR/."
    echo "Either the Java examples moved or the discovery glob is wrong. A compile"
    echo "gate that discovers nothing has verified nothing, so this is a failure,"
    echo "not a no-op."
    exit 1
fi

echo "Discovered $discovered Java example project(s) under $EXAMPLES_DIR/"
echo "Goals: $MAVEN_GOALS"
echo

# ── Pom introspection ────────────────────────────────────────────────────
#
# Delegated to .github/scripts/pom_introspect.py, which uses a real XML parser.
# The grep/sed version this replaces was defeated four separate ways by
# ordinary pom formatting — a multi-line <mainClass> silently skipped the
# check, a multi-line comment hard-failed the run, and an unscoped <release>
# let maven-javadoc-plugin choose the JDK. See that file's header. A parser has
# none of those failure modes and the questions become tree queries.
# Overridable only so the self-test can point a mutated COPY of this script,
# living in a scratch directory, at the real introspector. Not a production
# lever; the default is the sibling file.
POM_INTROSPECT="${POM_INTROSPECT:-$(dirname "${BASH_SOURCE[0]}")/pom_introspect.py}"
if [ ! -f "$POM_INTROSPECT" ]; then
    echo "::error::pom_introspect.py not found next to this script ($POM_INTROSPECT)."
    echo "Refusing to fall back to pattern-matching a pom — that is the defect class it replaced."
    exit 2
fi

# Smallest installed JDK that can build the requested level. Echoes the JDK
# feature version, or nothing when no installed JDK can.
jdk_for_level() {
    local level="$1" v
    for v in $(printf '%s\n' $SUPPORTED_JDKS | sort -n); do
        if [ -n "${JDK_HOME[$v]:-}" ] && [ "$level" -le "$v" ]; then
            echo "$v"
            return 0
        fi
    done
    return 1
}

attempted=0
failed=0
declare -a FAILURES=()
build_log="$(mktemp)"

for pom in "${POMS[@]}"; do
    project_dir="$(dirname "$pom")"

    # One parser invocation answers all three questions. A pom the parser
    # cannot read is a hard failure: the alternative is treating it as
    # level-less, which reads as a different defect and sends the author after
    # the wrong thing.
    facts=""
    if ! facts="$(python3 "$POM_INTROSPECT" "$pom" 2>&1)"; then
        echo "::error file=${pom#./}::could not be parsed as XML: ${facts}"
        FAILURES+=("$pom (unparseable pom)")
        failed=1
        attempted=$((attempted + 1))
        continue
    fi

    # A <build><outputDirectory> would send the post-build assertions below to
    # the wrong place and quietly turn them into no-ops. No example pom sets
    # one today (scenario 7 of the self-test proves it over the real tree), so
    # refuse rather than silently stop checking. A PLUGIN's own
    # <outputDirectory> — maven-dependency-plugin's copy-dependencies, say —
    # is a different parameter and the parser does not report it.
    if build_output_dir="$(printf '%s\n' "$facts" | sed -n 's/^build_output_dir=//p')" \
       && [ -n "$build_output_dir" ]; then
        echo "::error file=${pom#./}::sets <build><outputDirectory>$build_output_dir</outputDirectory>. This gate asserts class output under target/classes; teach it this pom's output directory rather than letting the post-build checks silently pass."
        FAILURES+=("$pom (custom <build><outputDirectory>, unsupported)")
        failed=1
        attempted=$((attempted + 1))
        continue
    fi

    level="$(printf '%s\n' "$facts" | sed -n 's/^level=//p')"
    if [ -z "$level" ]; then
        echo "::error file=${pom#./}::declares no Java level. Add maven.compiler.release (or target/source, or java.version, or a maven-compiler-plugin <configuration>) so this gate knows which JDK to build it with."
        FAILURES+=("$pom (no declared Java level)")
        failed=1
        attempted=$((attempted + 1))
        continue
    fi

    jdk=""
    if ! jdk="$(jdk_for_level "$level")"; then
        echo "::error file=${pom#./}::requires Java $level ($(printf '%s\n' "$facts" | sed -n 's/^level_source=//p')) and no installed JDK can build it (installed: ${SUPPORTED_JDKS}). Add $level to the workflow's java-version list and to SUPPORTED_JDKS."
        FAILURES+=("$pom (needs Java $level, no matching JDK)")
        failed=1
        attempted=$((attempted + 1))
        continue
    fi

    attempted=$((attempted + 1))
    printf 'Building %-72s (Java %-2s via JDK %s) ... ' "${pom#./}" "$level" "$jdk"
    start="$SECONDS"

    # Freshness stamp. The class-output assertion below would otherwise be
    # satisfied by a PREVIOUS build's artefacts: `target/` is gitignored so CI
    # always starts clean, but a developer running this twice would have the
    # second run pass on the first run's output even if nothing compiled.
    stamp="$(mktemp)"

    # Exit status is read directly from the command, never from a captured
    # substitution — `out=$(cmd)` moves the status into a subshell and every
    # downstream check then passes unconditionally.
    if ! JAVA_HOME="${JDK_HOME[$jdk]}" "$MVN_BIN" -B -ntp -q -f "$pom" "${MAVEN_GOAL_ARGV[@]}" >"$build_log" 2>&1; then
        echo "FAILED ($((SECONDS - start))s)"
        echo "::error file=${pom#./}::mvn $MAVEN_GOALS failed. examples/ ships to the public community mirror, so this is a broken artifact a reader would hit on first build."
        # Both ends of the log: the compiler's own [ERROR] lines wherever they
        # are, plus the tail, so a long reactor preamble cannot push the actual
        # cause out of a fixed head window.
        grep -E '^\[ERROR\]|error:|symbol:' "$build_log" | head -40
        echo "  --- last 30 lines ---"
        tail -30 "$build_log"
        FAILURES+=("$pom (build failed)")
        failed=1
        continue
    fi

    # ── Post-build assertions: maven exiting 0 is not evidence of a build ──
    #
    # `mvn compile` on a pom with no source root is BUILD SUCCESS. Assert the
    # compiler actually emitted something THIS RUN, and that anything the pom
    # names as an entry point is among what it emitted.
    classes_dir="$project_dir/target/classes"
    if [ -z "$(find "$classes_dir" -name '*.class' -newer "$stamp" -print -quit 2>/dev/null)" ]; then
        echo "FAILED ($((SECONDS - start))s)"
        echo "::error file=${pom#./}::mvn $MAVEN_GOALS succeeded but emitted no class files in this run. A project with no compilation units builds clean and verifies nothing — check that its sources are under src/main/java."
        FAILURES+=("$pom (no class files emitted)")
        failed=1
        continue
    fi

    missing_main=""
    while IFS= read -r main_class; do
        [ -n "$main_class" ] || continue
        # `-newer "$stamp"` and not merely `-f`: a class file left by an
        # EARLIER build satisfies existence even when this build emitted
        # nothing at that path, which is the same stale-artefact hole the
        # class-output check above closes.
        main_class_file="$classes_dir/${main_class//.//}.class"
        if [ ! -f "$main_class_file" ] || [ ! "$main_class_file" -nt "$stamp" ]; then
            missing_main="$main_class"
            break
        fi
    done < <(printf '%s\n' "$facts" | sed -n 's/^main_class=//p')

    if [ -n "$missing_main" ]; then
        echo "FAILED ($((SECONDS - start))s)"
        echo "::error file=${pom#./}::declares <mainClass>$missing_main</mainClass> but compilation produced no such class, so 'mvn exec:java' cannot run this example. This is #3158's adjacent defect: a <mainClass> naming a package the class does not declare."
        FAILURES+=("$pom (mainClass $missing_main not produced)")
        failed=1
        continue
    fi

    # An entry point behind an unresolvable ${...} is DISCLOSED, not silently
    # skipped and not failed: the placeholder may come from a parent pom or a
    # profile this gate does not evaluate, so refusing would red a valid pom,
    # and saying nothing would let the reader believe it was checked.
    while IFS= read -r unresolved; do
        [ -n "$unresolved" ] || continue
        echo
        echo "  NOTE: ${pom#./} declares <mainClass>$unresolved</mainClass>; the placeholder could not"
        echo "        be resolved from this pom's own <properties>, so the entry point was NOT verified."
    done < <(printf '%s\n' "$facts" | sed -n 's/^main_class_unresolved=//p')

    echo "ok ($((SECONDS - start))s)"
done

echo
echo "----------------------------------------------------------------------"

# Property 3: independent of the loop above.
if [ "$attempted" -ne "$discovered" ]; then
    echo "::error::Discovered $discovered project(s) but attempted $attempted."
    echo "The dispatch loop lost entries. Refusing to report a result for builds"
    echo "that never ran."
    exit 1
fi

if [ "$failed" -ne 0 ]; then
    echo "::error::${#FAILURES[@]} of $discovered Java example project(s) failed:"
    printf '  - %s\n' "${FAILURES[@]}"
    exit 1
fi

echo "All $discovered Java example project(s) compiled and emitted classes."
