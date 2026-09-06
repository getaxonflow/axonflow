#!/usr/bin/env bash
# Regression guard: every file under .github/workflows/ must be valid YAML.
#
# This is the bug fix/perf-benchmark-yaml-parse closed:
# scheduled-performance-benchmark.yml had a `gh pr create --body "..."`
# multi-line double-quoted string whose blank line sat at column 1.
# YAML's literal-block scalar (`run: |`) terminates on any non-empty line
# below the block's indent, so the parser saw the bash string's blank
# line as the end of `run:` and tried to read the next bash line as a
# new YAML key — failing with "could not find expected ':'".
#
# Symptom: every push of that workflow showed up in the Actions UI with
# `name = .github/workflows/scheduled-performance-benchmark.yml` (the
# path) instead of "Scheduled Performance Benchmark" (the declared
# `name:`), every run failed before any job started, and
# `gh workflow run …/dispatches` returned HTTP 422 with
# `Workflow does not have 'workflow_dispatch' trigger` — because the
# workflow registration had no parsed `on:` block.
#
# Catching this requires nothing more than running the YAML parser
# against every workflow file. CI runners on GitHub Actions don't do
# this for us — broken workflows just silently fail.

set -euo pipefail

WORKFLOW_DIR=".github/workflows"

if [ ! -d "$WORKFLOW_DIR" ]; then
    echo "ℹ️  $WORKFLOW_DIR not present; nothing to validate."
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ python3 required for YAML parse check"
    exit 1
fi

FAILED=()
while IFS= read -r -d '' f; do
    if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
        FAILED+=("$f")
    fi
done < <(find "$WORKFLOW_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "❌ The following workflow files do not parse as YAML:"
    for f in "${FAILED[@]}"; do
        echo "   - $f"
        # Re-run, surface only the scanner error and its location lines.
        python3 -c "
import yaml, sys
try:
    yaml.safe_load(open('$f'))
except yaml.YAMLError as e:
    print(e, file=sys.stderr)
    sys.exit(1)
" 2>&1 | sed 's/^/       /'
    done
    echo ""
    echo "   Effect: GitHub Actions cannot register the workflow. Every"
    echo "   push run shows up as a failure with no jobs, and"
    echo "   workflow_dispatch returns HTTP 422 because no triggers parse."
    echo "   Pattern: a multi-line bash double-quoted string inside run: |"
    echo "   whose continuation lines sit at column 1 will end the block."
    exit 1
fi

echo "✅ All ${WORKFLOW_DIR}/*.yml files parse as YAML."

# ---------------------------------------------------------------------------
# LAYER 2: the bash INSIDE a run: block must parse too.
#
# The check above proves the YAML parses. It says nothing about the shell
# script the YAML carries, and the two fail in opposite directions: a broken
# bash string can break the YAML (the bug above), and perfectly valid YAML can
# carry bash that dies at runtime.
#
# THE FAILURE THIS CLOSES, from #3688. A step gained
#
#     echo "    negative control: the enterprise edition half was stripped
#
# with no closing quote. The YAML was valid, so every check in this file
# passed. Bash swallowed everything after it until the next quote — which
# landed inside `${m#"$STAGED"/}` several lines down — and died on the `(` of
# `(community build)` with `syntax error near unexpected token`.
#
# The cost was not the red tick. That step's job is to `go vet` every mirrored
# Go module in the community build, and the vet sweep NEVER RAN. Worse, the
# line printed immediately before the death was
#
#     positive control: the gateway adapters reached the staged copy
#
# so the log's last word was reassurance, and the half that proves the
# community tree actually compiles was silently absent. A syntax error one line
# after a success message is indistinguishable, in a scrolled log, from a step
# that finished.
#
# `${{ }}` is substituted by Actions before bash ever sees it, so it is
# replaced with a placeholder here rather than being fed to bash as-is.
# Non-bash steps (shell: python, pwsh) are skipped by their declared shell,
# never by a guess at their content.
echo ""
echo "🔎 Checking bash syntax of every run: block …"
RUN_BLOCK_REPORT=$(python3 - "$WORKFLOW_DIR" <<'PY'
import glob, os, re, subprocess, sys, tempfile, yaml

workflow_dir = sys.argv[1]
checked = skipped = 0
failures = []
BASH = {"bash", "sh", None}

for wf in sorted(glob.glob(os.path.join(workflow_dir, "*.yml"))):
    try:
        doc = yaml.safe_load(open(wf))
    except Exception:
        continue  # layer 1 already failed this file
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        default_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell")
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            body = step.get("run")
            if not body:
                continue
            shell = step.get("shell", default_shell)
            if shell is not None and shell.split()[0] not in ("bash", "sh"):
                skipped += 1
                continue
            checked += 1
            script = re.sub(r"\$\{\{[^}]*\}\}", "GHA_EXPR", body)
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
                fh.write("#!/usr/bin/env bash\n" + script)
                path = fh.name
            proc = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            os.unlink(path)
            if proc.returncode != 0:
                err = proc.stderr.strip().splitlines()
                failures.append((os.path.basename(wf), step.get("name", "<unnamed>"),
                                 err[0] if err else "bash -n failed"))

for wf, name, err in failures:
    print(f"FAIL\t{wf}\t{name}\t{err}")
print(f"SUMMARY\t{checked}\t{skipped}\t{len(failures)}")
PY
) || { echo "❌ the run-block scanner itself failed"; exit 1; }

RUN_BLOCK_FAILURES=$(printf '%s\n' "$RUN_BLOCK_REPORT" | grep -c '^FAIL' || true)
RUN_BLOCK_SUMMARY=$(printf '%s\n' "$RUN_BLOCK_REPORT" | grep '^SUMMARY' | head -1)
RUN_BLOCK_CHECKED=$(printf '%s' "$RUN_BLOCK_SUMMARY" | cut -f2)
RUN_BLOCK_SKIPPED=$(printf '%s' "$RUN_BLOCK_SUMMARY" | cut -f3)

# ANTI-VACUITY: a scanner that checked nothing would report zero failures and
# pass. The tree has over a thousand run: blocks; a collapse to a handful means
# the parser stopped finding them, not that the workflows got simpler.
if [ "${RUN_BLOCK_CHECKED:-0}" -lt 500 ]; then
    echo "❌ the run-block scanner examined only ${RUN_BLOCK_CHECKED:-0} blocks."
    echo "   The tree has >1000. Zero failures over a handful of blocks is a"
    echo "   broken scanner reporting success, not a clean tree."
    exit 1
fi

if [ "$RUN_BLOCK_FAILURES" -ne 0 ]; then
    echo "❌ ${RUN_BLOCK_FAILURES} run: block(s) are not valid bash:"
    printf '%s\n' "$RUN_BLOCK_REPORT" | grep '^FAIL' | while IFS=$'\t' read -r _ wf name err; do
        echo "   ${wf} — step: ${name}"
        echo "       ${err}"
    done
    echo ""
    echo "   These parse as YAML and fail at RUNTIME, mid-step. Anything the"
    echo "   step printed before the error still appears in the log, so a"
    echo "   success message can be the last thing a reader sees while the"
    echo "   work after it never ran."
    exit 1
fi

echo "✅ ${RUN_BLOCK_CHECKED} run: block(s) parse as bash (${RUN_BLOCK_SKIPPED} non-bash skipped)."
