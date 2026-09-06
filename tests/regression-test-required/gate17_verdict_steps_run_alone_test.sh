#!/usr/bin/env bash
# Regression guard: every workflow step that runs an ADR-065 gate 17 SHAPE test
# declares AXONFLOW_GATE17_ALONE=1, and no other place does.
#
# THE BUG CLASS. A shape budget is a ratio of two wall-clock terms measured at
# different moments in one process. It cancels the machine only while the
# process has the machine to itself: under `go test ./...` package parallelism
# on the 4-vCPU runner the graph closure ratio read 47.7 where the same binary,
# run alone by name minutes earlier in the same job, read 12.1 (job
# 101403668523, #3769). So TestGate17ShapeBudgetsHold and
# TestGate17GraphShapeBudgetsHold are verdicts only where AXONFLOW_GATE17_ALONE
# is "1" and SKIP otherwise, saying so. That makes the switch the whole gate:
# a named step that loses it runs the test, gets a skip, and - because the step
# requires the `--- PASS:` line - fails loudly; but a step someone rewrites to
# accept a skip, or a workflow that runs the shape test in a package arm WITH
# the switch set, would turn the verdict into noise in either direction. This
# guard pins both: the switch is set on exactly the steps that run a shape
# test by name, and on no `./...` arm.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

report=$(python3 - <<'PY'
import yaml, io, glob, re, sys

SWITCH = "AXONFLOW_GATE17_ALONE"
SHAPE = re.compile(r"TestGate17(Graph)?ShapeBudgetsHold")
PACKAGE_ARM = re.compile(r"go test[^\n]*\./\.\.\.")

def env_of(job, step):
    env = {}
    for src in (job.get("env") or {}, step.get("env") or {}):
        if isinstance(src, dict):
            env.update({str(k): str(v) for k, v in src.items()})
    return env

shape_steps, offenders = [], []
for f in sorted(glob.glob(".github/workflows/*.yml")):
    d = yaml.safe_load(io.open(f, encoding="utf-8")) or {}
    for jname, job in (d.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            run = step.get("run") or ""
            if not isinstance(run, str):
                continue
            env = env_of(job, step)
            where = f"{f.split('/')[-1]}:{jname}:{step.get('name') or '<unnamed>'}"
            if SHAPE.search(run):
                shape_steps.append(where)
                if env.get(SWITCH) != "1":
                    offenders.append(f"{where}: runs a shape test by name without {SWITCH}=1 (it would skip, and the PASS check would red it - or worse, a rewritten check would accept the skip)")
                if PACKAGE_ARM.search(run):
                    offenders.append(f"{where}: runs a shape test in the same step as a `./...` arm; the shape test must run alone, by name")
            elif env.get(SWITCH) == "1" and PACKAGE_ARM.search(run):
                offenders.append(f"{where}: sets {SWITCH}=1 on a `./...` package arm, which is exactly the contended run the switch exists to exclude")
print(len(shape_steps))
print("\n".join(shape_steps))
print("--")
print("\n".join(offenders))
PY
)
count=$(printf '%s\n' "$report" | head -1)
steps=$(printf '%s\n' "$report" | sed -n '2,/^--$/p' | sed '$d')
offenders=$(printf '%s\n' "$report" | sed '1,/^--$/d' | sed '/^$/d')

# Anti-vacuity: the tree has five named steps that run a shape test (test.yml
# x2, test-community.yml x1, gate17-latency-budgets.yml x2). Fewer means the
# matcher stopped seeing them, not that the gate shrank quietly.
if [ "${count:-0}" -lt 5 ]; then
  echo "FAIL: only ${count:-0} step(s) run a gate 17 shape test by name; expected at least 5 - the census is not looking at the tree, or a named step was removed"
  printf '%s\n' "$steps" | sed 's/^/  /'
  exit 1
fi
echo "ok: ${count} step(s) run a gate 17 shape test by name:"
printf '%s\n' "$steps" | sed 's/^/  /'

if [ -n "$offenders" ]; then
  echo "FAIL: the alone switch and the shape tests disagree:"
  printf '%s\n' "$offenders" | sed 's/^/  /'
  exit 1
fi
echo "ok: every shape-test step sets ${SWITCH:-AXONFLOW_GATE17_ALONE}=1 and no package arm does"

# Self-test both directions on fixtures, so the matcher cannot rot silently.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"
cat > "$tmp/.github/workflows/missing.yml" <<'Y'
on: [pull_request]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: shape without the switch
        run: go test ./pdp/ -run '^TestGate17ShapeBudgetsHold$'
Y
cat > "$tmp/.github/workflows/contended.yml" <<'Y'
on: [pull_request]
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      AXONFLOW_GATE17_ALONE: "1"
    steps:
      - name: package arm with the switch
        run: go test ./... -count=1
Y
cat > "$tmp/.github/workflows/good.yml" <<'Y'
on: [pull_request]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: shape alone
        env:
          AXONFLOW_GATE17_ALONE: "1"
        run: go test -tags enterprise ./shared/identity/ -run '^TestGate17GraphShapeBudgetsHold$'
Y
verdict=$(cd "$tmp" && python3 -c "
import yaml,io,glob,re
SHAPE=re.compile(r'TestGate17(Graph)?ShapeBudgetsHold'); ARM=re.compile(r'go test[^\n]*\./\.\.\.')
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d=yaml.safe_load(io.open(f))
    for jn,job in d['jobs'].items():
        for st in job['steps']:
            env={**(job.get('env') or {}),**(st.get('env') or {})}; run=st.get('run') or ''
            alone=str(env.get('AXONFLOW_GATE17_ALONE'))=='1'
            if SHAPE.search(run) and not alone: print('BAD', f.split('/')[-1])
            if ARM.search(run) and alone: print('BAD', f.split('/')[-1])
            if SHAPE.search(run) and alone and not ARM.search(run): print('GOOD', f.split('/')[-1])
")
case "$verdict" in *"BAD missing.yml"*) echo "ok: fixture running a shape test without the switch IS detected" ;; *) echo "FAIL: the matcher missed the switch-less shape fixture"; exit 1 ;; esac
case "$verdict" in *"BAD contended.yml"*) echo "ok: fixture setting the switch on a ./... arm IS detected" ;; *) echo "FAIL: the matcher missed the contended-arm fixture"; exit 1 ;; esac
case "$verdict" in *"GOOD good.yml"*) echo "ok: a named shape step with the switch is accepted" ;; *) echo "FAIL: the matcher rejected the well-formed fixture"; exit 1 ;; esac
case "$verdict" in *"BAD good.yml"*) echo "FAIL: the well-formed fixture was flagged"; exit 1 ;; esac
echo "PASS: gate 17 shape verdicts run only where the binary is alone"
