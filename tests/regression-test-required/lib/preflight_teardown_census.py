#!/usr/bin/env python3
"""Census: fixed-project runtime-e2e suites and whether their executor
workflow clears a killed run's stack BEFORE running the suite.

Invoked by preflight_teardown_for_fixed_project_suites_test.sh against both
the real tree and its fixtures, so the matcher that checks the repo is the one
the controls prove. Two separately-anchored copies is how the host-ports guard
silently skipped 32 declarations while reporting a confident zero.

Usage:  preflight_teardown_census.py <root>
Prints: line 1  = "<fixed-project suites with a workflow executor> <unwired>"
        line 2+ = "<state>\t<suite>\t<project>\t<workflow>"
                  state is OK | MISSING | AFTER | NOTFOUND
"""
import csv
import glob
import io
import os
import re
import sys

import yaml


def registry(root):
    """suite -> executor workflow, for suites a workflow actually runs.

    Column 2 is the KIND and column 3 is the filename. Reading column 2 as the
    filename made every lookup miss and the census returned "not invoked" for
    all 40 suites - which is why line 1 prints a denominator.
    """
    out, unwired = {}, []
    p = os.path.join(root, 'scripts/e2e/runtime_e2e_suites.tsv')
    for row in csv.reader(io.open(p, encoding='utf-8'), delimiter='\t'):
        if not row or row[0].startswith('#') or len(row) < 3:
            continue
        if row[1].strip() == 'workflow':
            out[row[0].strip()] = row[2].strip()
        else:
            unwired.append(row[0].strip())
    return out, unwired


def fixed_project(path):
    """The compose project name, when it is FIXED for every run.

    A name carrying $$, $RANDOM, a run id or mktemp is unique per run, so a
    leftover volume from a previous run can never be re-attached: those suites
    leak, but they do not inherit, and this guard is about inheriting.
    """
    for line in io.open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*PROJECT=(?:"?\$\{PROJECT:-)?([A-Za-z0-9_.$-]*)', line)
        if m:
            if re.search(r'\$\$|RANDOM|GITHUB_RUN|mktemp', line):
                return None
            return m.group(1) or None
    return None


def state_of(wf_path, suite):
    """OK / MISSING / AFTER / NOTFOUND for one suite's executor workflow.

    ORDER IS THE INVARIANT, NOT PRESENCE. A teardown step that runs after the
    suite is the cleanup the suite already does for itself on a clean exit; it
    does nothing for the case this guard exists for, which is the PREVIOUS run
    having been killed. Hence AFTER is a distinct, reported state.
    """
    try:
        d = yaml.safe_load(io.open(wf_path, encoding='utf-8'))
    except Exception:
        return 'NOTFOUND'
    if not isinstance(d, dict):
        return 'NOTFOUND'
    needle = 'runtime-e2e/%s/test.sh' % suite
    for job in (d.get('jobs') or {}).values():
        if not isinstance(job, dict):
            continue
        run_i = td_i = None
        for i, step in enumerate(job.get('steps') or []):
            if not isinstance(step, dict):
                continue
            r = step.get('run', '') or ''
            if needle in r:
                if 'teardown' in r:
                    if td_i is None:
                        td_i = i
                elif run_i is None:
                    run_i = i
        if run_i is None:
            continue
        if td_i is None:
            return 'MISSING'
        return 'OK' if td_i < run_i else 'AFTER'
    return 'NOTFOUND'


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    reg, unwired = registry(root)
    rows, n = [], 0
    for sh in sorted(glob.glob(os.path.join(root, 'runtime-e2e/*/test.sh'))):
        suite = os.path.basename(os.path.dirname(sh))
        proj = fixed_project(sh)
        if not proj:
            continue
        wf = reg.get(suite)
        if not wf:
            continue  # unwired: never runs in CI, so it cannot eject a drain
        n += 1
        st = state_of(os.path.join(root, '.github/workflows', wf), suite)
        rows.append((st, suite, proj, wf))
    print('%d %d' % (n, len([u for u in unwired])))
    for st, suite, proj, wf in rows:
        if st != 'OK':
            print('%s\t%s\t%s\t%s' % (st, suite, proj, wf))


if __name__ == '__main__':
    main()
