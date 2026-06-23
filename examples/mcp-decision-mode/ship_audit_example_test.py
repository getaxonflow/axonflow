"""Runs the turnkey shipping demo end-to-end so CI proves it works (and covers
the script). The demo stands up an in-process HTTP receiver, so it needs no
external stack."""

from __future__ import annotations

import ship_audit_example


def test_ship_audit_example_runs_clean():
    # main() returns 0 only when BOTH scenarios pass: rows land locally AND
    # centrally and correlate (up), and stay durable locally when the sink is
    # down (fail-open). Any regression flips the exit code.
    assert ship_audit_example.main() == 0
