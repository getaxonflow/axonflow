#!/usr/bin/env bash
# Keep the current Go/Java/Rust example install pins in step with /health's
# single recommendation map. The repository-gates workflow runs this suite.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="$ROOT/tests/regression-test-required/release_example_sdk_pins.py"
test -f "$CHECKER"
PYTHONDONTWRITEBYTECODE=1 python3 "$CHECKER"

# Both Go module forms must be rejected when stale. Most examples use the
# single-line form, which an earlier checker silently skipped.
PYTHONDONTWRITEBYTECODE=1 python3 - "$CHECKER" <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("pins", sys.argv[1])
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
for form in (
    "require github.com/getaxonflow/axonflow-sdk-go/v9 v9.2.0",
    "require (\n\tgithub.com/getaxonflow/axonflow-sdk-go/v9 v9.2.0\n)",
):
    with TemporaryDirectory() as directory:
        path = Path(directory) / "go.mod"
        path.write_text(f"module example.test\n\n{form}\n")
        error = checker.check_example(path, checker.recommended_versions())
        if not error or "v9.2.0" not in error:
            raise SystemExit(f"stale Go SDK pin escaped the guard: {form}")
print("PASS: stale Go SDK pins rejected in single-line and block require forms")
PY
