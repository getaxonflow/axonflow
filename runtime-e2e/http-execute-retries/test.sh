#!/usr/bin/env bash
set -euo pipefail

EXPECTED_ASSERTIONS=7
ASSERTIONS_RUN=0

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <agent-binary> <output-directory>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
agent="$1"
output="$2"

python3 "$SCRIPT_DIR/verify.py" --agent "$agent" --output "$output"

while IFS= read -r passed; do
  [ "$passed" = "true" ] || {
    echo "FAIL: results.json contains a failed retry case" >&2
    exit 1
  }
  ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
done < <(python3 - "$output/results.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    for result in json.load(handle):
        print("true" if result.get("passed") is True else "false")
PY
)

if [ "$ASSERTIONS_RUN" -ne "$EXPECTED_ASSERTIONS" ]; then
  echo "FAIL: expected $EXPECTED_ASSERTIONS retry assertions, ran $ASSERTIONS_RUN" >&2
  exit 1
fi

echo "PASS: $ASSERTIONS_RUN retry runtime assertions"
