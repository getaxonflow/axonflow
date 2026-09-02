#!/usr/bin/env bash
# The two defensive parameter loops in update-stack.yml must name the SAME set.
#
# WHY THIS RATCHET EXISTS. update-stack.yml carries two copies of the same
# defensive loop - one in the change-set PREVIEW job and one in the DEPLOY job.
# The loop's own comment explains that it is mandatory for NEW parameters,
# because the main loop only iterates the parameters the live stack already
# carries, and a parameter the stack has never had is not among them.
#
# When #3564 added five DecisionShadow* parameters, they were added to the
# preview loop and not the deploy loop. The failure is silent and it points the
# wrong way: an operator dispatches `decision_shadow_mode: shadow`, the change
# set PREVIEWS `shadow`, params.json omits the key, CloudFormation applies the
# template default `off`, and the workflow reports success. The fleet runs with
# the observation window closed while every signal says it is open.
#
# Comparing the two loops is the whole check. It cannot say whether a NEW
# parameter was added to either - that is the twin's job, and the CFN template
# test's - but it makes "added to one" impossible.
set -uo pipefail

WORKFLOW="${1:-.github/workflows/update-stack.yml}"

if [ ! -f "$WORKFLOW" ]; then
  echo "FAIL: $WORKFLOW not found"
  exit 1
fi

# Every defensive loop is a `for PARAM in <literal names>; do` line. Selected by
# SHAPE rather than by line number, which drifts - and narrowed to a LITERAL
# list, because the file also contains `for PARAM in "${!SVC_MAP[@]}"; do`, a
# loop over a service map that has nothing to do with stack parameters. Matching
# it too would compare a set of parameter names against a shell expansion and
# fail permanently for a reason that is not this test's subject.
mapfile -t LOOPS < <(grep -nE 'for PARAM in [A-Za-z][A-Za-z0-9 ]*; do' "$WORKFLOW")

if [ "${#LOOPS[@]}" -lt 2 ]; then
  echo "FAIL: expected at least 2 'for PARAM in ...' loops in $WORKFLOW, found ${#LOOPS[@]}"
  echo "      If a loop was deliberately removed, this test must be updated deliberately too:"
  echo "      a single remaining loop means one of the two jobs no longer forces new parameters."
  printf '  %s\n' "${LOOPS[@]}"
  exit 1
fi

echo "=== found ${#LOOPS[@]} defensive parameter loop(s) ==="

normalize() {
  # Everything between "for PARAM in " and "; do", whitespace-split and sorted,
  # so a reordering is not a failure and a membership change is.
  sed -E 's/^.*for PARAM in (.*); do.*$/\1/' <<<"$1" | tr ' ' '\n' | sed '/^$/d' | sort
}

FIRST_LINE="${LOOPS[0]}"
FIRST_NO="${FIRST_LINE%%:*}"
FIRST_SET="$(normalize "$FIRST_LINE")"
FIRST_COUNT="$(wc -l <<<"$FIRST_SET" | tr -d ' ')"

# ANTI-VACUITY: a loop that somehow parsed to nothing would make every
# comparison below trivially equal.
if [ "$FIRST_COUNT" -lt 5 ]; then
  echo "FAIL: the loop at line $FIRST_NO parsed to only $FIRST_COUNT parameter(s);"
  echo "      this test would then be comparing empty sets and passing."
  exit 1
fi
echo "  line $FIRST_NO: $FIRST_COUNT parameter(s) (reference)"

STATUS=0
for ((i = 1; i < ${#LOOPS[@]}; i++)); do
  LINE="${LOOPS[$i]}"
  NO="${LINE%%:*}"
  SET="$(normalize "$LINE")"
  COUNT="$(wc -l <<<"$SET" | tr -d ' ')"
  echo "  line $NO: $COUNT parameter(s)"
  if [ "$SET" != "$FIRST_SET" ]; then
    echo "FAIL: the defensive parameter loops at lines $FIRST_NO and $NO name DIFFERENT sets."
    echo "      Only in line $FIRST_NO:"
    comm -23 <(printf '%s\n' "$FIRST_SET") <(printf '%s\n' "$SET") | sed 's/^/        /'
    echo "      Only in line $NO:"
    comm -13 <(printf '%s\n' "$FIRST_SET") <(printf '%s\n' "$SET") | sed 's/^/        /'
    echo
    echo "      A parameter in the PREVIEW loop and not the DEPLOY loop previews a value"
    echo "      CloudFormation then does not apply, and the run reports success."
    STATUS=1
  fi
done

if [ "$STATUS" -ne 0 ]; then
  exit 1
fi

echo "PASS: all ${#LOOPS[@]} defensive parameter loops name the same $FIRST_COUNT parameter(s)"
