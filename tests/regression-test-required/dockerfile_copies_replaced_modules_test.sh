#!/usr/bin/env bash
# Every Dockerfile that resolves a module's build list must copy the manifests
# of every module that module REPLACES by a filesystem path.
#
# WHY THIS RATCHET EXISTS. #3564 added
# `replace axonflow/platform/decision => ./decision` to platform/go.mod. A
# filesystem replace is resolved by READING that path, so `go mod download`
# fails outright when the replaced module's go.mod is not in the build context:
#
#   go: axonflow/platform/decision@v0.0.0-... (replaced by ./decision):
#       reading decision/go.mod: no such file or directory
#
# Five Dockerfiles copy platform/go.mod for a dependency-cache layer and then
# run `go mod download`. All five broke at once, and NOTHING in the repo could
# see it: `go build`, `go vet` and every unit test operate on the source tree,
# which has the directory. The failure appears only when an image is built - so
# it surfaced as eleven runtime-e2e suites failing in under 80 seconds with a
# Docker error, one layer removed from the cause.
#
# The check is derived from the go.mod files rather than from a list of known
# replaces, so a NEW filesystem replace is covered on the commit that adds it -
# and, symmetrically, REMOVING a replace correctly stops requiring its COPY
# rather than failing. Verified both ways: deleting the COPY from
# platform/orchestrator/Dockerfile fails this check, and deleting the replace
# from platform/go.mod passes it with a smaller pair count.
#
# The anti-vacuity floors are on the two inputs and on the product: no
# filesystem replace anywhere, no Dockerfile resolving a build list, or no
# (Dockerfile, replace) pair actually compared - each is a state in which this
# script would report success while checking nothing, and each is a hard fail.
set -uo pipefail

REPO_ROOT="${1:-.}"
cd "$REPO_ROOT" || exit 1

STATUS=0
CHECKED=0

# normalize_path collapses "." and ".." lexically, WITHOUT touching the
# filesystem.
#
# Pure bash rather than `realpath -m`: that flag is GNU-only and BSD realpath on
# macOS rejects it, so a developer running this locally would get an empty
# TARGET and a silently vacuous check - the failure mode every other guard in
# this directory is written to avoid.
normalize_path() {
  local in="$1" part out=()
  IFS='/' read -r -a parts <<<"$in"
  for part in "${parts[@]}"; do
    case "$part" in
      ''|'.') continue ;;
      '..')
        if [ "${#out[@]}" -gt 0 ] && [ "${out[-1]}" != '..' ]; then
          unset 'out[-1]'
          out=("${out[@]}")
        else
          out+=('..')
        fi
        ;;
      *) out+=("$part") ;;
    esac
  done
  local joined
  joined="$(IFS='/'; echo "${out[*]}")"
  [ -n "$joined" ] || joined="."
  printf '%s' "$joined"
}

# Every module that some go.mod replaces by a filesystem path, as
# "<gomod-dir>|<replaced-module>|<relative-path>".
REPLACES=()
while IFS= read -r GOMOD; do
  DIR="$(dirname "$GOMOD")"
  # Both spellings: a single-line `replace X => ./y` and a line inside a
  # `replace (...)` block. Only FILESYSTEM replaces matter here - a replace to
  # another module VERSION is downloaded like any dependency.
  while IFS= read -r LINE; do
    [ -n "$LINE" ] || continue
    MOD="${LINE%%|*}"
    # ONLY A REPLACE FOR A MODULE THAT IS ALSO REQUIRED MATTERS.
    #
    # A replace directive for a module NOT in the build graph is INERT: the go
    # command never resolves it, so its path is never read and its manifest
    # need not be in the image. ee/go.mod carries exactly that case -
    # `replace axonflow/ee/platform/orchestrator/llm => ./platform/orchestrator/llm`
    # with no matching require - and demanding a COPY for it would fail a
    # Dockerfile that builds correctly today.
    if ! grep -qE "^[[:space:]]*${MOD//\//\\/} v" "$GOMOD"; then
      continue
    fi
    REPLACES+=("${DIR}|${LINE}")
  done < <(awk '
    /^replace [^(]/ && $4 ~ /^\.\.?\// { print $2 "|" $4 }
    /^[[:space:]]+[^ ]+ => \.\.?\// { print $1 "|" $3 }
  ' "$GOMOD")
done < <(find . -name go.mod -not -path '*/node_modules/*' -not -path './.git/*')

if [ "${#REPLACES[@]}" -eq 0 ]; then
  echo "FAIL: no filesystem replace found in any go.mod."
  echo "      This check would then pass vacuously. If the last one was removed"
  echo "      deliberately, delete this test in the same commit."
  exit 1
fi

echo "=== filesystem replaces found ==="
printf '  %s\n' "${REPLACES[@]}"
echo

# Every Dockerfile that copies a go.mod and then resolves a build list.
mapfile -t DOCKERFILES < <(grep -rl 'go mod download\|go mod tidy' --include='Dockerfile*' . 2>/dev/null | grep -v '/node_modules/')

if [ "${#DOCKERFILES[@]}" -eq 0 ]; then
  echo "FAIL: no Dockerfile runs 'go mod download'; this check would pass vacuously"
  exit 1
fi

echo "=== Dockerfiles that resolve a build list ==="
for DF in "${DOCKERFILES[@]}"; do
  # Which module roots does this Dockerfile copy a go.mod for?
  mapfile -t COPIED < <(grep -oE 'COPY [^ ]*/go\.mod' "$DF" | sed -E 's|COPY (.*)/go\.mod|\1|' | sort -u)
  if [ "${#COPIED[@]}" -eq 0 ]; then
    continue
  fi

  for ENTRY in "${REPLACES[@]}"; do
    GOMOD_DIR="${ENTRY%%|*}"
    REST="${ENTRY#*|}"
    REPLACED_PATH="${REST#*|}"
    # Strip the leading ./ from the go.mod's directory for comparison.
    OWNER="${GOMOD_DIR#./}"

    # Does this Dockerfile copy the OWNING module's manifest?
    OWNS=0
    for C in "${COPIED[@]}"; do
      [ "${C#./}" = "$OWNER" ] && OWNS=1
    done
    [ "$OWNS" -eq 1 ] || continue

    # It does. Then it must also copy the REPLACED module's manifest.
    #
    # NORMALIZED, because a replace path is relative to its own go.mod and may
    # climb: ee/go.mod replaces ../platform/decision, and the literal join
    # "ee/../platform/decision" appears in no COPY line. Resolved against the
    # repo root with realpath -m, which does not require the path to exist.
    TARGET="$(normalize_path "$OWNER/$REPLACED_PATH")"
    if [ -z "$TARGET" ] || [ "$TARGET" = "." ]; then
      # A replace that resolves to the repo root itself has no manifest of its
      # own to copy beyond the one already checked.
      continue
    fi
    CHECKED=$((CHECKED + 1))
    if grep -qE "COPY +${TARGET}/go\.mod" "$DF"; then
      echo "  OK   $DF copies ${TARGET}/go.mod (replaced by ${OWNER}/go.mod)"
    else
      echo "  FAIL $DF copies ${OWNER}/go.mod and runs 'go mod download', but does NOT copy"
      echo "       ${TARGET}/go.mod, which ${OWNER}/go.mod replaces by a filesystem path."
      echo "       'go mod download' READS that path and will fail:"
      echo "         go: <module> (replaced by ${REPLACED_PATH}): reading ...: no such file or directory"
      STATUS=1
    fi
  done
done

if [ "$CHECKED" -eq 0 ]; then
  echo "FAIL: no Dockerfile was matched against any filesystem replace."
  echo "      Either the path derivation above is wrong or the Dockerfiles stopped"
  echo "      copying a go.mod; both make this check silently vacuous."
  exit 1
fi

echo
if [ "$STATUS" -ne 0 ]; then
  exit 1
fi
echo "PASS: $CHECKED Dockerfile/replace pair(s) checked; every one copies the replaced module's manifest"
