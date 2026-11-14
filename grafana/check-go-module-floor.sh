#!/bin/sh
# check-go-module-floor.sh MODULE MIN_VERSION FILE...
#
# Each FILE is the output of `go version -m <binary>`: the module graph that
# the Go linker embedded in that binary, which is also what Trivy reads when it
# scans the image. The check passes only when EVERY file records MODULE at
# MIN_VERSION or newer.
#
# It fails closed. A file that is missing, empty, or not `go version -m`
# output; a module absent from the graph; a module listed twice; a
# pseudo-version or pre-release (which cannot be ordered against a release
# floor); a filesystem replacement, which Go lists as `=> <path> (devel)` -
# each one FAILS, because
# none of those states proves the floor, and a check that cannot fail is not a
# check. Every file is examined even after the first failure so the report
# names each binary that is below the floor.
#
# Used by platform/monitoring/Dockerfile at build time on both the prometheus
# and the promtool binary, and exercised directly by
# tests/regression-test-required/go_module_floor_check_test.sh.
set -u

usage() {
  echo "usage: $0 MODULE MIN_VERSION FILE..." >&2
  exit 2
}

[ "$#" -ge 3 ] || usage
module=$1
min=$2
shift 2

# release_version prints "MAJOR MINOR PATCH" for a vX.Y.Z release version and
# nothing for anything else (pseudo-versions, pre-releases, +incompatible).
release_version() {
  printf '%s\n' "$1" | sed -n 's/^v\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)$/\1 \2 \3/p'
}

min_parts=$(release_version "$min")
if [ -z "$min_parts" ]; then
  echo "FAIL: MIN_VERSION $min is not a release version of the form vX.Y.Z" >&2
  exit 2
fi
read -r min_major min_minor min_patch <<PARTS
$min_parts
PARTS

status=0
checked=0

for file in "$@"; do
  if [ ! -s "$file" ]; then
    echo "FAIL: $file is missing or empty"
    status=1
    continue
  fi
  # `go version -m` begins with "<path>: go1.N..." - anything else is not a
  # module listing and must not be read as one.
  if ! head -n 1 "$file" | grep -Eq '^[^:]+: (devel |go)[0-9a-zA-Z.+-]*'; then
    echo "FAIL: $file does not look like 'go version -m' output (first line: $(head -n 1 "$file"))"
    status=1
    continue
  fi

  # The dep line for the module, followed on the next line by '=>' when the
  # module is replaced; a replacement decides the effective version. A
  # directory replacement is printed as `=> <path> (devel)` (and never with a
  # version), so "(devel)" or no version at all is the path-replacement shape.
  ver=$(awk -v mod="$module" '
    $1 == "dep" && $2 == mod { count++; ver = $3; pending = 1; next }
    pending && $1 == "=>" { ver = ($3 == "" || $3 == "(devel)" ? "REPLACED-BY-PATH" : $3); pending = 0; next }
    { pending = 0 }
    END {
      if (count == 0) { print "ABSENT"; exit }
      if (count > 1) { print "DUPLICATE"; exit }
      print ver
    }
  ' "$file")

  case "$ver" in
    ABSENT)
      echo "FAIL: $file: $module is not in the embedded module graph"
      status=1
      continue
      ;;
    DUPLICATE)
      echo "FAIL: $file: $module appears more than once in the embedded module graph"
      status=1
      continue
      ;;
    REPLACED-BY-PATH)
      echo "FAIL: $file: $module is replaced by a filesystem path; the floor cannot be proven"
      status=1
      continue
      ;;
  esac

  parts=$(release_version "$ver")
  if [ -z "$parts" ]; then
    echo "FAIL: $file: $module $ver is not a release version; the floor $min cannot be proven"
    status=1
    continue
  fi
  read -r major minor patch <<PARTS
$parts
PARTS
  below=0
  if [ "$major" -lt "$min_major" ]; then
    below=1
  elif [ "$major" -eq "$min_major" ]; then
    if [ "$minor" -lt "$min_minor" ]; then
      below=1
    elif [ "$minor" -eq "$min_minor" ] && [ "$patch" -lt "$min_patch" ]; then
      below=1
    fi
  fi
  if [ "$below" -eq 1 ]; then
    echo "FAIL: $file: $module $ver is below the floor $min"
    status=1
    continue
  fi
  echo "OK: $file: $module $ver >= $min"
  checked=$(( checked + 1 ))
done

if [ "$status" -ne 0 ]; then
  echo "FAIL: $module floor $min is not proven for every binary"
  exit 1
fi
if [ "$checked" -eq 0 ]; then
  echo "FAIL: no binary was checked"
  exit 1
fi
echo "PASS: $module >= $min in $checked binary module graph(s)"
