#!/usr/bin/env bash
# ee/examples/payment-exception-shadow/Dockerfile (the `case-workflows` release
# image) keeps krb5-libs at or above 1.22.3-r0: the pinned python:3.12-alpine3.23
# base ships 1.22.1-r0, which carries sixteen HIGH CVEs the release scan
# (HIGH,CRITICAL, exit-code 1, no ignore list) refuses (#4486). The pin is a
# versioned apk constraint plus an independent readback that prints the
# installed version and compares it to the floor with apk's own ordering, so a
# vulnerable library fails the build loudly and names what it saw, while a later
# rebuild of the fixed package passes. Mutations of a COPY must fail this
# contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DOCKERFILE="${CASE_WORKFLOWS_DOCKERFILE:-$ROOT/ee/examples/payment-exception-shadow/Dockerfile}"
FLOOR=1.22.3-r0

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

test -f "$DOCKERFILE" || fail "the case-workflows Dockerfile is missing"
# A byte-order mark is stripped by BuildKit and would reach every check below as
# a stray byte; refuse it first so the reason is honest. Line 1 is the pinned
# FROM: this file sets no parser directive, so a `# syntax=` that pointed at
# another frontend, or any directive at all, is a difference here.
test "$(head -c 3 "$DOCKERFILE" | od -An -tx1 | tr -d ' \n')" != "efbbbf" \
  || fail "the file starts with a byte-order mark, which BuildKit strips and the checks below do not"
test "$(head -n 1 "$DOCKERFILE")" = 'FROM python:3.12-alpine3.23@sha256:e0e17c55a255d32e515d3ae66577578f2a439ebe92cd4a8b69fc29421bbdba7d' \
  || fail "line 1 must be the digest-pinned FROM (no parser directive is used here), got: $(head -n 1 "$DOCKERFILE")"
# BuildKit parses INSTRUCTIONS, not lines: it accepts leading whitespace and
# lowercase keywords, joins a `\`+newline continuation by appending the next
# line verbatim (a token may be split across lines), and treats `\` followed by
# blanks as a continuation. Refuse those forms, then read ONE normalised text
# (comments dropped, continuations joined verbatim, spaces squeezed) everywhere.
if grep -nE '\\[[:space:]]+$' "$DOCKERFILE" >/dev/null; then
  fail "a continuation backslash is followed by blanks (BuildKit still continues the line)"
fi
joined="$(grep -Ev '^[[:space:]]*#' "$DOCKERFILE" | sed -e ':a' -e '/\\$/N; s/\\\n//; ta' | tr -s ' ')"
# A SHELL override would run every RUN through another interpreter (or none)
# while the text below still matched; the image has no reason to set one. Read
# raw (any case, any indent) AND joined (a keyword split across a continuation).
if grep -Eiq '^[[:space:]]*SHELL ' "$DOCKERFILE" || grep -Eiq '^[[:space:]]*SHELL( |$)' <<<"$joined"; then
  fail "a SHELL instruction would neuter the RUN chain; the image must not set one"
fi
while IFS= read -r instr; do
  [ -n "$instr" ] || continue
  grep -Eq '^(FROM|ARG|ENV|RUN|COPY|ADD|WORKDIR|USER|ENTRYPOINT|CMD|HEALTHCHECK|EXPOSE|VOLUME|LABEL)( |$)' <<<"$instr" \
    || fail "an instruction is not in canonical form (column-0 uppercase keyword), which the checks below cannot see: ${instr:0:120}"
done <<<"$joined"
# Two forms BuildKit honours that detach executed text from read text: an
# `# escape=` directive (a backslash becomes literal) and a heredoc whose
# delimiter is a keyword (`RUN <<CMD ... CMD`, body is shell). Neither is used.
if grep -Eiq '^#[[:space:]]*escape[[:space:]]*=' "$DOCKERFILE"; then
  fail "a '# escape=' parser directive would change which lines BuildKit continues; this file must not set one"
fi
if grep -Eq '^(RUN|COPY|ADD) .*<<' <<<"$joined"; then
  fail "a heredoc instruction would run text the keyword gate cannot classify; this Dockerfile uses none (BuildKit accepts spellings such as <<\\CMD, so << is refused outright)"
fi
grep -Eq '^FROM python:3\.12-alpine3\.23@sha256:[0-9a-f]{64}$' <<<"$joined" \
  || fail "the base image is not the digest-pinned python:3.12-alpine3.23"
# Exact line, not a substring: a trailing `|| true` or `;` would ride along.
# Every occurrence of the floor is derived from FLOOR, so a bump is one edit.
expected="RUN apk add --no-cache --upgrade 'krb5-libs>=${FLOOR}' && v=\"\$(apk list -I krb5-libs | sed -n 's/^krb5-libs-\\([^ ]*\\) .*/\\1/p')\" && c=\"\$(apk version -t \"\$v\" ${FLOOR} 2>/dev/null || true)\" && echo \"krb5-libs installed=\${v:-none} floor=${FLOOR} compare=\${c:-unparseable}\" && case \"\$c\" in '='|'>') true ;; *) false ;; esac"
run_line="$(grep -F "apk add --no-cache --upgrade 'krb5-libs" <<<"$joined" || true)"
test "$run_line" = "$expected" \
  || fail "krb5-libs is not upgraded to >=${FLOOR} with a printing, positively floor-comparing readback in one exact && chain, got: ${run_line}"
# The upgrade must run as root, before the switch to the unprivileged user.
upgrade_line="$(grep -n "apk add --no-cache --upgrade 'krb5-libs" <<<"$joined" | cut -d: -f1 | head -1)"
user_line="$(grep -n '^USER ' <<<"$joined" | cut -d: -f1 | head -1)"
test -n "$upgrade_line" && test -n "$user_line" && test "$upgrade_line" -lt "$user_line" \
  || fail "the krb5-libs upgrade must run as root, before USER"

# The whole normalised Dockerfile, pinned: this image is eleven instructions,
# so the durable guard is equality, and a path the shell spells or an extra
# instruction anywhere is a difference here. Re-pin deliberately with a change.
expected_canon="$(cat <<'GOLDEN'
FROM python:3.12-alpine3.23@sha256:e0e17c55a255d32e515d3ae66577578f2a439ebe92cd4a8b69fc29421bbdba7d
RUN apk add --no-cache --upgrade 'krb5-libs>=1.22.3-r0' && v="$(apk list -I krb5-libs | sed -n 's/^krb5-libs-\([^ ]*\) .*/\1/p')" && c="$(apk version -t "$v" 1.22.3-r0 2>/dev/null || true)" && echo "krb5-libs installed=${v:-none} floor=1.22.3-r0 compare=${c:-unparseable}" && case "$c" in '='|'>') true ;; *) false ;; esac
ARG AXONFLOW_VERSION=unreleased
LABEL org.opencontainers.image.version=$AXONFLOW_VERSION
ENV AXONFLOW_VERSION=$AXONFLOW_VERSION
WORKDIR /app
RUN pip install --no-cache-dir 'psycopg[binary]==3.2.10'
COPY *.py /app/
COPY fixtures /app/fixtures
COPY schemas /app/schemas
USER 65532:65532
EXPOSE 8765
ENTRYPOINT ["python3", "hosted_service.py", "--host", "127.0.0.1"]
GOLDEN
)"
test "$(printf '%s\n' "$joined" | grep -v '^$')" = "$expected_canon" \
  || fail "the normalised Dockerfile differs from its pin: $(diff <(printf '%s\n' "$expected_canon") <(printf '%s\n' "$joined" | grep -v '^$') | head -5 | tr '\n' '|')"

if [ -z "${CASE_WORKFLOWS_CONTRACT_NO_MUTATE:-}" ]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/case-workflows-contract.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  mutations=0
  expect_mutant_fails() {
    local name="$1" expected_reason="$2" mutant="$work/$1.Dockerfile" out
    cmp -s "$DOCKERFILE" "$mutant" && fail "mutation '$name' did not change the copy"
    if out="$(CASE_WORKFLOWS_CONTRACT_NO_MUTATE=1 CASE_WORKFLOWS_DOCKERFILE="$mutant" bash "${BASH_SOURCE[0]}" 2>&1)"; then
      fail "mutation '$name' was NOT caught"
    fi
    [[ "$out" == *"$expected_reason"* ]] || fail "mutation '$name' failed for the wrong reason: $out"
    mutations=$((mutations + 1))
  }
  floor_re="${FLOOR//./\\.}"
  # 1. the upgrade removed entirely (the whole RUN instruction, continuations included)
  awk '/^RUN apk add --no-cache --upgrade .krb5-libs/ { skip = 1 } skip { if ($0 !~ /\\$/) skip = 0; next } { print }' "$DOCKERFILE" > "$work/no-upgrade.Dockerfile"
  expect_mutant_fails no-upgrade "is not upgraded"
  # 2. the floor lowered to the vulnerable version, everywhere it appears
  sed "s/${floor_re}/1.22.1-r0/g" "$DOCKERFILE" > "$work/lower-floor.Dockerfile"
  expect_mutant_fails lower-floor "is not upgraded"
  # 3. the comparison dropped (the readback would only print)
  grep -v "case \"\$c\" in" "$DOCKERFILE" | sed 's/^  && echo "krb5-libs installed=\(.*\)" \\$/  \&\& echo "krb5-libs installed=\1"/' > "$work/no-compare.Dockerfile"
  expect_mutant_fails no-compare "is not upgraded"
  # 4. the comparison made unable to fail (the catch-all passes too)
  sed "s/\*) false ;; esac\$/*) true ;; esac/" "$DOCKERFILE" > "$work/or-true.Dockerfile"
  expect_mutant_fails or-true "is not upgraded"
  # 5. the comparison widened to accept '<' (a vulnerable version)
  sed "s/in '='|'>') true/in '='|'>'|'<') true/" "$DOCKERFILE" > "$work/inverted.Dockerfile"
  expect_mutant_fails inverted "is not upgraded"
  # 5b. a SHELL override that makes every RUN a no-op
  # lowercase on purpose: Docker's instruction parser is case-insensitive
  awk '{ print } /^FROM / && !d { print "shell [\"/bin/sh\", \"-c\", \"true\"]"; d = 1 }' "$DOCKERFILE" > "$work/shell-override.Dockerfile"
  expect_mutant_fails shell-override "SHELL instruction would neuter"
  # 6. the base moved to a floating tag
  sed 's/^FROM python:3.12-alpine3.23@sha256:[0-9a-f]*$/FROM python:3.12-alpine3.23/' "$DOCKERFILE" > "$work/floating-base.Dockerfile"
  expect_mutant_fails floating-base "digest-pinned"
  # 7. the upgrade moved below USER
  python3 - "$DOCKERFILE" "$work/after-user.Dockerfile" <<'PY'
import sys
src=open(sys.argv[1]).read().split('\n')
start=next(i for i,l in enumerate(src) if l.startswith("RUN apk add --no-cache --upgrade 'krb5-libs"))
end=start
while src[end].endswith('\\'): end+=1
block=src[start:end+1]; rest=src[:start]+src[end+1:]
u=next(i for i,l in enumerate(rest) if l.startswith('USER '))
out=rest[:u+1]+block+rest[u+1:]
open(sys.argv[2],'w').write('\n'.join(out))
PY
  expect_mutant_fails after-user "must run as root, before USER"
  # 8. the SHELL keyword split across a continuation (BuildKit joins it verbatim)
  awk '{ print } /^FROM / && !d { print "SHE\\"; print "LL [\"/bin/sh\", \"-c\", \"true\"]"; d = 1 }' "$DOCKERFILE" > "$work/split-shell.Dockerfile"
  expect_mutant_fails split-shell "SHELL instruction would neuter"
  # 9. an indented lowercase RUN that downgrades after the upgrade
  awk '{ print } /^RUN pip install/ && !d { print "  run apk add --no-cache krb5-libs=1.22.1-r0"; d = 1 }' "$DOCKERFILE" > "$work/indented-lowercase-run.Dockerfile"
  expect_mutant_fails indented-lowercase-run "not in canonical form"
  # 10. an escape directive turning a continued line into a new instruction
  awk 'NR == 1 { print; print "# escape=`"; next } { print }' "$DOCKERFILE" > "$work/escape-directive.Dockerfile"
  expect_mutant_fails escape-directive "escape="
  # 11. a keyword-delimited heredoc downgrading after the upgrade
  awk '{ print } /^RUN pip install/ && !d { print "RUN <<CMD"; print "ENV ;apk add --no-cache krb5-libs=1.22.1-r0"; print "CMD"; d = 1 }' "$DOCKERFILE" > "$work/heredoc-downgrade.Dockerfile"
  expect_mutant_fails heredoc-downgrade "heredoc instruction"
  # 12. an extra canonical instruction the literal checks do not name: only the pin sees it
  awk '{ print } /^RUN pip install/ && !d { print "RUN cp /bin/busybox /usr/local/bin/python3"; d = 1 }' "$DOCKERFILE" > "$work/extra-instruction.Dockerfile"
  expect_mutant_fails extra-instruction "differs from its pin"
  # 13. a parser directive inserted as line 1 (another program would read this file)
  { echo '# syntax=docker.io/someone/evil-frontend:latest'; cat "$DOCKERFILE"; } > "$work/syntax-directive.Dockerfile"
  expect_mutant_fails syntax-directive "line 1 must be the digest-pinned FROM"
  # 14. a byte-order mark
  { printf '\357\273\277'; cat "$DOCKERFILE"; } > "$work/bom.Dockerfile"
  expect_mutant_fails bom "byte-order mark"
  # 15. a backslash-escaped heredoc delimiter (BuildKit accepts it)
  awk '{ print } /^RUN pip install/ && !d { print "RUN <<\\CMD"; print "ENV ;apk add --no-cache krb5-libs=1.22.1-r0"; print "CMD"; d = 1 }' "$DOCKERFILE" > "$work/heredoc-escaped.Dockerfile"
  expect_mutant_fails heredoc-escaped "heredoc instruction"
  echo "PASS: case-workflows keeps krb5-libs >= ${FLOOR} with a printing, floor-comparing readback; ${mutations} mutations caught"
else
  echo "PASS (mutant run)"
fi
