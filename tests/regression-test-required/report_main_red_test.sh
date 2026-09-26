#!/usr/bin/env bash
# report_main_red_test.sh - .github/actions/report-main-red/report-main-red.sh
# (#4041) against a stub forge: every branch of the one-issue-per-red-job
# lifecycle, the events it must stay silent on, and the rule that a tracker
# failure never turns a green job red.
#
# The stub stands in for `gh` through AXF_GH. It answers `issue list` from a
# fixture and records every write, so each case asserts the exact calls made.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/.github/actions/report-main-red/report-main-red.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

fail=0
flunk() { echo "FAIL: $*"; fail=1; }

STUB="$WORK/gh"
cat > "$STUB" <<'STUB'
#!/usr/bin/env bash
# issue list -> $FIXTURE/issues.json (or fail when $FIXTURE/list.fail exists);
# every other call is appended to $FIXTURE/calls, one line each, and fails
# when $FIXTURE/<verb>.fail exists.
verb="$1 $2"
case "$verb" in
"issue list")
	# Honours --label, --state and a quoted --search the way the forge does, so
	# a reporter that drops a filter is seen by a cell, not only by reading. An
	# issue's label is its "label" field, else read off its title's prefix.
	[ -e "$FIXTURE/list.fail" ] && exit 1
	label="" state="open" search="" limit=30
	shift 2
	while [ $# -gt 0 ]; do
		case "$1" in
		--label) label="$2"; shift 2 ;;
		--state) state="$2"; shift 2 ;;
		--search) search="$2"; shift 2 ;;
		--limit) limit="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	printf '%s\n' "--label $label --state $state${search:+ --search $search}" >> "$FIXTURE/lists"
	phrase=$(printf '%s' "$search" | sed -n 's/^"\(.*\)" in:title$/\1/p')
	# Like the forge: a quoted phrase with an inner `"` finds NOTHING, and a
	# phrase is matched with quotes ignored.
	case "$phrase" in *'"'*) echo '[]'; exit 0 ;; esac
	jq -c --arg l "$label" --arg s "$state" --arg p "$phrase" --argjson n "$limit" '[.[]
		| select(((.label // (if (.title | startswith("release-red: ")) then "release-red" else "main-red" end)) == $l) or $l == "")
		| select($s == "all" or ($s == "open" and .state == "OPEN") or ($s == "closed" and .state == "CLOSED"))
		| select($p == "" or (.title | gsub("\""; " ") | contains($p)))] | sort_by(-.number) | .[:$n]' "$FIXTURE/issues.json"
	;;
*)
	printf '%s\n' "$*" >> "$FIXTURE/calls"
	[ -e "$FIXTURE/${2}.fail" ] && exit 1
	[ "$verb" = "issue create" ] && echo "https://github.com/stub/stub/issues/9001"
	exit 0
	;;
esac
STUB
chmod +x "$STUB"

# run <case dir> <status> [event] [ref] [matrix]: the script's exit code; its
# output lands in <case dir>/out.
run() {
	local dir="$1" status="$2" event="${3:-push}" ref="${4:-refs/heads/main}" matrix="${5:-}"
	: > "$dir/calls"
	: > "$dir/lists"
	AXF_GH="$STUB" FIXTURE="$dir" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" MAIN_RED_REPO="${MAIN_RED_REPO_UNDER_TEST-o/r}" \
		bash "$SCRIPT" --status "$status" --workflow "Infrastructure Validation" --job "validate" \
		--run-url "https://github.com/o/r/actions/runs/1" --sha "abc1234" --repo "o/r" \
		${matrix:+--matrix "$matrix"} > "$dir/out" 2>&1
}

fixture() { # <name> <issues json> -> a fresh case dir
	local dir="$WORK/$1"
	mkdir -p "$dir"
	printf '%s' "$2" > "$dir/issues.json"
	printf '%s' "$dir"
}

TITLE="main-red: Infrastructure Validation / validate"

# 1. A failure with no issue opens one, labelled.
d=$(fixture fail_none '[]')
run "$d" failure || flunk "a failure with no issue exited non-zero: $(cat "$d/out")"
grep -q "^issue create --repo o/r --title $TITLE --label main-red --body-file " "$d/calls" || flunk "a failure with no issue did not open one: $(cat "$d/calls")"

# 2. A failure while its issue is open comments on it; no second issue.
d=$(fixture fail_open "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\"}]")
run "$d" failure || flunk "a failure with an open issue exited non-zero"
grep -q "^issue comment 7 --repo o/r --body-file " "$d/calls" || flunk "a failure did not comment on its open issue: $(cat "$d/calls")"
grep -q "^issue create" "$d/calls" && flunk "a failure opened a duplicate beside its open issue"

# 3. A failure after a green run closed it re-opens it.
d=$(fixture fail_closed "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"CLOSED\"}]")
run "$d" failure || flunk "a failure with a closed issue exited non-zero"
grep -q "^issue reopen 7 --repo o/r" "$d/calls" || flunk "a failure did not re-open its closed issue: $(cat "$d/calls")"
grep -q "^issue comment 7 " "$d/calls" || flunk "a re-open carried no run"

# 4. A success closes the open issue, naming the green run.
d=$(fixture green_open "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\"}]")
run "$d" success || flunk "a green run with an open issue exited non-zero"
grep -q "^issue close 7 --repo o/r --comment Green again on main at abc1234: https://github.com/o/r/actions/runs/1" "$d/calls" || flunk "a green run did not close its issue: $(cat "$d/calls")"

# 5. Silence: a green run with no open issue, a cancelled run, and every run
#    that does not speak for main write nothing.
d=$(fixture green_none "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"CLOSED\"}]")
run "$d" success; [ -s "$d/calls" ] && flunk "a green run with no open issue wrote: $(cat "$d/calls")"
d=$(fixture cancelled '[]')
run "$d" cancelled; [ -s "$d/calls" ] && flunk "a cancelled run wrote: $(cat "$d/calls")"
for ev in "pull_request refs/pull/1/merge" "merge_group refs/heads/gh-readonly-queue/main/x" "workflow_dispatch refs/heads/main" "push refs/heads/feature"; do
	set -- $ev
	d=$(fixture "silent_$1_${2//\//_}" '[]')
	run "$d" failure "$1" "$2" || flunk "a $1 run on $2 exited non-zero"
	[ -s "$d/calls" ] && flunk "a $1 run on $2 reported main red: $(cat "$d/calls")"
done
d=$(fixture schedule '[]')
run "$d" failure schedule refs/heads/main || flunk "a scheduled failure exited non-zero"
grep -q "^issue create" "$d/calls" || flunk "a scheduled failure opened no issue"

# 6. A matrix leg is its own key: its green cannot close another leg's red.
d=$(fixture matrix "[{\"number\":7,\"title\":\"$TITLE {\\\"arch\\\":\\\"amd64\\\"}\",\"state\":\"OPEN\"}]")
run "$d" success push refs/heads/main '{"arch":"arm64"}'
[ -s "$d/calls" ] && flunk "the arm64 leg's green touched the amd64 leg's issue: $(cat "$d/calls")"
run "$d" success push refs/heads/main '{"arch": "amd64"}'
grep -q "^issue close 7 " "$d/calls" || flunk "the amd64 leg's green did not close its own issue: $(cat "$d/calls")"

# 7. Planted: a title that differs by one character is another job's issue.
d=$(fixture near_miss "[{\"number\":7,\"title\":\"${TITLE}s\",\"state\":\"OPEN\"}]")
run "$d" success; [ -s "$d/calls" ] && flunk "a near-miss title was treated as this job's issue"

# 8. Only this repository: with the default, a red run in any other
#    repository (here o/r, standing for the public mirror) writes nothing.
d=$(fixture other_repo '[]')
MAIN_RED_REPO_UNDER_TEST="" run "$d" failure || flunk "a red run in another repository exited non-zero"
[ -s "$d/calls" ] && flunk "a red run outside getaxonflow/axonflow-enterprise wrote to its tracker: $(cat "$d/calls")"

# 9. A tracker failure: an error on a red run, only a warning on a green one.
d=$(fixture forge_red '[]'); touch "$d/list.fail"
run "$d" failure && flunk "a red run whose report could not be filed exited 0"
grep -q "::error::" "$d/out" || flunk "a red run's filing failure printed no ::error::"
d=$(fixture forge_green "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\"}]"); touch "$d/close.fail"
run "$d" success || flunk "a tracker failure turned a green run red: $(cat "$d/out")"
grep -q "::warning::" "$d/out" || flunk "a green run's close failure printed no ::warning::"

# 10. A RELEASE TAG (#4169): its own key space, `release-red: <tag> / ...` under
#     the label `release-red`, closed by the same job green on the same or a
#     LATER tag - never by an older tag, another job, or a green main.
TAG11="release-red: v11.1.0 / Infrastructure Validation / validate"
TAG10="release-red: v11.0.0 / Infrastructure Validation / validate"
d=$(fixture tag_fail '[]')
run "$d" failure push refs/tags/v11.1.0 || flunk "a failure on a release tag exited non-zero: $(cat "$d/out")"
grep -q "^issue create --repo o/r --title $TAG11 --label release-red --body-file " "$d/calls" || flunk "a failure on a tag did not open its release-red issue: $(cat "$d/calls")"
grep -q -- "--label main-red" "$d/calls" && flunk "a tag red was filed under main-red"
grep -q "^label create release-red " "$d/calls" || flunk "the release-red label was not ensured"

d=$(fixture tag_fail_open "[{\"number\":8,\"title\":\"$TAG11\",\"state\":\"OPEN\"}]")
run "$d" failure push refs/tags/v11.1.0 || flunk "a repeat tag failure exited non-zero"
grep -q "^issue comment 8 --repo o/r --body-file " "$d/calls" || flunk "a repeat tag failure did not comment on its open issue: $(cat "$d/calls")"

d=$(fixture tag_green_same "[{\"number\":8,\"title\":\"$TAG11\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0 || flunk "a green re-run on the same tag exited non-zero"
grep -q "^issue close 8 --repo o/r --comment Green on v11.1.0 at abc1234: " "$d/calls" || flunk "a green re-run on the same tag did not close its issue: $(cat "$d/calls")"

d=$(fixture tag_green_later "[{\"number\":8,\"title\":\"$TAG10\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0 || flunk "a green run on a later tag exited non-zero"
grep -q "^issue close 8 --repo o/r --comment Green on v11.1.0 at abc1234: " "$d/calls" || flunk "a green later tag did not close the older tag's issue, naming the tag: $(cat "$d/calls")"

d=$(fixture tag_green_older "[{\"number\":8,\"title\":\"$TAG11\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.0.1 || flunk "a green run on an older tag exited non-zero"
[ -s "$d/calls" ] && flunk "a green OLDER tag (v11.0.1) closed a newer tag's (v11.1.0) issue: $(cat "$d/calls")"

d=$(fixture tag_green_other_job "[{\"number\":8,\"title\":\"release-red: v11.1.0 / Infrastructure Validation / validates\",\"state\":\"OPEN\"},{\"number\":9,\"title\":\"release-red: v11.1.0 / Other / validate\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0
[ -s "$d/calls" ] && flunk "a tag green closed another job's release-red issue: $(cat "$d/calls")"

d=$(fixture main_green_tag_issue "[{\"number\":8,\"title\":\"$TAG11\",\"state\":\"OPEN\"}]")
run "$d" success push refs/heads/main
[ -s "$d/calls" ] && flunk "a green MAIN closed a release-red issue: $(cat "$d/calls")"
d=$(fixture tag_green_main_issue "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0
[ -s "$d/calls" ] && flunk "a green TAG closed a main-red issue: $(cat "$d/calls")"

d=$(fixture tag_matrix "[{\"number\":8,\"title\":\"$TAG11 {\\\"arch\\\":\\\"amd64\\\"}\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0 '{"arch":"arm64"}'
[ -s "$d/calls" ] && flunk "the arm64 leg's tag green touched the amd64 leg's tag issue: $(cat "$d/calls")"
run "$d" success push refs/tags/v11.1.0 '{"arch": "amd64"}'
grep -q "^issue close 8 " "$d/calls" || flunk "the amd64 leg's tag green did not close its own tag issue: $(cat "$d/calls")"

# 11. A cancelled TAG run is red (a timeout; nothing supersedes a tag), a
#     pre-release sorts before its release, and the closer touches only OPEN
#     issues whose tag part is a single word (R3 round 1 on #4419).
d=$(fixture tag_cancelled '[]')
run "$d" cancelled push refs/tags/v11.1.0 || flunk "a cancelled tag run exited non-zero"
grep -q "^issue create --repo o/r --title $TAG11 --label release-red " "$d/calls" || flunk "a cancelled tag run did not file its release-red issue: $(cat "$d/calls")"
d=$(fixture main_cancelled '[]')
run "$d" cancelled push refs/heads/main; [ -s "$d/calls" ] && flunk "a cancelled MAIN run wrote: $(cat "$d/calls")"

TAGGA="release-red: v11.2.0 / Infrastructure Validation / validate"
TAGRC="release-red: v11.2.0-rc.1 / Infrastructure Validation / validate"
d=$(fixture rc_does_not_close_ga "[{\"number\":8,\"title\":\"$TAGGA\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.2.0-rc.1
[ -s "$d/calls" ] && flunk "a green PRE-RELEASE (v11.2.0-rc.1) closed its release's (v11.2.0) issue: $(cat "$d/calls")"
d=$(fixture ga_closes_rc "[{\"number\":8,\"title\":\"$TAGRC\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.2.0
grep -q "^issue close 8 " "$d/calls" || flunk "a green release (v11.2.0) did not close its pre-release's (v11.2.0-rc.1) issue: $(cat "$d/calls")"

d=$(fixture closed_not_reclosed "[{\"number\":8,\"title\":\"$TAG10\",\"state\":\"CLOSED\"}]")
run "$d" success push refs/tags/v11.1.0
[ -s "$d/calls" ] && flunk "the tag closer acted on a CLOSED issue: $(cat "$d/calls")"
d=$(fixture spaced_tag "[{\"number\":8,\"title\":\"release-red: v11.0.0 extra / Infrastructure Validation / validate\",\"state\":\"OPEN\"}]")
run "$d" success push refs/tags/v11.1.0
[ -s "$d/calls" ] && flunk "the tag closer closed an issue whose tag part is not one word: $(cat "$d/calls")"

# 12. The filters themselves (#4169 row on #4249): the stub honours --label,
#     --state, --search and --limit as the forge does.
# The label: an OPEN issue titled like this job's main-red issue but labelled
# release-red is not this job's main-red issue.
d=$(fixture label_isolation "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\",\"label\":\"release-red\"}]")
run "$d" success; [ -s "$d/calls" ] && flunk "a green main closed an issue under another label: $(cat "$d/calls")"
# Closes read OPEN issues only.
d=$(fixture lists_open "[{\"number\":7,\"title\":\"$TITLE\",\"state\":\"OPEN\"}]")
run "$d" success
grep -qx -- "--label main-red --state open" "$d/lists" || flunk "a green main did not list the open main-red issues only: $(cat "$d/lists")"
# A red whose issue was closed long ago re-opens it, though 600 newer closed
# issues sit under the label: the forge is asked for that title, not for the
# newest N.
python3 - "$WORK/many.json" "$TITLE" <<'MANY'
import json, sys
out = [{"number": 1, "title": sys.argv[2], "state": "CLOSED"}]
out += [{"number": 100 + i, "title": f"main-red: Other / job{i}", "state": "CLOSED"} for i in range(600)]
json.dump(out, open(sys.argv[1], "w"))
MANY
d=$(fixture many_closed "$(cat "$WORK/many.json")")
run "$d" failure || flunk "a red with an old closed issue exited non-zero"
grep -q "^issue reopen 1 --repo o/r" "$d/calls" || flunk "a red behind 600 newer closed issues opened a duplicate instead of re-opening #1: $(cat "$d/calls")"
grep -q "^issue create" "$d/calls" && flunk "a duplicate was opened beside the closed issue"

# 13. A MATRIX job's red whose issue was closed long ago re-opens it: its title
#     carries the key as JSON, and the forge's search finds nothing for a phrase
#     with inner quotes, so the lookup searches with the quotes as spaces
#     (master's round on #4423).
MTITLE="$TITLE {\"arch\":\"amd64\"}"
python3 - "$WORK/many-matrix.json" "$MTITLE" <<'MANY'
import json, sys
out = [{"number": 1, "title": sys.argv[2], "state": "CLOSED"}]
out += [{"number": 100 + i, "title": f"main-red: Other / job{i}", "state": "CLOSED"} for i in range(600)]
json.dump(out, open(sys.argv[1], "w"))
MANY
d=$(fixture many_closed_matrix "$(cat "$WORK/many-matrix.json")")
run "$d" failure push refs/heads/main '{"arch":"amd64"}' || flunk "a matrix red with an old closed issue exited non-zero"
grep -q "^issue reopen 1 --repo o/r" "$d/calls" || flunk "a MATRIX red behind 600 newer closed issues opened a duplicate instead of re-opening #1: $(cat "$d/calls")"

[ $fail -eq 0 ] && echo "PASS: report-main-red opens, re-opens, comments and closes one issue per red job on main, and is silent everywhere else"
exit $fail
