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
	[ -e "$FIXTURE/list.fail" ] && exit 1
	cat "$FIXTURE/issues.json"
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
for ev in "pull_request refs/pull/1/merge" "merge_group refs/heads/gh-readonly-queue/main/x" "workflow_dispatch refs/heads/main" "push refs/tags/v11.0.0" "push refs/heads/feature"; do
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

[ $fail -eq 0 ] && echo "PASS: report-main-red opens, re-opens, comments and closes one issue per red job on main, and is silent everywhere else"
exit $fail
