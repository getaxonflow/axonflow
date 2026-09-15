#!/usr/bin/env bash
# report-main-red.sh - one issue per job that is red on main (#4041).
#
# A workflow that runs after the merge - on a push to main, or on a schedule -
# has no pull request to go red on, so when it fails nobody is told. This is
# that report: the last step of every such job calls it with the job's status.
#
#   failure  -> the job's issue is opened, or re-opened when a green run had
#               closed it, or commented on when it is already open; each time
#               with the run's URL and commit.
#   success  -> the job's open issue, if any, is closed by this run.
#   anything else (cancelled, skipped) -> nothing: a cancelled run on main is
#               almost always one a newer push superseded.
#
# ONE ISSUE PER JOB. The issue's title is the key: "main-red: <workflow> /
# <job>", plus the matrix values for a matrix job, so one leg's green cannot
# close another leg's red. Every such issue carries the `main-red` label.
#
# ONLY MAIN, AFTER THE MERGE. The rule lives here, not in each workflow's `if:`:
# a push to refs/heads/main or a schedule speaks for main. A pull request, the
# merge queue, a dispatch or a release tag does not, and is a no-op. So the
# step every job ends with is `if: always()`, and no workflow restates the rule.
#
# ONLY THIS REPOSITORY. The public mirror runs several of the same workflows;
# its reds are not this tracker's, and an issue opened there would name jobs in
# public. So it acts only in $MAIN_RED_REPO, default
# getaxonflow/axonflow-enterprise, and is a no-op anywhere else.
#
# A TRACKER FAILURE NEVER TURNS A GREEN JOB RED. On the failure path the job is
# already failing, so an unreachable tracker is an error. On the success path
# it is a warning; the next green run tries the close again.
#
# The forge is `gh`, or $AXF_GH, which is how
# tests/regression-test-required/report_main_red_test.sh drives this against a
# stub.
set -uo pipefail

GH="${AXF_GH:-gh}"
LABEL="main-red"

usage() {
	cat >&2 <<'USAGE'
Usage: report-main-red.sh --status <job status> --workflow <name> --job <id>
                          --run-url <url> --sha <commit> --repo <owner/name>
                          [--matrix <json>]
USAGE
}

status="" workflow="" job="" matrix="" run_url="" sha="" repo=""
while [ $# -gt 0 ]; do
	case "$1" in
	--status) status="${2:-}" ;;
	--workflow) workflow="${2:-}" ;;
	--job) job="${2:-}" ;;
	--matrix) matrix="${2:-}" ;;
	--run-url) run_url="${2:-}" ;;
	--sha) sha="${2:-}" ;;
	--repo) repo="${2:-}" ;;
	*) usage; exit 2 ;;
	esac
	shift 2 || { usage; exit 2; }
done
for v in status workflow job run_url sha repo; do
	[ -n "${!v}" ] || { echo "report-main-red: --${v//_/-} is required" >&2; usage; exit 2; }
done

if [ "$repo" != "${MAIN_RED_REPO:-getaxonflow/axonflow-enterprise}" ]; then
	echo "report-main-red: $repo is not ${MAIN_RED_REPO:-getaxonflow/axonflow-enterprise}; nothing to report"
	exit 0
fi

event="${GITHUB_EVENT_NAME:-}"
ref="${GITHUB_REF:-}"
case "$event" in
push)
	if [ "$ref" != "refs/heads/main" ]; then
		echo "report-main-red: a push to $ref does not speak for main; nothing to report"
		exit 0
	fi
	;;
schedule) ;;
*)
	echo "report-main-red: a '${event:-unknown}' run does not speak for main; nothing to report"
	exit 0
	;;
esac

case "$status" in
failure | success) ;;
*)
	echo "report-main-red: job status '$status' is neither a failure nor a success; nothing to report"
	exit 0
	;;
esac

title="main-red: $workflow / $job"
if [ -n "$matrix" ] && [ "$matrix" != "null" ]; then
	key=$(printf '%s' "$matrix" | jq -c -S . 2>/dev/null) || key="$matrix"
	title="$title $key"
fi

# forge_failed <what>: the tracker could not be told. Fatal only when the job
# is already red.
forge_failed() {
	if [ "$status" = failure ]; then
		echo "::error::report-main-red: could not $1 for '$title'; this red run is not on the tracker"
		exit 1
	fi
	echo "::warning::report-main-red: could not $1 for '$title'; the next green run tries again"
	exit 0
}

issues=$("$GH" issue list --repo "$repo" --label "$LABEL" --state all --limit 500 --json number,title,state) ||
	forge_failed "list the $LABEL issues"
match=$(printf '%s' "$issues" | jq -r --arg t "$title" \
	'[.[] | select(.title == $t)] | sort_by(.number) | last | select(. != null) | "\(.number) \(.state)"') ||
	forge_failed "read the $LABEL issues"
number="${match%% *}"
state="${match#* }"

if [ "$status" = success ]; then
	if [ -n "$match" ] && [ "$state" = OPEN ]; then
		"$GH" issue close "$number" --repo "$repo" --comment "Green again on main at ${sha}: ${run_url}" > /dev/null ||
			forge_failed "close #$number"
		echo "report-main-red: closed #$number - '$title' is green again"
	fi
	exit 0
fi

body=$(mktemp) || forge_failed "write the report"
trap 'rm -f "${body:?}"' EXIT
{
	printf 'The job `%s` of the workflow `%s` failed on main at `%s`.\n\n' "$job" "$workflow" "$sha"
	[ -n "$matrix" ] && [ "$matrix" != "null" ] && printf 'Matrix: `%s`\n\n' "$key"
	printf 'Run: %s\n\n' "$run_url"
	printf 'This issue is closed by the next green run of this job on main (#4041).\n'
} > "$body"

if [ -z "$match" ]; then
	"$GH" label create "$LABEL" --repo "$repo" --force --color B60205 \
		--description "A job that runs after the merge is red on main (#4041)" > /dev/null 2>&1 || true
	url=$("$GH" issue create --repo "$repo" --title "$title" --label "$LABEL" --body-file "$body") ||
		forge_failed "open an issue"
	echo "report-main-red: opened $url"
elif [ "$state" = OPEN ]; then
	"$GH" issue comment "$number" --repo "$repo" --body-file "$body" > /dev/null ||
		forge_failed "comment on #$number"
	echo "report-main-red: #$number is still open; added this run"
else
	"$GH" issue reopen "$number" --repo "$repo" > /dev/null || forge_failed "re-open #$number"
	"$GH" issue comment "$number" --repo "$repo" --body-file "$body" > /dev/null ||
		forge_failed "comment on #$number"
	echo "report-main-red: re-opened #$number - '$title' is red again"
fi
