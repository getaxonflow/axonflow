#!/usr/bin/env bash
# report-main-red.sh - one issue per job that is red on main (#4041) or on a
# release tag (#4169).
#
# A workflow that runs after the merge - on a push to main, or on a schedule -
# has no pull request to go red on, so when it fails nobody is told. This is
# that report: the last step of every such job calls it with the job's status.
#
#   failure  -> the job's issue is opened, or re-opened when a green run had
#               closed it, or commented on when it is already open; each time
#               with the run's URL and commit.
#   success  -> the job's open issue, if any, is closed by this run.
#   cancelled -> on main, nothing: a cancelled run there is almost always one a
#               newer push superseded. On a release TAG it is red (see below).
#   anything else (skipped) -> nothing.
#
# ONE ISSUE PER JOB. The issue's title is the key: "main-red: <workflow> /
# <job>", plus the matrix values for a matrix job, so one leg's green cannot
# close another leg's red. Every such issue carries the `main-red` label.
#
# ONLY MAIN, AFTER THE MERGE - AND RELEASE TAGS. The rule lives here, not in
# each workflow's `if:`: a push to refs/heads/main or a schedule speaks for
# main; a push to refs/tags/<tag> speaks for that release (#4169). A pull
# request, the merge queue, a dispatch or a push to any other branch does not,
# and is a no-op. So the step every job ends with is `if: always()`, and no
# workflow restates the rule.
#
# A RELEASE TAG HAS ITS OWN KEY SPACE (#4169). A red on a tag is not a red on
# main: its issue is "release-red: <tag> / <workflow> / <job>" under the label
# `release-red`, never `main-red`, so a green main never closes it and the
# pre-tag `main-red` gate does not read it. It closes when the same job goes
# green on the same tag (a re-run) or on any LATER tag, compared as versions
# (`sort -V`): a green v11.0.1 on an older line never heals v11.1.0. What no
# later green closes (a retired suite) is closed by hand at the release
# runbook's closeout step. The release gate for the tag being cut is the
# runbook's tag-runs step (gh-board.py tag-runs); this issue is the record.
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
tag=""
case "$event" in
push)
	case "$ref" in
	refs/heads/main) ;;
	refs/tags/?*) tag="${ref#refs/tags/}" ;;
	*)
		echo "report-main-red: a push to $ref does not speak for main; nothing to report"
		exit 0
		;;
	esac
	;;
schedule) ;;
*)
	echo "report-main-red: a '${event:-unknown}' run does not speak for main; nothing to report"
	exit 0
	;;
esac

# A CANCELLED run is nothing on main (a newer push superseded it) but RED on a
# tag: nothing supersedes a tag run, so its cancel is a timeout (every suite
# sets timeout-minutes) or a person, and either way the suite did not pass on
# the released commit.
case "$status" in
failure | success) ;;
cancelled)
	if [ -z "$tag" ]; then
		echo "report-main-red: a cancelled run on main was almost always superseded; nothing to report"
		exit 0
	fi
	;;
*)
	echo "report-main-red: job status '$status' is neither a failure nor a success; nothing to report"
	exit 0
	;;
esac
red=false
[ "$status" = success ] || red=true

# ver_le A B: tag A sorts at or before tag B. `sort -V` alone puts a
# pre-release AFTER its release (v11.1.0-rc.1 > v11.1.0), so the base versions
# are compared first and a pre-release precedes the release it names.
ver_le() {
	local a="$1" b="$2" ab="${1%%-*}" bb="${2%%-*}"
	if [ "$ab" != "$bb" ]; then
		[ "$(printf '%s\n%s\n' "$ab" "$bb" | sort -V | tail -n 1)" = "$bb" ]
		return
	fi
	[ "$a" = "$b" ] && return 0
	[ "$b" = "$bb" ] && return 0 # b is the release, a a pre-release of it
	[ "$a" = "$ab" ] && return 1 # a is the release, b a pre-release of it
	[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -n 1)" = "$b" ]
}

subject="$workflow / $job"
if [ -n "$matrix" ] && [ "$matrix" != "null" ]; then
	key=$(printf '%s' "$matrix" | jq -c -S . 2>/dev/null) || key="$matrix"
	subject="$subject $key"
fi
if [ -n "$tag" ]; then
	LABEL="release-red"
	title="release-red: $tag / $subject"
else
	title="main-red: $subject"
fi

# forge_failed <what>: the tracker could not be told. Fatal only when the job
# is already red.
forge_failed() {
	if [ "$red" = true ]; then
		echo "::error::report-main-red: could not $1 for '$title'; this red run is not on the tracker"
		exit 1
	fi
	echo "::warning::report-main-red: could not $1 for '$title'; the next green run tries again"
	exit 0
}

# The OPEN issues under the label: every close reads only these, so a limit
# counts live issues and closed ones cannot crowd an open one out (#4169).
open_issues=$("$GH" issue list --repo "$repo" --label "$LABEL" --state open --limit 500 --json number,title,state) ||
	forge_failed "list the open $LABEL issues"
exact() { # exact <issues json> -> "<number> <state>" of the newest issue titled $title
	printf '%s' "$1" | jq -r --arg t "$title" \
		'[.[] | select(.title == $t)] | sort_by(.number) | last | select(. != null) | "\(.number) \(.state)"'
}
match=$(exact "$open_issues") || forge_failed "read the open $LABEL issues"
# A red with no open issue re-opens its CLOSED one rather than open a duplicate.
# The forge is asked for that exact title, not for the newest N closed issues,
# so no number of other closed issues can hide it.
# The search phrase is the title with every `"` turned into a space: a MATRIX
# title carries its key as JSON, and the forge's search finds nothing for a
# quoted phrase with inner quotes (measured on the tracker: #4318 and #4296 are
# not found by their titles, and are found once the quotes are spaces). The
# exact-title filter below still decides the match.
if [ -z "$match" ] && [ "$red" = true ]; then
	phrase="${title//\"/ }"
	closed_issues=$("$GH" issue list --repo "$repo" --label "$LABEL" --state closed \
		--search "\"$phrase\" in:title" --limit 100 --json number,title,state) ||
		forge_failed "search the closed $LABEL issues"
	match=$(exact "$closed_issues") || forge_failed "read the closed $LABEL issues"
fi
number="${match%% *}"
state="${match#* }"

if [ "$status" = success ] && [ -n "$tag" ]; then
	# Every OPEN issue of THIS job on this tag or an earlier one: "release-red:
	# <t> / <subject>" with <t> at or before $tag. Listed OPEN-only, so the limit
	# counts live issues and closed ones cannot push the oldest open one out.
	older=$(printf '%s' "$open_issues" | jq -r --arg s " / $subject" \
		'.[] | select(.state == "OPEN") | select(.title | startswith("release-red: ") and endswith($s))
		 | "\(.number) \(.title | ltrimstr("release-red: ") | rtrimstr($s))"') ||
		forge_failed "read the $LABEL issues"
	while read -r n t; do
		[ -n "$n" ] || continue
		case "$t" in *" "* | "") continue ;; esac
		ver_le "$t" "$tag" || continue
		"$GH" issue close "$n" --repo "$repo" --comment "Green on ${tag} at ${sha}: ${run_url}" > /dev/null ||
			forge_failed "close #$n"
		echo "report-main-red: closed #$n - '$workflow / $job' is green on $tag"
	done <<< "$older"
	exit 0
fi

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
	if [ -n "$tag" ]; then
		verb="failed"
		[ "$status" = cancelled ] && verb="was cancelled (a timeout, or by hand)"
		printf 'The job `%s` of the workflow `%s` %s on the release tag `%s` at `%s`.\n\n' "$job" "$workflow" "$verb" "$tag" "$sha"
	else
		printf 'The job `%s` of the workflow `%s` failed on main at `%s`.\n\n' "$job" "$workflow" "$sha"
	fi
	[ -n "$matrix" ] && [ "$matrix" != "null" ] && printf 'Matrix: `%s`\n\n' "$key"
	printf 'Run: %s\n\n' "$run_url"
	if [ -n "$tag" ]; then
		printf 'This issue is closed by the next green run of this job on %s (a re-run) or on any later release tag (#4169). The release gate for a tag is the release runbook'"'"'s tag-runs step; a red that no later release clears is closed by hand at its closeout step.\n' "$tag"
	else
		printf 'This issue is closed by the next green run of this job on main (#4041).\n'
	fi
} > "$body"

if [ -z "$match" ]; then
	if [ -n "$tag" ]; then
		desc="A job is red on a release tag (#4169)"
	else
		desc="A job that runs after the merge is red on main (#4041)"
	fi
	"$GH" label create "$LABEL" --repo "$repo" --force --color B60205 --description "$desc" > /dev/null 2>&1 || true
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
