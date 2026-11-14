#!/usr/bin/env bash
# Behavioural regression tests for immutable ECR publication and retry paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG_SCRIPT="$ROOT/.github/scripts/tag-deployed-images.sh"
MARKET_SCRIPT="$ROOT/.github/scripts/copy-images-to-marketplace.sh"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/ecr-immutable-retry.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/bin"

MOCK_SOURCE_DIGEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"
MOCK_DRIFT_DIGEST="sha256:2222222222222222222222222222222222222222222222222222222222222222"
export MOCK_SOURCE_DIGEST MOCK_DRIFT_DIGEST

cat >"$FIXTURE/bin/aws" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

arg_value() {
  local wanted="$1"
  shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "$wanted" ]; then printf '%s\n' "$2"; return 0; fi
    shift
  done
  return 1
}

[ "${1:-}" = "ecr" ] || { echo "unexpected aws command: $*" >&2; exit 2; }
operation="${2:-}"
repo="$(arg_value --repository-name "$@" || true)"
image_id="$(arg_value --image-ids "$@" || true)"

case "$operation" in
  batch-get-image)
    if [ "${TAG_MISSING_SOURCE:-0}" = "1" ] && [ "$repo" = "image-b" ]; then exit 254; fi
    if [ "${TAG_MANIFEST_DENIED:-0}" = "1" ] && [ "$repo" = "image-b" ]; then
      echo 'AccessDeniedException' >&2
      exit 253
    fi
    printf '%s|%s\n' "$repo" "$image_id" >>"$MOCK_STATE/manifests"
    if [ "${TAG_PINNED_MANIFEST_MISSING:-0}" = "1" ] \
      && [ "$repo" = "image-b" ] \
      && [ "$image_id" = "imageDigest=$MOCK_SOURCE_DIGEST" ]; then
      echo 'ImageNotFoundException' >&2
      exit 254
    fi
    if [ "${TAG_SOURCE_MOVED:-0}" = "1" ] \
      && [ "$repo" = "image-b" ] \
      && [ "$image_id" = "imageTag=source123" ]; then
      printf '%s\n' '{"schemaVersion":2,"marker":"moved-source-tag"}'
    else
      printf '%s\n' '{"schemaVersion":2,"marker":"pinned-source-digest"}'
    fi
    ;;
  put-image)
    tag="$(arg_value --image-tag "$@")"
    manifest="$(arg_value --image-manifest "$@")"
    if [ "${TAG_PUT_FAIL:-0}" = "1" ] && [ "$repo" = "image-b" ]; then exit 42; fi
    if [[ "$manifest" == *moved-source-tag* ]]; then
      stored_digest="$MOCK_DRIFT_DIGEST"
    else
      stored_digest="$MOCK_SOURCE_DIGEST"
    fi
    printf '%s|%s|%s\n' "$repo" "$tag" "$stored_digest" >>"$MOCK_STATE/puts"
    printf '%s\n' '{"image":{"imageId":{"imageDigest":"mock"}}}'
    ;;
  describe-images)
    if [[ "$repo" == axonflow/* ]]; then
      image="${repo#axonflow/}"
      if [ -n "${MARKET_DOC_MODE:-}" ]; then
        if [ "$image_id" = "imageTag=1.2.3" ]; then
          if { [ "$MARKET_DOC_MODE" = "missing-exact" ] || [ "$MARKET_DOC_MODE" = "neighbor-only" ]; } \
            && [ "$image" = "axonflow-prometheus" ]; then
            echo 'ImageNotFoundException' >&2
            exit 254
          fi
          if [ "$MARKET_DOC_MODE" = "invalid-digest" ] && [ "$image" = "axonflow-grafana" ]; then
            printf '%s\n' 'not-a-sha256-digest'
          else
            printf '%s\n' "$MOCK_SOURCE_DIGEST"
          fi
          exit 0
        fi
        # Model the old substring query: a missing exact tag could either emit
        # no rows or match a neighboring tag such as 1.2.30 and still exit 0.
        if [ -z "$image_id" ]; then
          if [ "$MARKET_DOC_MODE" = "neighbor-only" ] && [ "$image" = "axonflow-prometheus" ]; then
            printf '%s\n' '1.2.30'
          fi
          exit 0
        fi
        echo "unexpected Marketplace runbook selector: $repo $image_id" >&2
        exit 2
      fi
      if [ "${MARKET_LOOKUP_DENIED:-0}" = "1" ] && [ "$image" = "image-a" ]; then
        echo 'AccessDeniedException' >&2
        exit 253
      fi
      if [ "${MARKET_EXISTING:-}" = "all" ] \
        || { [ "${MARKET_EXISTING:-}" = "partial" ] && [ "$image" = "image-a" ]; }; then
        printf '%s\n' "$MOCK_SOURCE_DIGEST"
        exit 0
      fi
      if [ "${MARKET_MISMATCH:-0}" = "1" ] && [ "$image" = "image-b" ]; then
        printf '%s\n' "$MOCK_DRIFT_DIGEST"
        exit 0
      fi
      if [ -f "$MOCK_STATE/creates" ] && grep -Fq "/${image}:1.2.3|" "$MOCK_STATE/creates"; then
        if [ "${MARKET_READBACK_DRIFT:-0}" = "1" ] && [ "$image" = "image-b" ]; then
          printf '%s\n' "$MOCK_DRIFT_DIGEST"
        else
          printf '%s\n' "$MOCK_SOURCE_DIGEST"
        fi
        exit 0
      fi
      echo 'ImageNotFoundException' >&2
      exit 254
    fi

    if [ "$image_id" = "imageTag=source123" ] || [[ "$image_id" == imageDigest=sha256:* ]]; then
      if [ "${TAG_MISSING_SOURCE:-0}" = "1" ] && [ "$repo" = "image-b" ]; then echo 'ImageNotFoundException' >&2; exit 254; fi
      printf '%s\n' "$MOCK_SOURCE_DIGEST"
      exit 0
    fi
    if [[ "$image_id" == imageTag=deployed-* ]]; then
      if [ "${TAG_LOOKUP_DENIED:-0}" = "1" ] && [ "$repo" = "image-a" ]; then
        echo 'AccessDeniedException' >&2
        exit 253
      fi
      if [ "${TAG_EXISTING:-}" = "all" ] \
        || { [ "${TAG_EXISTING:-}" = "partial" ] && [ "$repo" = "image-a" ]; }; then
        printf '%s\n' "$MOCK_SOURCE_DIGEST"
        exit 0
      fi
      if [ "${TAG_MISMATCH:-0}" = "1" ] && [ "$repo" = "image-b" ]; then
        printf '%s\n' "$MOCK_DRIFT_DIGEST"
        exit 0
      fi
      tag="${image_id#imageTag=}"
      if [ -f "$MOCK_STATE/puts" ] && grep -Fq "${repo}|${tag}" "$MOCK_STATE/puts"; then
        if [ "${TAG_READBACK_DRIFT:-0}" = "1" ] && [ "$repo" = "image-b" ]; then
          printf '%s\n' "$MOCK_DRIFT_DIGEST"
        else
          awk -F '|' -v repo="$repo" -v tag="$tag" \
            '$1 == repo && $2 == tag { print $3; found=1; exit } END { if (!found) exit 1 }' \
            "$MOCK_STATE/puts"
        fi
        exit 0
      fi
      echo 'ImageNotFoundException' >&2
      exit 254
    fi
    echo "unexpected describe-images selector: $repo $image_id" >&2
    exit 2
    ;;
  *) echo "unexpected aws ecr operation: $operation" >&2; exit 2 ;;
esac
MOCK

cat >"$FIXTURE/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  buildx)
    [ "${2:-}" = "imagetools" ] || exit 2
    if [ "${3:-}" = "inspect" ]; then
      ref="${4:-}"
      if [ "${MARKET_BAD_SOURCE_DIGEST:-0}" = "1" ] && [[ "$ref" == */image-b:* ]]; then
        printf 'not-a-digest\n'
      else
        printf '%s\n' "$MOCK_SOURCE_DIGEST"
      fi
    elif [ "${3:-}" = "create" ]; then
      destination="${5:-}"
      source="${6:-}"
      if [ "${MARKET_PUSH_FAIL:-0}" = "1" ] && [[ "$destination" == */image-b:* ]]; then exit 43; fi
      printf '%s|%s\n' "$destination" "$source" >>"$MOCK_STATE/creates"
    else
      exit 2
    fi
    ;;
  *) echo "unexpected docker command: $*" >&2; exit 2 ;;
esac
MOCK
chmod +x "$FIXTURE/bin/aws" "$FIXTURE/bin/docker"

run_case() {
  local name="$1" expected="$2" subject="$3"
  shift 3
  local case_root="$FIXTURE/$name"
  mkdir -p "$case_root"
  if env PATH="$FIXTURE/bin:$PATH" MOCK_STATE="$case_root" "$@" "$subject" >"$case_root/output" 2>&1; then
    status=0
  else
    status=$?
  fi
  if [ "$expected" = pass ] && [ "$status" -ne 0 ]; then
    echo "FAIL: $name unexpectedly failed"
    cat "$case_root/output"
    exit 1
  fi
  if [ "$expected" = fail ] && [ "$status" -eq 0 ]; then
    echo "FAIL: $name unexpectedly passed"
    cat "$case_root/output"
    exit 1
  fi
}

tag_env=(env REGION=us-east-1 VERSION=source123 ENVIRONMENT=staging RUN_ID=987 RUN_ATTEMPT=3 DEPLOY_DATE_OVERRIDE=20261110 IMAGES_OVERRIDE="image-a image-b")
run_case tag-absent pass "$TAG_SCRIPT" "${tag_env[@]}"
[ "$(wc -l <"$FIXTURE/tag-absent/puts" | tr -d ' ')" = 2 ] || { echo "FAIL: absent deployment markers were not both created"; exit 1; }
grep -Fq 'image-a|deployed-staging-20261110-source123-987-3' "$FIXTURE/tag-absent/puts" || { echo "FAIL: deployment marker is not unique per run and attempt"; exit 1; }

run_case tag-same pass "$TAG_SCRIPT" "${tag_env[@]}" TAG_EXISTING=all
[ ! -e "$FIXTURE/tag-same/puts" ] || { echo "FAIL: same-digest deployment marker was rewritten"; exit 1; }
grep -q 'write skipped' "$FIXTURE/tag-same/output" || { echo "FAIL: deployment same-digest skip was not reported"; exit 1; }

run_case tag-partial pass "$TAG_SCRIPT" "${tag_env[@]}" TAG_EXISTING=partial
[ "$(wc -l <"$FIXTURE/tag-partial/puts" | tr -d ' ')" = 1 ] || { echo "FAIL: deployment marker partial retry did not write exactly one missing tag"; exit 1; }
grep -Fq 'image-b|deployed-staging-20261110-source123-987-3' "$FIXTURE/tag-partial/puts" || { echo "FAIL: deployment marker partial retry wrote the wrong image"; exit 1; }

# Model the source tag moving from digest A to digest B after the first
# describe-images call. A tag-based manifest fetch would write B, then discover
# the poisoned immutable marker only on readback. The helper must instead fetch
# both manifests through the already-resolved digest A and complete safely.
run_case tag-source-moved pass "$TAG_SCRIPT" "${tag_env[@]}" TAG_SOURCE_MOVED=1
[ "$(wc -l <"$FIXTURE/tag-source-moved/puts" | tr -d ' ')" = 2 ] || { echo "FAIL: digest-pinned source movement case did not write both exact markers"; exit 1; }
if grep -Fq 'imageTag=source123' "$FIXTURE/tag-source-moved/manifests"; then
  echo "FAIL: source movement case fetched a manifest through the mutable tag"
  exit 1
fi
[ "$(grep -Fc "imageDigest=$MOCK_SOURCE_DIGEST" "$FIXTURE/tag-source-moved/manifests")" = 2 ] || { echo "FAIL: source movement case did not fetch every manifest through the resolved digest"; exit 1; }
if grep -Fq "$MOCK_DRIFT_DIGEST" "$FIXTURE/tag-source-moved/puts"; then
  echo "FAIL: source movement poisoned an immutable deployment marker"
  exit 1
fi

# If the manifest at the resolved digest disappears or becomes unreadable,
# destination-wide preflight must fail before any marker is written.
run_case tag-source-moved-pinned-missing fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_SOURCE_MOVED=1 TAG_PINNED_MANIFEST_MISSING=1
[ ! -e "$FIXTURE/tag-source-moved-pinned-missing/puts" ] || { echo "FAIL: unavailable pinned source manifest allowed a deployment-marker write"; exit 1; }
grep -q 'has no readable manifest' "$FIXTURE/tag-source-moved-pinned-missing/output" || { echo "FAIL: unavailable pinned source manifest was not reported"; exit 1; }

run_case tag-mismatch fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_MISMATCH=1
[ ! -e "$FIXTURE/tag-mismatch/puts" ] || { echo "FAIL: marker collision allowed a partial write"; exit 1; }
grep -q 'immutable marker collision' "$FIXTURE/tag-mismatch/output" || { echo "FAIL: marker collision was not identified"; exit 1; }

run_case tag-readback-drift fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_READBACK_DRIFT=1
grep -q 'exact readback failed' "$FIXTURE/tag-readback-drift/output" || { echo "FAIL: marker readback drift was not identified"; exit 1; }

run_case tag-missing-source fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_MISSING_SOURCE=1
[ ! -e "$FIXTURE/tag-missing-source/puts" ] || { echo "FAIL: missing source allowed a marker write"; exit 1; }

run_case tag-lookup-denied fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_LOOKUP_DENIED=1
[ ! -e "$FIXTURE/tag-lookup-denied/puts" ] || { echo "FAIL: denied marker lookup was mistaken for absence"; exit 1; }
grep -q 'digest lookup failed' "$FIXTURE/tag-lookup-denied/output" || { echo "FAIL: denied marker lookup was not reported"; exit 1; }

run_case tag-manifest-denied fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_MANIFEST_DENIED=1
[ ! -e "$FIXTURE/tag-manifest-denied/puts" ] || { echo "FAIL: denied manifest lookup allowed a marker write"; exit 1; }
grep -q 'manifest lookup failed' "$FIXTURE/tag-manifest-denied/output" || { echo "FAIL: denied manifest lookup was not reported"; exit 1; }

run_case tag-put-failure fail "$TAG_SCRIPT" "${tag_env[@]}" TAG_PUT_FAIL=1

market_env=(env SOURCE_ACCOUNT=111111111111 SOURCE_REGION=eu-central-1 MARKETPLACE_ACCOUNT=222222222222 MARKETPLACE_REGION=us-east-1 SHA=abcdef0123456789abcdef0123456789abcdef01 VERSION=1.2.3 IMAGES_OVERRIDE="image-a image-b")
run_case market-absent pass "$MARKET_SCRIPT" "${market_env[@]}"
[ "$(wc -l <"$FIXTURE/market-absent/creates" | tr -d ' ')" = 2 ] || { echo "FAIL: absent Marketplace tags were not both pushed"; exit 1; }
grep -Fq '/image-a@sha256:1111111111111111111111111111111111111111111111111111111111111111' "$FIXTURE/market-absent/creates" || { echo "FAIL: Marketplace copy did not pin the source digest"; exit 1; }

run_case market-same pass "$MARKET_SCRIPT" "${market_env[@]}" MARKET_EXISTING=all
[ ! -e "$FIXTURE/market-same/creates" ] || { echo "FAIL: same-digest Marketplace tags were rewritten"; exit 1; }
grep -q 'write skipped' "$FIXTURE/market-same/output" || { echo "FAIL: Marketplace same-digest skip was not reported"; exit 1; }

run_case market-partial pass "$MARKET_SCRIPT" "${market_env[@]}" MARKET_EXISTING=partial
[ "$(wc -l <"$FIXTURE/market-partial/creates" | tr -d ' ')" = 1 ] || { echo "FAIL: Marketplace partial retry did not push exactly one missing tag"; exit 1; }
grep -Fq '/image-b:1.2.3|' "$FIXTURE/market-partial/creates" || { echo "FAIL: Marketplace partial retry pushed the wrong image"; exit 1; }

run_case market-mismatch fail "$MARKET_SCRIPT" "${market_env[@]}" MARKET_MISMATCH=1
[ ! -e "$FIXTURE/market-mismatch/creates" ] || { echo "FAIL: Marketplace collision allowed a partial write"; exit 1; }
grep -q 'immutable Marketplace collision' "$FIXTURE/market-mismatch/output" || { echo "FAIL: Marketplace collision was not identified"; exit 1; }

run_case market-lookup-denied fail "$MARKET_SCRIPT" "${market_env[@]}" MARKET_LOOKUP_DENIED=1
[ ! -e "$FIXTURE/market-lookup-denied/creates" ] || { echo "FAIL: denied Marketplace lookup was mistaken for absence"; exit 1; }
grep -q 'Marketplace digest lookup failed' "$FIXTURE/market-lookup-denied/output" || { echo "FAIL: denied Marketplace lookup was not reported"; exit 1; }

run_case market-readback-drift fail "$MARKET_SCRIPT" "${market_env[@]}" MARKET_READBACK_DRIFT=1
grep -q 'exact Marketplace readback failed' "$FIXTURE/market-readback-drift/output" || { echo "FAIL: Marketplace readback drift was not identified"; exit 1; }

run_case market-bad-source fail "$MARKET_SCRIPT" "${market_env[@]}" MARKET_BAD_SOURCE_DIGEST=1
[ ! -e "$FIXTURE/market-bad-source/creates" ] || { echo "FAIL: invalid source digest allowed a Marketplace write"; exit 1; }

run_case market-bad-sha fail "$MARKET_SCRIPT" env SOURCE_ACCOUNT=111111111111 SOURCE_REGION=eu-central-1 MARKETPLACE_ACCOUNT=222222222222 MARKETPLACE_REGION=us-east-1 SHA=abcdef VERSION=1.2.3 IMAGES_OVERRIDE="image-a image-b"
[ ! -e "$FIXTURE/market-bad-sha/creates" ] || { echo "FAIL: invalid source SHA allowed a Marketplace write"; exit 1; }

run_case market-push-failure fail "$MARKET_SCRIPT" "${market_env[@]}" MARKET_PUSH_FAIL=1

python3 - "$ROOT/technical-docs/runbooks/RUNBOOK_MARKETPLACE_VERSION_RELEASE.md" "$FIXTURE/marketplace-verify.sh" <<'PY'
from pathlib import Path
import re
import sys

runbook = Path(sys.argv[1]).read_text()
match = re.search(r"### Verify Images \(required\)\n```bash\n(.*?)\n```", runbook, re.DOTALL)
assert match, "Marketplace required-verification block is missing"
Path(sys.argv[2]).write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + match.group(1) + "\n")
PY
chmod +x "$FIXTURE/marketplace-verify.sh"

run_case marketplace-runbook-exact pass "$FIXTURE/marketplace-verify.sh" env VERSION=1.2.3 MARKET_DOC_MODE=exact
run_case marketplace-runbook-missing-exact fail "$FIXTURE/marketplace-verify.sh" env VERSION=1.2.3 MARKET_DOC_MODE=missing-exact
grep -q 'exact Marketplace tag axonflow-prometheus:1.2.3 is missing or unreadable' "$FIXTURE/marketplace-runbook-missing-exact/output" || { echo "FAIL: Marketplace runbook did not reject a missing exact tag"; exit 1; }
run_case marketplace-runbook-neighbor-only fail "$FIXTURE/marketplace-verify.sh" env VERSION=1.2.3 MARKET_DOC_MODE=neighbor-only
grep -q 'exact Marketplace tag axonflow-prometheus:1.2.3 is missing or unreadable' "$FIXTURE/marketplace-runbook-neighbor-only/output" || { echo "FAIL: Marketplace runbook accepted a substring-only neighboring tag"; exit 1; }
run_case marketplace-runbook-invalid-digest fail "$FIXTURE/marketplace-verify.sh" env VERSION=1.2.3 MARKET_DOC_MODE=invalid-digest
grep -q 'invalid digest for exact Marketplace tag axonflow-grafana:1.2.3' "$FIXTURE/marketplace-runbook-invalid-digest/output" || { echo "FAIL: Marketplace runbook accepted an invalid exact-tag digest"; exit 1; }

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
active = [
    root / "scripts/ci/replicate-ecr-image.sh",
    root / "scripts/deployment/auto-deploy-cloudformation.sh",
    root / "scripts/deployment/lib/push.sh",
    root / "scripts/marketplace/setup-production-ecr-regions.sh",
]
for path in active:
    text = path.read_text()
    logical_lines = []
    current = ""
    for line in text.splitlines():
        current += line.strip() + " "
        if line.rstrip().endswith("\\"):
            continue
        logical_lines.append(current.strip())
        current = ""
    commands = [line for line in logical_lines if "aws ecr create-repository" in line]
    assert commands, f"{path}: active ECR creation path disappeared from the census"
    for command in commands:
        assert "--image-tag-mutability IMMUTABLE" in command, (
            f"{path}: ECR creation is not explicitly immutable: {command}"
        )

deploy = (root / ".github/workflows/deploy-platform.yml").read_text()
market = (root / ".github/workflows/marketplace-push.yml").read_text()
deployment_runbook = (root / "technical-docs/runbooks/RUNBOOK_DEPLOYMENT.md").read_text()
deployment_guide = (root / "technical-docs/DEPLOYMENT_GUIDE.md").read_text()
marketplace_runbook = (root / "technical-docs/runbooks/RUNBOOK_MARKETPLACE_VERSION_RELEASE.md").read_text()
marketplace_helper = (root / ".github/scripts/copy-images-to-marketplace.sh").read_text()
marketplace_provisioner = (root / "scripts/marketplace/setup-production-ecr-regions.sh").read_text()
assert ".github/scripts/tag-deployed-images.sh" in deploy
assert "RUN_ID: ${{ github.run_id }}" in deploy
assert "RUN_ATTEMPT: ${{ github.run_attempt }}" in deploy
assert ".github/scripts/copy-images-to-marketplace.sh" in market
assert "permissions:\n  contents: read" in market
assert 'SOURCE_REF: ${{ github.ref }}' in market
assert 'marketplace-push.yml@refs/heads/main' in market
marker_shape = "deployed-<environment>-<YYYYMMDD>-<version>-<run_id>-<run_attempt>"
assert marker_shape in deployment_runbook
assert marker_shape in deployment_guide
assert 'DEPLOY_TAG="deployed-${ENVIRONMENT}-$(date +%Y%m%d)"' not in deployment_runbook
assert ".github/scripts/tag-deployed-images.sh" in deployment_runbook
assert '-f source_sha="${SOURCE_SHA}"' in marketplace_runbook
assert '-f source_region="${SOURCE_REGION}"' in marketplace_runbook
assert "push_to_marketplace" not in marketplace_runbook
assert ".github/scripts/copy-images-to-marketplace.sh" in marketplace_runbook
assert "build-and-push-marketplace.sh" not in marketplace_runbook
marketplace_repositories = [
    "axonflow-agent",
    "axonflow-orchestrator",
    "axonflow-customer-portal",
    "axonflow-customer-portal-ui",
    "axonflow-performance-testing",
    "axonflow-grafana",
    "axonflow-prometheus",
]
repository_words = " ".join(marketplace_repositories)
assert f"IMAGES=({repository_words})" in marketplace_helper
assert f"for img in {repository_words}; do" in marketplace_runbook
provisioner_block = re.search(
    r"(?ms)^REPOSITORIES=\(\n(.*?)^\)", marketplace_provisioner
)
assert provisioner_block, "Marketplace provisioner repository census is missing"
provisioned_repositories = re.findall(
    r'^\s*"([^"]+)"', provisioner_block.group(1), re.MULTILINE
)
assert provisioned_repositories == marketplace_repositories, (
    "Marketplace provisioner must create the exact ordered publisher census: "
    f"expected={marketplace_repositories}, actual={provisioned_repositories}"
)
assert '--image-ids imageTag="${VERSION}"' in marketplace_runbook
assert "imageDetails[0].imageDigest" in marketplace_runbook
assert "contains(@" not in marketplace_runbook
assert "^sha256:[0-9a-f]{64}$" in marketplace_runbook
assert len(marketplace_repositories) == 7
PY

echo "PASS: immutable ECR retries skip exact tags, refuse collisions, verify readback, and create immutable repositories"
