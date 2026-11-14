#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATOR="$ROOT/.github/scripts/validate-image-attestation-index.py"
PROMOTER="$ROOT/.github/scripts/promote-verified-image.py"
COMPLETION="$ROOT/.github/scripts/promotion-completion.py"
RESOLVER="$ROOT/.github/scripts/resolve-trusted-image.py"
SELECTOR="$ROOT/.github/scripts/validate-image-selector.py"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
source_commit="$(git -C "$ROOT" rev-parse HEAD)"
repository="123456789012.dkr.ecr.us-east-1.amazonaws.com/axonflow-case-workflows"
source_repository="getaxonflow/axonflow-enterprise" workflow=".github/workflows/build.yml"
source_ref="refs/heads/main" run_id=123 run_attempt=1

[[ "$(python3 "$SELECTOR" abc1234)" == "abc1234" ]]
[[ "$(python3 "$SELECTOR" "sha256:$(printf 'a%.0s' {1..64})")" == "sha256:$(printf 'a%.0s' {1..64})" ]]
[[ "$(python3 "$SELECTOR" --full-sha-only "$source_commit")" == "$source_commit" ]]
assert_selector_invalid() { if python3 "$SELECTOR" "$1" >"$WORK/selector.log" 2>&1; then echo "FAIL: accepted mutable selector $1" >&2; exit 1; fi; grep -q 'image selector must be' "$WORK/selector.log"; }
assert_selector_invalid latest
assert_selector_invalid main-latest
assert_selector_invalid v11.4.0
if python3 "$SELECTOR" --tag-only "sha256:$(printf 'a%.0s' {1..64})" >"$WORK/selector-tag-only.log" 2>&1; then
  echo "FAIL: tag-only path accepted an image digest" >&2
  exit 1
fi
for invalid in abc1234 "sha256:$(printf 'a%.0s' {1..64})"; do
  if python3 "$SELECTOR" --full-sha-only "$invalid" >"$WORK/selector-full-sha.log" 2>&1; then
    echo "FAIL: full-SHA-only path accepted $invalid" >&2
    exit 1
  fi
  grep -q 'full lowercase 40-character Git SHA' "$WORK/selector-full-sha.log"
done

python3 - "$WORK/receipt" "$source_commit" "$repository" <<'PY'
import datetime, hashlib, json, pathlib, sys
root, source, repository = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
children, now = {}, datetime.datetime.now(datetime.timezone.utc).isoformat()
for arch in ("amd64", "arm64"):
    config = root / "children" / arch / "config.json"
    config_digest = put(config, {"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}})
    child = root / "children" / arch / "manifest.json"
    children[arch] = put(child, {"schemaVersion": 2, "config": {"digest": config_digest}, "layers": []})
    layers = []
    for kind in ("provenance", "sbom"):
        ptype = "https://slsa.dev/provenance/v1" if kind == "provenance" else "https://spdx.dev/Document"
        body = ({"buildDefinition": {"externalParameters": {"request": {"root": {"request": {"args": {"vcs:revision": source}}}}}}, "runDetails": {"metadata": {"buildkit_metadata": {"vcs": {"revision": source}}}}} if kind == "provenance" else {"spdxVersion": "SPDX-2.3"})
        temp = root / "predicates" / f"{arch}-{kind}.json"
        digest = put(temp, {"_type": "https://in-toto.io/Statement/v1", "predicateType": ptype, "subject": [{"digest": {"sha256": children[arch][7:]}}], "predicate": body})
        final = root / "predicates" / f"{digest[7:]}.json"; temp.rename(final)
        layers.append({"mediaType": "application/vnd.in-toto+json", "digest": digest, "annotations": {"in-toto.io/predicate-type": ptype}})
    temp = root / "attestations" / f"{arch}.json"
    children[arch + "_att"] = put(temp, {"schemaVersion": 2, "layers": layers})
    temp.rename(root / "attestations" / f"{children[arch + '_att'][7:]}.json")
    vr = root / "vulnerability" / arch
    put(vr / "report.json", {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"RepoDigests": [repository + "@" + children[arch]], "ImageConfig": {"architecture": arch, "os": "linux"}}, "Results": [{"Target": arch, "Vulnerabilities": None}]})
    put(vr / "scanner-version.json", {"Version": "0.70.0"}); put(vr / "db-metadata.json", {"Version": 2, "UpdatedAt": now})
    names = ("report.json", "scanner-version.json", "db-metadata.json")
    put(vr / "disposition.json", {"status": "pass", "architecture": arch, "image_digest": children[arch], "source_commit": source, "scanned_at": now, "evidence": {n: hashlib.sha256((vr / n).read_bytes()).hexdigest() for n in names}})
manifests=[]
for arch in ("amd64", "arm64"):
    manifests += [{"digest": children[arch], "platform": {"os": "linux", "architecture": arch}}, {"digest": children[arch + "_att"], "platform": {"os": "unknown", "architecture": "unknown"}, "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": children[arch]}}]
digest=put(root/"index.json", {"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":manifests}); (root/"index-digest").write_text(digest)
PY
index_digest="$(cat "$WORK/receipt/index-digest")"
validate=(python3 "$VALIDATOR" --index "$WORK/receipt/index.json" --expected-index-digest "$index_digest" --children-dir "$WORK/receipt/children" --attestations-dir "$WORK/receipt/attestations" --predicates-dir "$WORK/receipt/predicates" --expected-source-commit "$source_commit" --vulnerability-dir "$WORK/receipt/vulnerability")
"${validate[@]}" --receipt-manifest "$WORK/receipt/receipt-manifest.json" --image-repository "$repository" --index-digest "$index_digest" --source-repository "$source_repository" --workflow "$workflow" --source-ref "$source_ref" --run-id "$run_id" --run-attempt "$run_attempt"

assert_invalid() { local label="$1" expected="$2"; shift 2; if "$@" >"$WORK/$label.log" 2>&1; then echo "FAIL: accepted $label" >&2; exit 1; fi; grep -q "$expected" "$WORK/$label.log"; }
cp "$WORK/receipt/index.json" "$WORK/original"; jq '.manifests[2].digest=.manifests[0].digest | .manifests[3].annotations["vnd.docker.reference.digest"]=.manifests[0].digest' "$WORK/original" > "$WORK/receipt/index.json"
same="sha256:$(shasum -a 256 "$WORK/receipt/index.json" | awk '{print $1}')"; same_validate=("${validate[@]}"); same_validate[5]="$same"
assert_invalid same-child 'distinct manifest digests' "${same_validate[@]}"; mv "$WORK/original" "$WORK/receipt/index.json"
cp "$WORK/receipt/children/amd64/config.json" "$WORK/config-original"; cp "$WORK/receipt/children/amd64/manifest.json" "$WORK/child-original"; cp "$WORK/receipt/index.json" "$WORK/index-original"
jq '.architecture="arm64"' "$WORK/config-original" > "$WORK/receipt/children/amd64/config.json"
config_digest="sha256:$(shasum -a 256 "$WORK/receipt/children/amd64/config.json" | awk '{print $1}')"
jq --arg digest "$config_digest" '.config.digest=$digest' "$WORK/child-original" > "$WORK/receipt/children/amd64/manifest.json"
child_digest="sha256:$(shasum -a 256 "$WORK/receipt/children/amd64/manifest.json" | awk '{print $1}')"
jq --arg digest "$child_digest" '.manifests[0].digest=$digest | .manifests[1].annotations["vnd.docker.reference.digest"]=$digest' "$WORK/index-original" > "$WORK/receipt/index.json"
swapped_index="sha256:$(shasum -a 256 "$WORK/receipt/index.json" | awk '{print $1}')"; swapped_validate=("${validate[@]}"); swapped_validate[5]="$swapped_index"
assert_invalid swapped-platform 'config declares a different platform' "${swapped_validate[@]}"
mv "$WORK/config-original" "$WORK/receipt/children/amd64/config.json"; mv "$WORK/child-original" "$WORK/receipt/children/amd64/manifest.json"; mv "$WORK/index-original" "$WORK/receipt/index.json"
for target in index.json children/amd64/manifest.json "attestations/$(find "$WORK/receipt/attestations" -type f -maxdepth 1 | head -1 | xargs basename)" "predicates/$(find "$WORK/receipt/predicates" -type f -maxdepth 1 | head -1 | xargs basename)"; do
  cp "$WORK/receipt/$target" "$WORK/original"; printf ' ' >> "$WORK/receipt/$target"; assert_invalid "blob-${target//\//-}" 'bytes do not match' "${validate[@]}"; mv "$WORK/original" "$WORK/receipt/$target"
done
cp "$WORK/receipt/vulnerability/amd64/disposition.json" "$WORK/original"; jq '.scanned_at="2020-01-01T00:00:00+00:00"' "$WORK/original" > "$WORK/receipt/vulnerability/amd64/disposition.json"
assert_invalid stale-vuln 'evidence is stale' "${validate[@]}"; mv "$WORK/original" "$WORK/receipt/vulnerability/amd64/disposition.json"

planted_vulnerability_negative() {
  local label="$1" file="$2" filter="$3" expected="$4" root="$WORK/receipt/vulnerability/amd64"
  cp "$root/$file" "$WORK/evidence-original"; cp "$root/disposition.json" "$WORK/disposition-original"
  jq "$filter" "$WORK/evidence-original" > "$root/$file"
  local evidence_hash; evidence_hash="$(shasum -a 256 "$root/$file" | awk '{print $1}')"
  jq --arg file "$file" --arg digest "$evidence_hash" '.evidence[$file]=$digest' "$WORK/disposition-original" > "$root/disposition.json"
  assert_invalid "$label" "$expected" "${validate[@]}"
  mv "$WORK/evidence-original" "$root/$file"; mv "$WORK/disposition-original" "$root/disposition.json"
}
planted_vulnerability_negative stale-db db-metadata.json '.UpdatedAt="2020-01-01T00:00:00Z"' 'database is stale'
planted_vulnerability_negative attacker-scanner scanner-version.json '.Version="0.0.0-attacker"' 'scanner identity is unapproved'
planted_vulnerability_negative empty-results report.json '.Results=[]' 'results are vacuous'
planted_vulnerability_negative malformed-results report.json '.Results=[{"Vulnerabilities":[]}]' 'results are vacuous'
planted_vulnerability_negative wrong-target report.json '.Metadata.ImageConfig.architecture="arm64"' 'report platform is invalid'
planted_vulnerability_negative wrong-digest report.json '.Metadata.RepoDigests=["example.invalid/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]' 'not bound to'

cp "$WORK/receipt/vulnerability/amd64/report.json" "$WORK/original"; printf ' ' >> "$WORK/receipt/vulnerability/amd64/report.json"
assert_invalid tampered-vuln 'evidence was tampered' "${validate[@]}"; mv "$WORK/original" "$WORK/receipt/vulnerability/amd64/report.json"
mv "$WORK/receipt/vulnerability/arm64/report.json" "$WORK/missing-report.json"
assert_invalid missing-vuln 'evidence is missing' "${validate[@]}"; mv "$WORK/missing-report.json" "$WORK/receipt/vulnerability/arm64/report.json"

python3 - "$ROOT/.github/workflows/build.yml" <<'PY'
import pathlib,sys,yaml
root=pathlib.Path(sys.argv[1]).parents[2]
d=yaml.safe_load(pathlib.Path(sys.argv[1]).read_text()); b=d["jobs"]["build"]["steps"]; m=d["jobs"]["merge"]["steps"]
image=next(s for s in b if s.get("uses")=="docker/build-push-action@v7"); assert image["with"]["provenance"]=="mode=max" and image["with"]["sbom"] is True
metadata=next(s for s in d["jobs"]["plan"]["steps"] if s.get("name")=="Generate build metadata")["run"]
assert "git rev-parse --short" not in metadata
assert ".github/scripts/release-build-plan.py" in metadata
assert '--github-output "$GITHUB_OUTPUT"' in metadata
assert "authorize-build-publication.sh" in metadata
assert 'EVENT_NAME' in metadata and 'EVENT_REPOSITORY' in metadata and 'EVENT_REF' in metadata
matrix=next(s for s in d["jobs"]["plan"]["steps"] if s.get("name")=="Compute image matrix")["run"]
assert ".github/scripts/release-build-plan.py" in matrix
generator=(root / ".github/scripts/release-build-plan.py").read_text()
for image in ("agent", "orchestrator", "customer-portal", "customer-portal-ui", "prometheus", "grafana", "performance-testing", "gateway-adapters", "case-workflows"):
    assert f'"name": "{image}"' in generator
for job_name in ("detect-changes", "plan", "build", "merge"):
    checkouts = [s for s in d["jobs"][job_name]["steps"] if s.get("uses") == "actions/checkout@v6"]
    assert checkouts and all(s.get("with", {}).get("ref") == "${{ github.sha }}" for s in checkouts)
build_aws=[s for s in d["jobs"]["build"]["steps"] if str(s.get("uses", "")).startswith("aws-actions/configure-aws-credentials@")]
merge_aws=[s for s in d["jobs"]["merge"]["steps"] if str(s.get("uses", "")).startswith("aws-actions/configure-aws-credentials@")]
assert build_aws and all(s.get("if") == "needs.plan.outputs.push == 'true'" for s in build_aws)
assert merge_aws
assert "needs.plan.outputs.push == 'true'" in d["jobs"]["merge"]["if"]
iam=(root / "infra/iam/github-actions-roles.yaml").read_text()
assert "repo:getaxonflow/axonflow-enterprise:ref:refs/heads/main" in iam
assert "repo:getaxonflow/axonflow:ref:refs/heads/main" in iam
assert "repo:getaxonflow/axonflow-enterprise:*" not in iam
assert "repo:getaxonflow/axonflow:*" not in iam
assert "StringLike:" not in iam
scan=next(s for s in b if str(s.get("uses","")).startswith("aquasecurity/trivy-action@")); assert scan["uses"].endswith("ed142fd0673e97e23eac54620cfb913e5ce36c25") and scan["with"]["format"]=="json" and scan["with"]["exit-code"]=="1"
att=[s for s in m if str(s.get("uses","")).startswith("actions/attest-build-provenance@")]; assert len(att)==3 and all(s["uses"].endswith("977bb373ede98d70efdf65b84cb5f73e068dcc2a") for s in att)
names=[s.get("name") for s in m]
promote_step=names.index("Verify signed receipt, promote exact digest, and write completion")
sign_completion=names.index("Sign completed promotion receipt")
verify_completion=names.index("Verify completed promotion admission")
retain=names.index("Retain immutable image receipts")
assert promote_step < sign_completion < verify_completion < retain
assert "concurrency" not in d["jobs"]["merge"]
workflow=pathlib.Path(sys.argv[1]).read_text()
assert ".github/scripts/promotion-completion.py" in workflow
promoter=(pathlib.Path(sys.argv[1]).parent.parent / "scripts" / "promote-verified-image.py").read_text()
assert "--mutable-tag" not in workflow and "--mutable-tag" not in promoter
assert '--shared-immutable-tag "$SHORT_SHA"' in workflow
assert "branch-latest" not in workflow and "latest-on-main" not in workflow
assert "${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" in workflow
immutable=next(i for i,s in enumerate(m) if s.get("name")=="Require immutable ECR repository")
quarantine=next(i for i,s in enumerate(m) if s.get("name")=="Create quarantined multi-arch manifest list")
assert immutable < quarantine and '!= "IMMUTABLE"' in m[immutable]["run"]
deploy=yaml.safe_load((root / ".github/workflows/deploy-application.yml").read_text())
prepare=deploy["jobs"]["prepare"]["steps"]
determine=next(s for s in prepare if s.get("name")=="Determine version")["run"]
verify=next(s for s in prepare if s.get("name")=="Verify images exist in ECR")["run"]
deploy_text=(root / ".github/workflows/deploy-application.yml").read_text()
assert "validate-image-selector.py" in determine and "validate-image-selector.py" in verify
assert '!= "IMMUTABLE"' in verify and "imageDetails[0].imageDigest" in verify
assert "gh attestation verify" in verify and "validate-client-image-admission.py" in verify
assert "--signer-workflow" in verify and ".github/workflows/build.yml" in verify
assert "--subject-name" in verify and "--source-ref refs/heads/main" in verify
assert "Skipping ECR validation" not in deploy_text and "version='latest'" not in deploy_text
assert "main-latest" not in deploy_text and "branch-latest" not in deploy_text
assert "axonflow-agent@${IMAGE_DIGEST}" in deploy_text
assert "${RUN_ID}-${RUN_ATTEMPT}" in deploy_text
assert "COMPLETED PROMOTION ADMISSION MISSING" in deploy_text
assert "promotion-completion.py write" in deploy_text
assert "promotion-completion.py \"${completion_parser_args[@]}\"" in deploy_text
deploy_platform_path=root / ".github/workflows/deploy-platform.yml"
deploy_platform=yaml.safe_load(deploy_platform_path.read_text())
deploy_platform_text=deploy_platform_path.read_text()
assert deploy_platform["permissions"]["attestations"] == "read"
prepare_images=deploy_platform["jobs"]["prepare-images"]["steps"]
platform_names=[step.get("name") for step in prepare_images]
platform_checkout=next(step for step in prepare_images if step.get("uses")=="actions/checkout@v6")
assert platform_checkout["with"]["ref"] == "${{ github.sha }}"
assert platform_checkout["with"]["fetch-depth"] == 0
authority=platform_names.index("Require trusted main workflow revision")
configure_aws=platform_names.index("Configure AWS credentials")
check_existing=platform_names.index("Check existing images in ECR")
refuse_direct=platform_names.index("Refuse direct image builds without completed promotion admission")
first_direct_build=platform_names.index("Set up Docker Buildx")
assert authority < configure_aws
assert check_existing < refuse_direct < first_direct_build
assert "COMPLETED PROMOTION ADMISSION MISSING" in deploy_text
assert "completed promotion admission missing" in deploy_platform_text
assert "run build.yml on trusted main" in deploy_platform_text
update_stack_path=root / ".github/workflows/update-stack.yml"
update_stack=yaml.safe_load(update_stack_path.read_text())
update_text=update_stack_path.read_text()
assert update_stack["permissions"]["attestations"] == "read"
update_prepare=update_stack["jobs"]["prepare"]
update_checkout=next(step for step in update_prepare["steps"] if step.get("uses")=="actions/checkout@v6")
assert update_checkout["with"] == {"ref": "${{ github.sha }}", "fetch-depth": 0}
update_names=[step.get("name") for step in update_prepare["steps"]]
admit_index=update_names.index("Admit exact image overrides")
assert admit_index < update_names.index("Upload template to S3")
admit=update_prepare["steps"][admit_index]
assert "resolve-trusted-image.py" in admit["run"]
assert "refs/heads/main" in admit["run"] and "update-stack.yml@refs/heads/main" in admit["run"]
assert "git merge-base --is-ancestor" in admit["run"]
raw_inputs=(
    "performance_testing", "agent", "orchestrator", "customer_portal",
    "customer_portal_ui", "case_workflows", "prometheus", "grafana",
)
for name in raw_inputs:
    raw=f"${{{{ inputs.{name}_image_tag }}}}"
    assert update_text.count(raw) == 1, (name, "raw input must be consumed only by central admission")
    admitted=f"${{{{ needs.prepare.outputs.{name}_image_tag }}}}"
    assert update_text.count(admitted) == 2, (name, "dry-run and apply must consume the same admitted output")
assert "steps.admitted_images.outputs.agent" in update_prepare["outputs"]["agent_image_tag"]
# Consumer audit: core build.yml images are admitted by deploy-application,
# deploy-platform, and update-stack. deploy-clients is a distinct
# build-client-images.yml contract; marketplace-test consumes already-curated
# Marketplace release identities; marketplace-push is a publisher, not a
# deployment consumer; scheduled-performance-benchmark only reads a live tag.
deployment_consumers={
    "deploy-application.yml": "COMPLETED PROMOTION ADMISSION MISSING",
    "deploy-platform.yml": "completed promotion admission missing",
    "update-stack.yml": "resolve-trusted-image.py",
    "deploy-clients.yml": "build-client-images.yml",
}
for filename, guard in deployment_consumers.items():
    assert guard in (root / ".github/workflows" / filename).read_text()
for workflow_path in (
    root / ".github/workflows/build.yml",
    root / ".github/workflows/build-client-images.yml",
    root / ".github/workflows/deploy-clients.yml",
    root / ".github/workflows/deploy-application.yml",
):
    parsed = yaml.safe_load(workflow_path.read_text())
    configured = [
        step
        for job in parsed["jobs"].values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("aws-actions/configure-aws-credentials@")
    ]
    assert configured and all("allowed-account-ids" in step["with"] for step in configured)
PY

# The same provider-neutral plan/receipt board is part of the required image
# admission regression, including dirty source, tree/edition/matrix drift,
# mixed-build, replay, stale scanner and OCI child-platform negatives.
python3 "$ROOT/.github/scripts/test_ci_down_admission.py"

authority="$ROOT/.github/scripts/authorize-build-publication.sh"
[[ "$(bash "$authority" push getaxonflow/axonflow-enterprise refs/heads/main "$source_commit" "$source_commit")" == "true" ]]
[[ "$(bash "$authority" workflow_dispatch getaxonflow/axonflow-enterprise refs/heads/feature/hostile "$source_commit" "$source_commit")" == "false" ]]
[[ "$(bash "$authority" push getaxonflow/axonflow-enterprise refs/heads/develop "$source_commit" "$source_commit")" == "false" ]]
if bash "$authority" push getaxonflow/axonflow-enterprise refs/heads/main "$source_commit" "$(printf '0%.0s' {1..40})" >"$WORK/wrong-checkout.log" 2>&1; then
  echo "FAIL: publication authority accepted a checkout different from the workflow SHA" >&2
  exit 1
fi
grep -q "checkout is not the workflow's exact full SHA" "$WORK/wrong-checkout.log"

# ECR IMMUTABLE is the atomic authority for same-short-SHA reruns. Both
# publishers pass a simultaneous empty preflight, but only one digest can win
# the repository's compare-and-create operation; the loser cannot overwrite it.
python3 - <<'PY'
import threading
barrier = threading.Barrier(2)
lock = threading.Lock()
tag = {}
results = []
def publish(digest):
    assert "same123" not in tag
    barrier.wait()
    with lock:
        if "same123" in tag:
            results.append((digest, False))
        else:
            tag["same123"] = digest
            results.append((digest, True))
threads = [threading.Thread(target=publish, args=("sha256:" + char * 64,)) for char in ("a", "b")]
for thread in threads: thread.start()
for thread in threads: thread.join()
assert sorted(success for _, success in results) == [False, True]
assert tag["same123"] in {"sha256:" + "a" * 64, "sha256:" + "b" * 64}
PY

receipt_digest="$(shasum -a 256 "$WORK/receipt/receipt-manifest.json" | awk '{print $1}')"
write_admission() { local dst="$1" subject="${2#sha256:}" rid="${3:-$run_id}" attempt="${4:-$run_attempt}"; jq -n --arg s "$subject" --arg r "https://github.com/$source_repository" --arg w "$workflow" --arg ref "$source_ref" --arg b "https://github.com/$source_repository/$workflow@main" --arg i "https://github.com/$source_repository/actions/runs/$rid/attempts/$attempt" --arg c "$source_commit" '[{verificationResult:{signature:{certificate:{subjectAlternativeName:$b}},verifiedTimestamps:[{}],statement:{subject:[{digest:{sha256:$s}}],predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:$r,path:$w,ref:$ref}},internalParameters:{github:{runner_environment:"github-hosted"}},resolvedDependencies:[{digest:{gitCommit:$c}}]},runDetails:{builder:{id:$b},metadata:{invocationId:$i}}}}}}]' > "$dst"; }
write_admission "$WORK/receipt/image-admission.json" "$index_digest"; write_admission "$WORK/receipt/receipt-admission.json" "sha256:$receipt_digest"; cp "$WORK/receipt/image-admission.json" "$WORK/receipt/image-admission-under-test.json"

completion_manifest="$WORK/receipt/promotion-completion.json"
completion_admission="$WORK/receipt/promotion-completion-admission.json"
python3 "$COMPLETION" write --output "$completion_manifest" --repository "$repository" --digest "$index_digest"
completion_digest="$(shasum -a 256 "$completion_manifest" | awk '{print $1}')"
write_admission "$completion_admission" "sha256:$completion_digest"
python3 "$COMPLETION" verify --manifest "$completion_manifest" --verification "$completion_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"
cp "$completion_admission" "$WORK/completion-admission-original"
jq '.[0].verificationResult.statement.predicate.runDetails.builder.id="https://github.com/attacker/repo/.github/workflows/build.yml@main"' "$WORK/completion-admission-original" > "$completion_admission"
assert_invalid completion-wrong-builder 'trusted workflow/source identity' python3 "$COMPLETION" verify --manifest "$completion_manifest" --verification "$completion_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"
jq '.[0].verificationResult.statement.predicate.buildDefinition.internalParameters.github.runner_environment="self-hosted"' "$WORK/completion-admission-original" > "$completion_admission"
assert_invalid completion-self-hosted 'trusted workflow/source identity' python3 "$COMPLETION" verify --manifest "$completion_manifest" --verification "$completion_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"
mv "$WORK/completion-admission-original" "$completion_admission"
cp "$completion_manifest" "$WORK/completion-original"
jq '.promotion_status="pending"' "$WORK/completion-original" > "$completion_manifest"
assert_invalid incomplete-completion 'not canonical or does not match' python3 "$COMPLETION" verify --manifest "$completion_manifest" --verification "$completion_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"
mv "$WORK/completion-original" "$completion_manifest"

mkdir -p "$WORK/bin" "$WORK/tags"
export MOCK_TAG_DIR="$WORK/tags" MOCK_LOG="$WORK/registry.log" MOCK_MARKERS="$WORK/markers"
mkdir -p "$MOCK_MARKERS"
cat > "$WORK/bin/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >> "$MOCK_LOG"
if [[ "$1 $2" == "ecr describe-repositories" ]]; then
  if [[ -f "$MOCK_MARKERS/mutable-repository" ]]; then echo MUTABLE; else echo IMMUTABLE; fi
elif [[ "$1 $2" == "ecr describe-images" ]]; then
  tag=""; for arg in "$@"; do [[ "$arg" == imageTag=* ]] && tag="${arg#imageTag=}"; done
  if [[ -f "$MOCK_MARKERS/enable-race" && "$tag" == "${MOCK_RACE_TAG:-}" && ! -f "$MOCK_MARKERS/race-seen-$PPID" ]]; then
    touch "$MOCK_MARKERS/race-seen-$PPID"
    for _ in {1..500}; do
      arrivals=$(find "$MOCK_MARKERS" -name 'race-seen-*' -type f | wc -l | tr -d ' ')
      if [[ "$arrivals" -ge 2 ]]; then touch "$MOCK_MARKERS/race-released"; break; fi
      sleep 0.01
    done
    [[ -f "$MOCK_MARKERS/race-released" ]] || { echo "race barrier timed out" >&2; exit 70; }
    echo ImageNotFoundException >&2
    exit 254
  fi
  if [[ -f "$MOCK_MARKERS/bad-count-$tag" ]]; then
    count="$(cat "$MOCK_MARKERS/bad-count-$tag")"
    if [[ "$count" -le 1 ]]; then rm "$MOCK_MARKERS/bad-count-$tag"; else printf '%s\n' "$((count - 1))" > "$MOCK_MARKERS/bad-count-$tag"; fi
    printf 'sha256:%064d\n' 8
    exit 0
  fi
  if [[ -f "$MOCK_MARKERS/unavailable-count-$tag" ]]; then
    count="$(cat "$MOCK_MARKERS/unavailable-count-$tag")"
    if [[ "$count" -le 1 ]]; then rm "$MOCK_MARKERS/unavailable-count-$tag"; else printf '%s\n' "$((count - 1))" > "$MOCK_MARKERS/unavailable-count-$tag"; fi
    echo ServiceUnavailableException >&2
    exit 255
  fi
  if [[ -f "$MOCK_MARKERS/bad-$tag" ]]; then rm "$MOCK_MARKERS/bad-$tag"; printf 'sha256:%064d\n' 8; exit 0; fi
  if [[ -f "$MOCK_TAG_DIR/$tag" ]]; then cat "$MOCK_TAG_DIR/$tag"; else echo ImageNotFoundException >&2; exit 254; fi
elif [[ "$1 $2" == "ecr batch-delete-image" ]]; then
  for arg in "$@"; do [[ "$arg" == imageTag=* ]] && rm -f "$MOCK_TAG_DIR/${arg#imageTag=}"; done
else exit 2; fi
SH
cat > "$WORK/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
source="${!#}"; digest="${source##*@}"; tags=(); while (($#)); do if [[ "$1" == "-t" ]]; then tags+=("${2##*:}"); shift 2; else shift; fi; done
for tag in "${tags[@]}"; do
  lock="$MOCK_TAG_DIR/.lock-$tag"
  for _ in {1..500}; do mkdir "$lock" 2>/dev/null && break; sleep 0.01; done
  [[ -d "$lock" ]] || { echo "tag lock timed out" >&2; exit 70; }
  if [[ -f "$MOCK_MARKERS/fail-before-$tag" ]]; then
    rm "$MOCK_MARKERS/fail-before-$tag"
    rmdir "$lock"
    exit 1
  fi
  if [[ -f "$MOCK_TAG_DIR/$tag" ]]; then rmdir "$lock"; echo "ImageTagAlreadyExistsException" >&2; exit 1; fi
  printf '%s\n' "$digest" > "$MOCK_TAG_DIR/$tag"
  rmdir "$lock"
  if [[ -f "$MOCK_MARKERS/partial-$tag" ]]; then rm "$MOCK_MARKERS/partial-$tag"; exit 1; fi
  if [[ -f "$MOCK_MARKERS/arm-bad-readback" && "$tag" == "$MOCK_BAD_READBACK_TAG" ]]; then
    rm "$MOCK_MARKERS/arm-bad-readback"
    printf '8\n' > "$MOCK_MARKERS/bad-count-$MOCK_BAD_READBACK_TAG"
  fi
  if [[ -f "$MOCK_MARKERS/arm-shared-transient-readback" && "$tag" == "$MOCK_SHARED_TAG" ]]; then
    rm "$MOCK_MARKERS/arm-shared-transient-readback"
    touch "$MOCK_MARKERS/bad-$MOCK_SHARED_TAG"
  fi
  if [[ -f "$MOCK_MARKERS/arm-shared-unavailable-readback" && "$tag" == "$MOCK_SHARED_TAG" ]]; then
    rm "$MOCK_MARKERS/arm-shared-unavailable-readback"
    printf '8\n' > "$MOCK_MARKERS/unavailable-count-$MOCK_SHARED_TAG"
  fi
done
SH
cat > "$WORK/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == "attestation verify" ]] || exit 2
subject=$3
if [[ "$subject" == oci://* ]]; then
  [[ ! -f "$MOCK_MARKERS/resolver-missing-image-admission" ]] || { echo "no image attestation" >&2; exit 1; }
  image="${subject#oci://}"; image="${image%@*}"
  digest="${subject##*@}"; hash="${digest#sha256:}"
  name_args=(--arg name "$image")
else
  [[ ! -f "$MOCK_MARKERS/resolver-missing-completion-admission" ]] || { echo "no completion attestation" >&2; exit 1; }
  hash="$(shasum -a 256 "$subject" | awk '{print $1}')"
  if [[ -f "$MOCK_MARKERS/resolver-tampered-completion-admission" ]]; then hash="$(printf 'f%.0s' {1..64})"; fi
  name_args=(--arg name "$(basename "$subject")")
fi
jq -n \
  --arg hash "$hash" \
  "${name_args[@]}" \
  --arg source "https://github.com/$MOCK_SOURCE_REPOSITORY" \
  --arg workflow ".github/workflows/build.yml" \
  --arg ref "refs/heads/main" \
  --arg builder "https://github.com/$MOCK_SOURCE_REPOSITORY/.github/workflows/build.yml@refs/heads/main" \
  --arg invocation "https://github.com/$MOCK_SOURCE_REPOSITORY/actions/runs/123/attempts/1" \
  --arg commit "$MOCK_SOURCE_COMMIT" \
  '[{verificationResult:{signature:{certificate:{subjectAlternativeName:$builder}},verifiedTimestamps:[{}],statement:{subject:[{name:$name,digest:{sha256:$hash}}],predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:$source,path:$workflow,ref:$ref}},internalParameters:{github:{runner_environment:"github-hosted"}},resolvedDependencies:[{digest:{gitCommit:$commit}}]},runDetails:{builder:{id:$builder},metadata:{invocationId:$invocation}}}}}}]'
SH
chmod +x "$WORK/bin/aws" "$WORK/bin/docker" "$WORK/bin/gh"
export MOCK_SOURCE_COMMIT="$source_commit" MOCK_SOURCE_REPOSITORY="$source_repository"

# The same resolver invoked by update-stack refuses a stranded short-SHA tag
# unless both the exact image provenance and the post-promotion completion
# admission exist and bind the same trusted main commit and digest.
resolver_repository=axonflow-case-workflows
resolver_registry="${repository%/"$resolver_repository"}"
printf '%s\n' "$index_digest" > "$MOCK_TAG_DIR/${source_commit:0:7}"
resolver=(python3 -I "$RESOLVER" --trust-mode github-actions-v1 --registry "$resolver_registry" --admission-registry "$resolver_registry" --repository "$resolver_repository" --region us-east-1 --selector "${source_commit:0:7}" --source-repository "$source_repository" --source-commit "$source_commit" --evidence-dir "$WORK/resolver-evidence")
[[ "$(PATH="$WORK/bin:$PATH" "${resolver[@]}")" == "$index_digest" ]]
touch "$MOCK_MARKERS/resolver-missing-completion-admission"
assert_invalid update-stack-stranded-short-sha 'command failed: gh: no completion attestation' env PATH="$WORK/bin:$PATH" "${resolver[@]}"
rm "$MOCK_MARKERS/resolver-missing-completion-admission"
touch "$MOCK_MARKERS/resolver-tampered-completion-admission"
assert_invalid update-stack-tampered-completion 'completed promotion admission is missing' env PATH="$WORK/bin:$PATH" "${resolver[@]}"
rm "$MOCK_MARKERS/resolver-tampered-completion-admission"
touch "$MOCK_MARKERS/resolver-missing-image-admission"
assert_invalid update-stack-missing-image-admission 'command failed: gh: no image attestation' env PATH="$WORK/bin:$PATH" "${resolver[@]}"
rm "$MOCK_MARKERS/resolver-missing-image-admission"
promote_base=(python3 -I "$PROMOTER" --trust-mode github-actions-v1 --repository "$repository" --ecr-repository-name axonflow-case-workflows --digest "$index_digest" --receipt-manifest "$WORK/receipt/receipt-manifest.json" --image-admission "$WORK/receipt/image-admission-under-test.json" --receipt-admission "$WORK/receipt/receipt-admission.json" --source-repository "$source_repository" --source-commit "$source_commit" --workflow "$workflow" --source-ref "$source_ref" --run-id "$run_id" --run-attempt "$run_attempt" --verifier-path "$VALIDATOR")
timestamp_tag=20261109-000000-123-1
promote=("${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag "$timestamp_tag")
export MOCK_BAD_READBACK_TAG=20261109-000002-125-1
export MOCK_SHARED_TAG="${source_commit:0:7}"

# Build a second, independently admitted index for the same source commit. A
# nondeterministic rerun must not replace the first digest behind the shared
# short-SHA tag, even when both publishers pass preflight concurrently.
cp -R "$WORK/receipt" "$WORK/receipt-race-b"
jq '.annotations={"test.variant":"race-b"}' "$WORK/receipt/index.json" > "$WORK/receipt-race-b/index.json"
race_b_digest="sha256:$(shasum -a 256 "$WORK/receipt-race-b/index.json" | awk '{print $1}')"
race_b_index_hash="${race_b_digest#sha256:}"
jq --arg digest "$race_b_digest" --arg rid 124 --arg hash "$race_b_index_hash" \
  '.index_digest=$digest | .run_id=$rid | (.evidence[] | select(.name=="index.json") | .sha256)=$hash' \
  "$WORK/receipt/receipt-manifest.json" > "$WORK/receipt-race-b/receipt-manifest.json"
write_admission "$WORK/receipt-race-b/image-admission.json" "$race_b_digest" 124
race_b_receipt_digest="$(shasum -a 256 "$WORK/receipt-race-b/receipt-manifest.json" | awk '{print $1}')"
write_admission "$WORK/receipt-race-b/receipt-admission.json" "sha256:$race_b_receipt_digest" 124
race_b=(python3 -I "$PROMOTER" --trust-mode github-actions-v1 --repository "$repository" --ecr-repository-name axonflow-case-workflows --digest "$race_b_digest" --receipt-manifest "$WORK/receipt-race-b/receipt-manifest.json" --image-admission "$WORK/receipt-race-b/image-admission.json" --receipt-admission "$WORK/receipt-race-b/receipt-admission.json" --source-repository "$source_repository" --source-commit "$source_commit" --workflow "$workflow" --source-ref "$source_ref" --run-id 124 --run-attempt 1 --verifier-path "$VALIDATOR" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag 20261109-000010-124-1)
race_a=("${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag 20261109-000010-123-1)

export MOCK_RACE_TAG="${source_commit:0:7}"
touch "$MOCK_MARKERS/enable-race"; rm -f "$MOCK_MARKERS"/race-seen-* "$MOCK_MARKERS/race-released"
set +e
PATH="$WORK/bin:$PATH" "${race_a[@]}" >"$WORK/race-a.log" 2>&1 & race_a_pid=$!
PATH="$WORK/bin:$PATH" "${race_b[@]}" >"$WORK/race-b.log" 2>&1 & race_b_pid=$!
wait "$race_a_pid"; race_a_status=$?
wait "$race_b_pid"; race_b_status=$?
set -e
race_successes=0
if [[ "$race_a_status" -eq 0 ]]; then race_successes=$((race_successes + 1)); fi
if [[ "$race_b_status" -eq 0 ]]; then race_successes=$((race_successes + 1)); fi
[[ "$race_successes" -eq 1 ]]
winner_digest="$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")"
[[ "$winner_digest" == "$index_digest" || "$winner_digest" == "$race_b_digest" ]]
[[ "$winner_digest" == "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" ]]

# Same-commit, same-digest overlap may lose the atomic tag race, but must never
# delete the winner's shared tag. Its exact retry then creates only its own
# run-distinct tag and both runs remain independently traceable.
rm -f "$MOCK_TAG_DIR"/* "$MOCK_MARKERS"/race-seen-* "$MOCK_MARKERS/race-released"
cp -R "$WORK/receipt" "$WORK/receipt-race-same"
jq --arg rid 125 '.run_id=$rid' "$WORK/receipt/receipt-manifest.json" > "$WORK/receipt-race-same/receipt-manifest.json"
write_admission "$WORK/receipt-race-same/image-admission.json" "$index_digest" 125
race_same_receipt_digest="$(shasum -a 256 "$WORK/receipt-race-same/receipt-manifest.json" | awk '{print $1}')"
write_admission "$WORK/receipt-race-same/receipt-admission.json" "sha256:$race_same_receipt_digest" 125
race_same=(python3 -I "$PROMOTER" --trust-mode github-actions-v1 --repository "$repository" --ecr-repository-name axonflow-case-workflows --digest "$index_digest" --receipt-manifest "$WORK/receipt-race-same/receipt-manifest.json" --image-admission "$WORK/receipt-race-same/image-admission.json" --receipt-admission "$WORK/receipt-race-same/receipt-admission.json" --source-repository "$source_repository" --source-commit "$source_commit" --workflow "$workflow" --source-ref "$source_ref" --run-id 125 --run-attempt 1 --verifier-path "$VALIDATOR" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag 20261109-000011-125-1)
race_same_a=("${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag 20261109-000011-123-1)
rm -f "$MOCK_MARKERS"/race-seen-* "$MOCK_MARKERS/race-released"; touch "$MOCK_MARKERS/enable-race"
set +e
PATH="$WORK/bin:$PATH" "${race_same_a[@]}" >"$WORK/race-same-a.log" 2>&1 & race_same_a_pid=$!
PATH="$WORK/bin:$PATH" "${race_same[@]}" >"$WORK/race-same-b.log" 2>&1 & race_same_b_pid=$!
wait "$race_same_a_pid"; race_same_a_status=$?
wait "$race_same_b_pid"; race_same_b_status=$?
set -e
[[ "$race_same_a_status" -eq 0 && "$race_same_b_status" -eq 0 ]]
[[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" ]]
rm -f "$MOCK_MARKERS/enable-race" "$MOCK_MARKERS"/race-seen-* "$MOCK_MARKERS/race-released"
[[ "$(cat "$MOCK_TAG_DIR/20261109-000011-123-1")" == "$index_digest" ]]
[[ "$(cat "$MOCK_TAG_DIR/20261109-000011-125-1")" == "$index_digest" ]]

# Reset the isolated registry fixture before the remaining promotion cases.
rm -f "$MOCK_TAG_DIR"/* "$MOCK_MARKERS"/race-seen-* "$MOCK_MARKERS/race-released"

# Shared mutable tags are structurally unsupported and cannot re-enter through
# a caller without failing before any registry read or write.
: > "$MOCK_LOG"; assert_invalid mutable-tag-option 'unrecognized arguments' env PATH="$WORK/bin:$PATH" "${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag x777777 --mutable-tag latest; [[ ! -s "$MOCK_LOG" ]]

jq '.[0].verificationResult.statement.predicate.runDetails.builder.id="https://github.com/attacker/repo/.github/workflows/build.yml@main"' "$WORK/receipt/image-admission.json" > "$WORK/receipt/image-admission-under-test.json"
: > "$MOCK_LOG"; assert_invalid wrong-builder 'trusted signed workflow identity' env PATH="$WORK/bin:$PATH" "${promote[@]}"; [[ ! -s "$MOCK_LOG" ]]
cp "$WORK/receipt/image-admission.json" "$WORK/receipt/image-admission-under-test.json"
cp "$WORK/receipt/vulnerability/amd64/scanner-version.json" "$WORK/scanner-original"; printf ' ' >> "$WORK/receipt/vulnerability/amd64/scanner-version.json"
: > "$MOCK_LOG"; assert_invalid receipt-tamper 'evidence digest mismatch' env PATH="$WORK/bin:$PATH" "${promote[@]}"; [[ ! -s "$MOCK_LOG" ]]; mv "$WORK/scanner-original" "$WORK/receipt/vulnerability/amd64/scanner-version.json"

touch "$MOCK_MARKERS/mutable-repository"; : > "$MOCK_LOG"
assert_invalid mutable-repository 'immutable tags are required' env PATH="$WORK/bin:$PATH" "${promote[@]}"
! grep -q '^docker ' "$MOCK_LOG"; rm "$MOCK_MARKERS/mutable-repository"

: > "$MOCK_LOG"; PATH="$WORK/bin:$PATH" "${promote[@]}"
for tag in "${source_commit:0:7}" "$timestamp_tag"; do [[ "$(cat "$MOCK_TAG_DIR/$tag")" == "$index_digest" ]]; done
[[ ! -e "$MOCK_TAG_DIR/main-latest" && ! -e "$MOCK_TAG_DIR/latest" ]]
# Exact retry performs readback only and does not republish.
: > "$MOCK_LOG"; PATH="$WORK/bin:$PATH" "${promote[@]}"; ! grep -q '^docker ' "$MOCK_LOG"
# Immutable collision refuses before mutation.
old="sha256:$(printf '7%.0s' {1..64})"; printf '%s\n' "$old" > "$MOCK_TAG_DIR/${source_commit:0:7}"; : > "$MOCK_LOG"
assert_invalid immutable-collision 'refusing overwrite' env PATH="$WORK/bin:$PATH" "${promote[@]}"; [[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$old" ]]; ! grep -q '^docker ' "$MOCK_LOG"
printf '%s\n' "$index_digest" > "$MOCK_TAG_DIR/${source_commit:0:7}"
# The run-owned tag is admitted first and the shared deployable identity is the
# final commit point. A failure before that commit rolls the run-owned tag back
# and leaves no deployable short-SHA behind.
rm -f "$MOCK_TAG_DIR/${source_commit:0:7}"
absent_run_tag=20261109-000001-124-1
absent_promote=("${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag "$absent_run_tag")
touch "$MOCK_MARKERS/fail-before-${source_commit:0:7}"
assert_invalid absent-shared-partial 'returned non-zero' env PATH="$WORK/bin:$PATH" "${absent_promote[@]}"
[[ ! -e "$MOCK_TAG_DIR/${source_commit:0:7}" && ! -e "$MOCK_TAG_DIR/$absent_run_tag" ]]

# A lost client response after the shared tag landed is resolved by immutable
# readback. The run succeeds, so a deployable tag can never belong to a run
# reported as rejected.
touch "$MOCK_MARKERS/partial-${source_commit:0:7}"
PATH="$WORK/bin:$PATH" "${absent_promote[@]}"
[[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" ]]
[[ "$(cat "$MOCK_TAG_DIR/$absent_run_tag")" == "$index_digest" ]]
: > "$MOCK_LOG"; PATH="$WORK/bin:$PATH" "${absent_promote[@]}"; ! grep -q '^docker ' "$MOCK_LOG"

# A transient stale/error read immediately after the shared write is retried;
# exact readback still commits the run instead of reporting a rejected run
# with a deployable tag.
rm -f "$MOCK_TAG_DIR/${source_commit:0:7}" "$MOCK_TAG_DIR/$absent_run_tag"
touch "$MOCK_MARKERS/arm-shared-transient-readback"
PATH="$WORK/bin:$PATH" "${absent_promote[@]}"
[[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" ]]
[[ "$(cat "$MOCK_TAG_DIR/$absent_run_tag")" == "$index_digest" ]]

# Persistent registry-read failure after the shared write is fundamentally
# ambiguous: the promoter rejects and rolls back its run-owned tag, but cannot
# safely delete a shared tag another same-digest publisher may own. Deployment
# therefore requires the later signed completion admission, not bare tag state.
rm -f "$MOCK_TAG_DIR/${source_commit:0:7}" "$MOCK_TAG_DIR/$absent_run_tag"
touch "$MOCK_MARKERS/arm-shared-unavailable-readback"
assert_invalid persistent-shared-read 'cannot verify promoted tag' env PATH="$WORK/bin:$PATH" "${absent_promote[@]}"
[[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" ]]
[[ ! -e "$MOCK_TAG_DIR/$absent_run_tag" ]]
missing_completion="$WORK/process-death/promotion-completion.json"
missing_admission="$WORK/process-death/promotion-completion-admission.json"
assert_invalid stranded-tag-unadmitted 'cannot read completed promotion admission' python3 "$COMPLETION" verify --manifest "$missing_completion" --verification "$missing_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"

# A process death after successful registry promotion but before the completion
# attestation has the same fail-closed result. Only the deterministic manifest
# plus trusted signed admission makes the exact digest deployable.
rm -f "$MOCK_TAG_DIR/${source_commit:0:7}" "$MOCK_TAG_DIR/$absent_run_tag"
PATH="$WORK/bin:$PATH" "${absent_promote[@]}"
assert_invalid process-death-unadmitted 'cannot read completed promotion admission' python3 "$COMPLETION" verify --manifest "$missing_completion" --verification "$missing_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"
mkdir -p "$(dirname "$missing_completion")"
python3 "$COMPLETION" write --output "$missing_completion" --repository "$repository" --digest "$index_digest"
missing_completion_digest="$(shasum -a 256 "$missing_completion" | awk '{print $1}')"
write_admission "$missing_admission" "sha256:$missing_completion_digest"
python3 "$COMPLETION" verify --manifest "$missing_completion" --verification "$missing_admission" --repository "$repository" --digest "$index_digest" --source-repository "$source_repository" --source-ref "$source_ref" --source-commit "$source_commit"

# A post-create readback mismatch is also rolled back without touching other tags.
bad_promote=("${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag "$MOCK_BAD_READBACK_TAG")
touch "$MOCK_MARKERS/arm-bad-readback"
assert_invalid bad-readback 'read back as' env PATH="$WORK/bin:$PATH" "${bad_promote[@]}"
[[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" && ! -e "$MOCK_TAG_DIR/$MOCK_BAD_READBACK_TAG" ]]
rm -f "$MOCK_MARKERS/bad-count-$MOCK_BAD_READBACK_TAG"

# Three reruns retain disjoint per-run immutable identities while converging on
# the same immutable short-SHA identity. There is no mutable alias or queue.
for publisher in a b c; do
  case "$publisher" in
    a) run_tag=20261109-000003-201-1 ;;
    b) run_tag=20261109-000003-202-1 ;;
    c) run_tag=20261109-000003-203-1 ;;
  esac
  PATH="$WORK/bin:$PATH" "${promote_base[@]}" --shared-immutable-tag "${source_commit:0:7}" --immutable-tag "$run_tag"
  [[ "$(cat "$MOCK_TAG_DIR/${source_commit:0:7}")" == "$index_digest" ]]
  [[ "$(cat "$MOCK_TAG_DIR/$run_tag")" == "$index_digest" ]]
done

echo 'ok: OCI bytes, architecture, vulnerability evidence, signed admission, and immutable promotion fail closed'
