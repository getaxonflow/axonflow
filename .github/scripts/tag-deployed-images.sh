#!/usr/bin/env bash
# Add one unique, immutable deployment marker to each deployed ECR image.
set -euo pipefail

: "${REGION:?REGION is required}"
: "${VERSION:?VERSION is required}"
: "${ENVIRONMENT:?ENVIRONMENT is required}"
: "${RUN_ID:?RUN_ID is required}"
: "${RUN_ATTEMPT:?RUN_ATTEMPT is required}"

DEPLOY_DATE="${DEPLOY_DATE_OVERRIDE:-$(date -u +%Y%m%d)}"
SAFE_VERSION="${VERSION//:/-}"
DEPLOY_TAG="deployed-${ENVIRONMENT}-${DEPLOY_DATE}-${SAFE_VERSION}-${RUN_ID}-${RUN_ATTEMPT}"
[[ "$DEPLOY_TAG" =~ ^[A-Za-z0-9_.-]+$ ]] || {
  echo "FATAL: generated deployment tag is not ECR-safe: $DEPLOY_TAG" >&2
  exit 1
}

if [ -n "${IMAGES_OVERRIDE:-}" ]; then
  read -r -a IMAGES <<<"$IMAGES_OVERRIDE"
else
  IMAGES=(axonflow-agent axonflow-orchestrator axonflow-customer-portal axonflow-customer-portal-ui axonflow-case-workflows axonflow-prometheus axonflow-grafana)
fi
[ "${#IMAGES[@]}" -gt 0 ] || { echo "FATAL: no images selected" >&2; exit 1; }

valid_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

describe_digest() {
  local output status
  set +e
  output="$(aws ecr describe-images \
    --repository-name "$1" \
    --region "$REGION" \
    --image-ids "$2" \
    --query 'imageDetails[0].imageDigest' \
    --output text 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
  elif [[ "$output" == *ImageNotFoundException* ]]; then
    printf '\n'
  else
    echo "FATAL: ECR digest lookup failed for $1 ($2): $output" >&2
    return "$status"
  fi
}

source_manifest() {
  local output status
  set +e
  output="$(aws ecr batch-get-image \
    --repository-name "$1" \
    --region "$REGION" \
    --image-ids "$2" \
    --query 'images[0].imageManifest' \
    --output text 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
  elif [[ "$output" == *ImageNotFoundException* ]]; then
    printf '\n'
  else
    echo "FATAL: ECR manifest lookup failed for $1 ($2): $output" >&2
    return "$status"
  fi
}

declare -A SOURCE_DIGEST SOURCE_MANIFEST DESTINATION_PRESENT
preflight_failed=0

echo "🏷️  Preflighting immutable deployment marker: $DEPLOY_TAG"
for image in "${IMAGES[@]}"; do
  if [[ "$VERSION" == sha256:* ]]; then
    source_id="imageDigest=$VERSION"
  else
    source_id="imageTag=$VERSION"
  fi

  source_digest="$(describe_digest "$image" "$source_id")"
  if ! valid_digest "$source_digest"; then
    echo "FATAL: $image source selector $VERSION is absent or has invalid digest '$source_digest'" >&2
    preflight_failed=1
    continue
  fi

  # The source tag can move after describe_digest resolves it. Fetch by the
  # immutable digest we just validated so a later tag update cannot give this
  # marker a different manifest and poison an immutable destination tag.
  manifest="$(source_manifest "$image" "imageDigest=$source_digest")"
  if [ -z "$manifest" ] || [ "$manifest" = "None" ]; then
    echo "FATAL: $image source selector $VERSION has no readable manifest" >&2
    preflight_failed=1
    continue
  fi

  destination_digest="$(describe_digest "$image" "imageTag=$DEPLOY_TAG")"
  if [ -n "$destination_digest" ] && [ "$destination_digest" != "None" ]; then
    if ! valid_digest "$destination_digest"; then
      echo "FATAL: $image:$DEPLOY_TAG returned invalid digest '$destination_digest'" >&2
      preflight_failed=1
      continue
    fi
    if [ "$destination_digest" != "$source_digest" ]; then
      echo "FATAL: immutable marker collision for $image:$DEPLOY_TAG (existing=$destination_digest expected=$source_digest)" >&2
      preflight_failed=1
      continue
    fi
    DESTINATION_PRESENT[$image]=1
  else
    DESTINATION_PRESENT[$image]=0
  fi
  SOURCE_DIGEST[$image]="$source_digest"
  SOURCE_MANIFEST[$image]="$manifest"
done

[ "$preflight_failed" -eq 0 ] || {
  echo "ABORT: deployment-marker preflight failed before any ECR write." >&2
  exit 1
}

for image in "${IMAGES[@]}"; do
  if [ "${DESTINATION_PRESENT[$image]}" -eq 1 ]; then
    echo "  $image:$DEPLOY_TAG already matches ${SOURCE_DIGEST[$image]}; write skipped"
  else
    aws ecr put-image \
      --repository-name "$image" \
      --region "$REGION" \
      --image-tag "$DEPLOY_TAG" \
      --image-manifest "${SOURCE_MANIFEST[$image]}" >/dev/null
    echo "  $image:$DEPLOY_TAG created"
  fi

  readback="$(describe_digest "$image" "imageTag=$DEPLOY_TAG")"
  if [ "$readback" != "${SOURCE_DIGEST[$image]}" ]; then
    echo "FATAL: exact readback failed for $image:$DEPLOY_TAG (readback=${readback:-<missing>} expected=${SOURCE_DIGEST[$image]})" >&2
    exit 1
  fi
  echo "  $image:$DEPLOY_TAG verified at $readback"
done

echo "✅ All ${#IMAGES[@]} deployment markers are exact: $DEPLOY_TAG"
