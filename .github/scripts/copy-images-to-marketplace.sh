#!/usr/bin/env bash
# Copy already-built images to immutable Marketplace release tags, safely resumable.
set -euo pipefail

: "${SOURCE_ACCOUNT:?SOURCE_ACCOUNT is required}"
: "${SOURCE_REGION:?SOURCE_REGION is required}"
: "${MARKETPLACE_ACCOUNT:?MARKETPLACE_ACCOUNT is required}"
: "${MARKETPLACE_REGION:?MARKETPLACE_REGION is required}"
: "${SHA:?SHA is required}"
: "${VERSION:?VERSION is required}"

[[ "$VERSION" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || {
  echo "FATAL: VERSION is not an ECR-safe tag: $VERSION" >&2
  exit 1
}
[[ "$SHA" =~ ^[0-9a-f]{7,40}$ ]] || {
  echo "FATAL: SHA is not a lowercase 7-40 character Git SHA: $SHA" >&2
  exit 1
}

SOURCE="${SOURCE_ACCOUNT}.dkr.ecr.${SOURCE_REGION}.amazonaws.com"
DEST="${MARKETPLACE_ACCOUNT}.dkr.ecr.${MARKETPLACE_REGION}.amazonaws.com/axonflow"
if [ -n "${IMAGES_OVERRIDE:-}" ]; then
  read -r -a IMAGES <<<"$IMAGES_OVERRIDE"
else
  IMAGES=(axonflow-agent axonflow-orchestrator axonflow-customer-portal axonflow-customer-portal-ui axonflow-performance-testing axonflow-grafana axonflow-prometheus)
fi
[ "${#IMAGES[@]}" -gt 0 ] || { echo "FATAL: no images selected" >&2; exit 1; }

valid_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

destination_digest() {
  local output status
  set +e
  output="$(aws ecr describe-images \
    --registry-id "$MARKETPLACE_ACCOUNT" \
    --repository-name "axonflow/$1" \
    --image-ids "imageTag=$VERSION" \
    --region "$MARKETPLACE_REGION" \
    --query 'imageDetails[0].imageDigest' \
    --output text 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
  elif [[ "$output" == *ImageNotFoundException* ]]; then
    printf '\n'
  else
    echo "FATAL: Marketplace digest lookup failed for axonflow/$1:$VERSION: $output" >&2
    return "$status"
  fi
}

declare -A SOURCE_DIGEST DESTINATION_PRESENT
preflight_failed=0

echo "Preflighting immutable Marketplace copy from $SOURCE:$SHA to $DEST:$VERSION"
for image in "${IMAGES[@]}"; do
  source_ref="${SOURCE}/${image}:${SHA}"
  source_digest="$(docker buildx imagetools inspect "$source_ref" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
  if ! valid_digest "$source_digest"; then
    echo "FATAL: could not resolve an exact source digest for $source_ref" >&2
    preflight_failed=1
    continue
  fi

  existing="$(destination_digest "$image")"
  if [ -n "$existing" ] && [ "$existing" != "None" ]; then
    if ! valid_digest "$existing"; then
      echo "FATAL: axonflow/$image:$VERSION returned invalid digest '$existing'" >&2
      preflight_failed=1
      continue
    fi
    if [ "$existing" != "$source_digest" ]; then
      echo "FATAL: immutable Marketplace collision for axonflow/$image:$VERSION (existing=$existing expected=$source_digest)" >&2
      preflight_failed=1
      continue
    fi
    DESTINATION_PRESENT[$image]=1
  else
    DESTINATION_PRESENT[$image]=0
  fi
  SOURCE_DIGEST[$image]="$source_digest"
done

[ "$preflight_failed" -eq 0 ] || {
  echo "ABORT: Marketplace immutability preflight failed before any destination write." >&2
  exit 1
}

for image in "${IMAGES[@]}"; do
  source_ref="${SOURCE}/${image}:${SHA}"
  destination_ref="${DEST}/${image}:${VERSION}"
  if [ "${DESTINATION_PRESENT[$image]}" -eq 1 ]; then
    echo "  $destination_ref already matches ${SOURCE_DIGEST[$image]}; write skipped"
  else
    docker buildx imagetools create \
      --tag "$destination_ref" \
      "${SOURCE}/${image}@${SOURCE_DIGEST[$image]}" >/dev/null
    echo "  $destination_ref pushed"
  fi

  readback="$(destination_digest "$image")"
  if [ "$readback" != "${SOURCE_DIGEST[$image]}" ]; then
    echo "FATAL: exact Marketplace readback failed for $destination_ref (readback=${readback:-<missing>} expected=${SOURCE_DIGEST[$image]})" >&2
    exit 1
  fi
  echo "  $destination_ref verified at $readback"
done

echo "✅ All ${#IMAGES[@]} Marketplace tags are exact for version $VERSION"
