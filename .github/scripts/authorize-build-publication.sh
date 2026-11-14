#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: $0 EVENT REPOSITORY REF EXPECTED_SHA CHECKED_OUT_SHA" >&2
  exit 64
fi

event_name="$1"
repository="$2"
ref="$3"
expected_sha="$4"
checked_out_sha="$5"

if [[ ! "$expected_sha" =~ ^[0-9a-f]{40}$ || "$checked_out_sha" != "$expected_sha" ]]; then
  echo "build publication authority denied: checkout is not the workflow's exact full SHA" >&2
  exit 1
fi

if [[ "$event_name" == "push" &&
      "$repository" == "getaxonflow/axonflow-enterprise" &&
      "$ref" == "refs/heads/main" ]]; then
  printf 'true\n'
else
  printf 'false\n'
fi
