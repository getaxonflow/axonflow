#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

cfn-lint infrastructure/cloudformation/ci-down-release-builders.yaml
python3 .github/scripts/test_ci_down_provider_infrastructure.py
python3 -m py_compile \
  .github/scripts/ci_down_provider.py \
  .github/scripts/ci_down_dispatch.py \
  .github/scripts/test_ci_down_provider_infrastructure.py
bash -n \
  infrastructure/ci-down-release/run-native-phase.sh \
  infrastructure/ci-down-release/run-promoter-phase.sh
