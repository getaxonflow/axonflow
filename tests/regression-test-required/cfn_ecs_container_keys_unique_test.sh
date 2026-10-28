#!/usr/bin/env bash
set -euo pipefail

checker=scripts/testing/check-cfn-ecs-container-keys.py
templates=(
  ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml
  infrastructure/cloudformation/community-saas-ecs.yaml
)

python3 "$checker" --self-test
python3 "$checker" "${templates[@]}"
