#!/usr/bin/env bash
set -euo pipefail

# Preview and apply must build the RLS switch and both database-role secret
# parameters from the same inputs. Keeping dispatch expressions in env also
# prevents user-supplied values from becoming executable shell source and
# keeps either run block below GitHub's expression compiler limit.

python3 - <<'PY'
from pathlib import Path
import re

workflow = Path(".github/workflows/update-stack.yml").read_text()


def step(name: str) -> tuple[str, str]:
    marker = f"      - name: {name}\n"
    start = workflow.index(marker)
    boundary = re.search(r"(?m)^(?:      - |  [A-Za-z][A-Za-z0-9_-]*:\s*$)", workflow[start + len(marker):])
    end = start + len(marker) + boundary.start() if boundary else len(workflow)
    body = workflow[start:end]
    run_marker = "        run: |\n"
    run_start = body.index(run_marker) + len(run_marker)
    return body[:run_start], body[run_start:]


required_env = {
    "APP_ROLE_PROVISIONED_INPUT",
    "DB_APP_ROLE_URL_SECRET_ARN_INPUT",
    "DB_PLATFORM_ADMIN_URL_SECRET_ARN_INPUT",
}
required_run_fragments = {
    'CONFIG_PARAMS[AppRoleProvisioned]="$APP_ROLE_PROVISIONED_INPUT"',
    'resolve_role_secret "$DB_APP_ROLE_URL_SECRET_ARN_INPUT" db_app_role_url',
    'resolve_role_secret "$DB_PLATFORM_ADMIN_URL_SECRET_ARN_INPUT" db_platform_admin_url',
    'CONFIG_PARAMS[DBAppRoleURLSecretArn]="$DB_APP_ROLE_URL_SECRET_ARN_INPUT"',
    'CONFIG_PARAMS[DBPlatformAdminURLSecretArn]="$DB_PLATFORM_ADMIN_URL_SECRET_ARN_INPUT"',
}

for name in ("Create change set preview", "Build parameters file"):
    header, run = step(name)
    missing_env = sorted(key for key in required_env if f"          {key}:" not in header)
    missing_run = sorted(fragment for fragment in required_run_fragments if fragment not in run)
    assert not missing_env, f"{name}: missing env mappings: {missing_env}"
    assert not missing_run, f"{name}: missing RLS parameter wiring: {missing_run}"
    assert "${{" not in run, f"{name}: GitHub expressions must not be embedded in shell source"
    assert "set -euo pipefail" in run, f"{name}: shell must fail closed"

print("PASS: update-stack preview/apply RLS parameter wiring is symmetric and shell-safe")
PY
