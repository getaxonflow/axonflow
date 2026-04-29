# GitHub Actions IAM Roles — CloudFormation

This directory codifies the two IAM roles that GitHub Actions assumes:

| Role | Purpose | Used by |
|---|---|---|
| `GitHubActionsECRRole` | Push Docker images to ECR | `.github/workflows/build.yml` |
| `GitHubActionsInfraRole` | Drive CloudFormation infra deploys | `.github/workflows/deploy-infrastructure.yml` |

Both roles trust the GitHub OIDC provider for `getaxonflow/axonflow` and `getaxonflow/axonflow-enterprise`.

The template is `github-actions-roles.yaml`. Stack name: `axonflow-github-actions-roles` (already imported and live as of 2026-04-29).

## Why this exists

These roles used to be hand-managed in IAM — no template, no commit history, no review path. On 2026-04-29 the EU-staging tear-down emptied the `eu-central-1` ECR registry, and a one-line region migration in `build.yml` (#1765) had to be paired with an out-of-band `aws iam put-role-policy` call to widen the role's permissions to `us-east-1`. That second surgery is the kind of step we want to never do again.

With this template:

- A region migration is one PR (parameter change) plus one stack update.
- Permission widening is reviewable in a diff.
- Drift detection runs on demand.
- The role lifecycle is anchored to a stack name, not to whoever last clicked through the IAM console.

## Subsequent updates — *change-set apply*

Any change to the template (region migration, new sub-claim allow-list, broadened ECR action set, etc.) goes through the standard CFN change-set flow:

```bash
aws cloudformation create-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name <descriptive-name> \
  --template-body file://infra/iam/github-actions-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=EcrRegion,ParameterValue=us-east-1
                # ^ override defaults here as needed

aws cloudformation describe-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name <descriptive-name>

aws cloudformation execute-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name <descriptive-name>
```

## Drift detection

```bash
aws cloudformation detect-stack-drift \
  --stack-name axonflow-github-actions-roles

# Wait a few seconds, then:
aws cloudformation describe-stack-resource-drifts \
  --stack-name axonflow-github-actions-roles \
  --query 'StackResourceDrifts[?StackResourceDriftStatus!=`IN_SYNC`]'
```

If anyone makes a console / CLI change after the initial import, drift detection is how we'll find it. As of the import on 2026-04-29 both roles report `IN_SYNC`.

## How the initial import was done — *for reference / replay*

The roles already existed in IAM (created manually) before this template did, so taking CloudFormation ownership without recreating them required a `change-set-type=IMPORT` change set. This is documented here in case the stack ever needs to be rebuilt from scratch (e.g. accidental stack delete; both resources have `DeletionPolicy: Retain` so the IAM resources would survive).

Two AWS-side quirks to know about:

1. **Resources to import must declare `DeletionPolicy`.** Both roles in the template carry `DeletionPolicy: Retain` + `UpdateReplacePolicy: Retain`. Drop those and the import will reject.
2. **The IMPORT change set rejects templates that include `Outputs:`.** Strip the `Outputs:` block before creating the import change set; add it back via a follow-up `update-stack` once the import completes.

```bash
# 1. Build the resource-mapping JSON.
cat > /tmp/resources-to-import.json <<'EOF'
[
  {
    "ResourceType": "AWS::IAM::Role",
    "LogicalResourceId": "GitHubActionsECRRole",
    "ResourceIdentifier": { "RoleName": "GitHubActionsECRRole" }
  },
  {
    "ResourceType": "AWS::IAM::Role",
    "LogicalResourceId": "GitHubActionsInfraRole",
    "ResourceIdentifier": { "RoleName": "GitHubActionsInfraRole" }
  }
]
EOF

# 2. Strip Outputs: section for the import (CFN forbids it during IMPORT).
awk '/^Outputs:/{exit} {print}' infra/iam/github-actions-roles.yaml \
  > /tmp/iam-import-only.yaml

# 3. Create the import change set.
aws cloudformation create-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name import-existing-roles \
  --change-set-type IMPORT \
  --template-body file:///tmp/iam-import-only.yaml \
  --resources-to-import file:///tmp/resources-to-import.json \
  --capabilities CAPABILITY_NAMED_IAM

# 4. Inspect — wait for status `CREATE_COMPLETE`.
aws cloudformation describe-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name import-existing-roles \
  --query '{Status:Status,Action:Changes[].ResourceChange.Action,Logical:Changes[].ResourceChange.LogicalResourceId}'

# 5. Execute the import (non-destructive — does not modify live IAM state).
aws cloudformation execute-change-set \
  --stack-name axonflow-github-actions-roles \
  --change-set-name import-existing-roles
aws cloudformation wait stack-import-complete \
  --stack-name axonflow-github-actions-roles

# 6. Apply full template (now with Outputs) via update-stack.
aws cloudformation update-stack \
  --stack-name axonflow-github-actions-roles \
  --template-body file://infra/iam/github-actions-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM
aws cloudformation wait stack-update-complete \
  --stack-name axonflow-github-actions-roles

# 7. CFN import takes ownership but does NOT modify the live resource.
#    If the live state predates the template, drift detection will flag it.
#    Bring live in sync once with direct put-role-policy / tag-role calls,
#    then drift goes IN_SYNC. Future template changes apply normally
#    through update-stack.
aws cloudformation detect-stack-drift \
  --stack-name axonflow-github-actions-roles
```

## Permissions model

`GitHubActionsECRRole` is intentionally narrow:

- `ecr:GetAuthorizationToken` (token-only — not regional).
- ECR push action set, scoped to `arn:aws:ecr:${EcrRegion}:${AccountId}:repository/axonflow-*`.
- Cross-region push is denied by ARN scope, not by an explicit `Deny` (cleaner; one source of truth in `EcrRegion`).
- Granting on the project wildcard (`axonflow-*`) is intentional: any future image target added to `build.yml` gets push access without a second IAM update. Repo creation is separately privileged.

`GitHubActionsInfraRole` is broader (CloudFormation needs to manage many resource types) but follows the same pattern: read-only ECR access scoped to `axonflow-*`.

## Audit pointer

The 2026-04-29 manual `PutRolePolicy` against `GitHubActionsECRRole` (the original cross-region fix) is captured in CloudTrail. The follow-up sync from this template is a second `PutRolePolicy` from the same admin user on the same day. From the import forward, IAM mutations should land via `cloudformation:UpdateStack` events instead.
