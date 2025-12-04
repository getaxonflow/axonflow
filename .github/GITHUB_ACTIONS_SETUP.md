# GitHub Actions Setup

## AWS OIDC Authentication

**Status:** ✅ Configured (Nov 11, 2025)

### OIDC Provider

**Provider ARN:** `arn:aws:iam::686831565523:oidc-provider/token.actions.githubusercontent.com`
**URL:** https://token.actions.githubusercontent.com
**Client:** sts.amazonaws.com

### IAM Role

**Role Name:** `GitHubActionsECRRole`
**Role ARN:** `arn:aws:iam::686831565523:role/GitHubActionsECRRole`

**Permissions:**
- ECR authentication (`ecr:GetAuthorizationToken`)
- ECR push to repositories:
  - axonflow-agent
  - axonflow-orchestrator
  - axonflow-travel-backend
  - axonflow-travel-frontend

**Trust Policy:**
- Repository: `getaxonflow/axonflow` (all branches)
- Authentication: OIDC via GitHub Actions

### GitHub Secret

**Secret Name:** `AWS_ROLE_ARN`
**Location:** Repository Settings → Secrets and variables → Actions
**Added:** Nov 11, 2025

### Testing

Build workflow automatically triggers on:
- Push to `main` or `develop` branches
- Changes to `platform/**`, `migrations/**`, Dockerfiles
- Pull requests to `main` or `develop`
- Manual workflow dispatch

### Workflows Using OIDC

1. **build.yml** - Build and push Docker images to ECR
   - Uses: `aws-actions/configure-aws-credentials@v4`
   - Role: Assumes `GitHubActionsECRRole` via OIDC
   - Permissions: `id-token: write` (required for OIDC)

### Security

- ✅ No long-lived AWS credentials stored in GitHub
- ✅ Temporary credentials via OIDC (auto-expire after 1 hour)
- ✅ Trust policy restricts access to specific repository
- ✅ Least privilege: Only ECR push permissions granted

### Troubleshooting

**Error: "Credentials could not be loaded"**
- Verify `AWS_ROLE_ARN` secret is set in repository
- Check IAM role trust policy includes your repository
- Ensure workflow has `id-token: write` permission

**Error: "User is not authorized to perform: ecr:GetAuthorizationToken"**
- Verify IAM role has ECR permissions policy attached
- Check role ARN matches the secret value

### Maintenance

**OIDC Provider Thumbprint:**
- Current: `6938fd4d98bab03faadb97b34396831e3780aea1`
- Update if GitHub changes their certificate (rare)
- Command: `aws iam update-open-id-connect-provider-thumbprint`

**Role Permissions:**
- Review quarterly
- Add new ECR repositories to policy as needed
- Monitor CloudTrail for unauthorized access attempts

---

**Created:** November 11, 2025
**Last Updated:** November 11, 2025
**Status:** Active and tested
