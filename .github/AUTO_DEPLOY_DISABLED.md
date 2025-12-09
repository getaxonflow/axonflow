# Auto-Deployment Status

**Status:** ⏸️ **DISABLED** (Nov 11, 2025)

## Why Disabled

The auto-deployment workflow was disabled because:
1. Deployment requires `.env.eu` configuration that isn't stored in GitHub
2. Central instances should require manual approval before deployment
3. Build workflow succeeded, but deployment failed with missing environment variables

## Current Workflow

**What Still Works:**
- ✅ Build workflow: Automatically builds and pushes Docker images to ECR on push to main/develop
- ✅ Manual deployment: Available via GitHub Actions UI

**What's Disabled:**
- ❌ Auto-deploy after successful build (workflow_run trigger commented out)

## Manual Deployment

To deploy manually:

1. Go to: https://github.com/getaxonflow/axonflow/actions/workflows/deploy.yml
2. Click "Run workflow"
3. Select:
   - **Target:** loadtest / central / healthcare / ecommerce
   - **Component:** agent / orchestrator / both
   - **Version:** Commit SHA (e.g., `837c684`)
4. Click "Run workflow"

**Example deployments:**
```bash
# Deploy to loadtest (testing)
Target: loadtest
Component: agent
Version: 837c684

# Deploy to central (production - requires approval)
Target: central
Component: both
Version: 837c684
```

## Re-enabling Auto-Deploy

When ready to re-enable:

1. **Add `.env.eu` to GitHub Secrets:**
   - Go to: https://github.com/getaxonflow/axonflow/settings/secrets/actions
   - Add required variables: `DATABASE_URL`, `REDIS_URL`, `CENTRAL_AXONFLOW_IP`, etc.

2. **Uncomment workflow trigger in `.github/workflows/deploy.yml`:**
   ```yaml
   on:
     workflow_run:
       workflows: ["Build and Push Docker Images"]
       types:
         - completed
       branches:
         - main
         - develop
     workflow_dispatch:
       # ... manual trigger remains
   ```

3. **Add manual approval for central instances:**
   - Create GitHub Environment: "central-production"
   - Add required reviewers
   - Update deploy job to use environment for central deployments
   - Example:
     ```yaml
     deploy:
       environment:
         name: ${{ inputs.target == 'central' && 'central-production' || '' }}
     ```

## Configuration

**File:** `.github/workflows/deploy.yml`
**Modified:** Nov 11, 2025 (commit 837c684)
**Disabled by:** AxonFlow Team

## Required Environment Variables

For deployment workflow to work:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string (if used)
- `CENTRAL_AXONFLOW_IP` - Central instance IPs
- `AXONFLOW_SSH_KEY` - SSH key for instance access (already configured)
- `AWS_ROLE_ARN` - IAM role for AWS access (already configured)

---

**Created:** November 11, 2025
**Last Updated:** November 11, 2025
**Status:** Auto-deploy disabled, manual deployment available
