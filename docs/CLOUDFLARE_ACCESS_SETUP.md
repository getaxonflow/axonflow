# Cloudflare Access Setup for Protected Documentation

## Prerequisites

- Cloudflare Pro plan (confirmed)
- Admin access to Cloudflare dashboard
- Domain `getaxonflow.com` managed by Cloudflare

---

## Step 1: Enable Zero Trust (if not already)

1. Go to: https://dash.cloudflare.com/
2. Click on your account
3. In left sidebar, find **Zero Trust** (or go to https://one.dash.cloudflare.com/)
4. If first time, you'll be asked to set up a team name (e.g., `axonflow`)

---

## Step 2: Create Access Group

This group will hold all emails allowed to access protected docs.

1. Go to: **Zero Trust → Access → Access Groups**
2. Click **Add a group**
3. Configure:
   - **Group name:** `axonflow-protected-docs-users`
   - **Group criteria:**
     - Include: **Emails** → Leave empty for now (will be populated via API)

4. Click **Save**
5. **IMPORTANT:** Copy the Group ID from the URL after saving:
   - URL will look like: `https://one.dash.cloudflare.com/.../access/groups/abc123-def456-...`
   - The `abc123-def456-...` part is your **CF_ACCESS_GROUP_ID**

---

## Step 3: Create Access Application

1. Go to: **Zero Trust → Access → Applications**
2. Click **Add an application**
3. Select **Self-hosted**
4. Configure:

   **Application Configuration:**
   - **Application name:** `AxonFlow Protected Docs`
   - **Session Duration:** `1 week` (168 hours)

   **Application domain:**
   - **Subdomain:** `docs`
   - **Domain:** `getaxonflow.com`
   - **Path:** `/docs/protected/` (include trailing slash)

5. Click **Next**

---

## Step 4: Configure Policy

1. **Policy name:** `Allow Protected Docs Users`
2. **Action:** `Allow`
3. **Session duration:** `1 week`

4. **Configure rules:**
   - **Include:**
     - Selector: `Access groups`
     - Value: `axonflow-protected-docs-users` (the group we created)

5. Click **Next**

---

## Step 5: Configure Authentication

1. **Identity providers:**
   - Enable: **One-time PIN** (this is the email OTP method)
   - This is built-in, no external IdP needed

2. Leave other settings as default

3. Click **Add application**

---

## Step 6: Create API Token

1. Go to: https://dash.cloudflare.com/profile/api-tokens
2. Click **Create Token**
3. Click **Create Custom Token**
4. Configure:

   **Token name:** `AxonFlow Docs Access Management`

   **Permissions:**
   | Resource | Permission |
   |----------|------------|
   | Account → Access: Organizations, Identity Providers, and Groups | Edit |
   | Zone → Zone | Read |

   **Account Resources:**
   - Include: `All accounts` (or select specific account)

   **Zone Resources:**
   - Include: `Specific zone` → `getaxonflow.com`

5. Click **Continue to summary** → **Create Token**
6. **IMPORTANT:** Copy the token immediately (shown only once)
   - This is your **CF_API_TOKEN**

---

## Step 7: Get Account ID

1. Go to: https://dash.cloudflare.com/
2. Click on `getaxonflow.com` zone
3. On the right sidebar, find **API** section
4. Copy the **Account ID**
   - This is your **CF_ACCOUNT_ID**

---

## Step 8: Store Credentials

You'll need these three values for the CLI and portal:

```bash
CF_API_TOKEN=<token-from-step-6>
CF_ACCOUNT_ID=<account-id-from-step-7>
CF_ACCESS_GROUP_ID=<group-id-from-step-2>
```

**For local development:**
```bash
# Add to ~/.zshrc or ~/.bashrc
export CF_API_TOKEN="your-token"
export CF_ACCOUNT_ID="your-account-id"
export CF_ACCESS_GROUP_ID="your-group-id"
```

**For production (AWS Secrets Manager):**
```bash
# Create secret
aws secretsmanager create-secret \
  --name "axonflow/cloudflare-access" \
  --secret-string '{
    "api_token": "your-token",
    "account_id": "your-account-id",
    "access_group_id": "your-group-id"
  }' \
  --region eu-central-1
```

---

## Step 9: Test the Setup

1. Open an incognito browser window
2. Go to: `https://docs.getaxonflow.com/docs/protected/`
3. You should see a Cloudflare Access login page
4. Enter your email (it will fail since no emails are in the group yet - that's expected!)

---

## Verification Checklist

- [ ] Zero Trust dashboard accessible
- [ ] Access Group `axonflow-protected-docs-users` created
- [ ] Access Application `AxonFlow Protected Docs` created with `/docs/protected/` path
- [ ] Policy uses Access Group (not hardcoded emails)
- [ ] One-time PIN authentication enabled
- [ ] Session duration set to 1 week
- [ ] API Token created with correct permissions
- [ ] All three credentials saved (CF_API_TOKEN, CF_ACCOUNT_ID, CF_ACCESS_GROUP_ID)
- [ ] Test shows CF Access login page on protected path

---

## Next Steps

Once you've completed this setup and have the three credential values, let me know and I'll proceed with:

1. Creating the CLI tool (`axonctl docs grant/revoke/list`)
2. Migrating protected content to Docusaurus
3. Adding portal integration

---

## Troubleshooting

**"Access denied" instead of login page:**
- Check the path matches exactly: `/docs/protected/`
- Verify the application is active (not in test mode)

**API token not working:**
- Ensure "Access: Organizations, Identity Providers, and Groups: Edit" permission is set
- Token must be for the correct account

**Group not showing in policy:**
- Groups take a few seconds to propagate
- Refresh the page and try again
