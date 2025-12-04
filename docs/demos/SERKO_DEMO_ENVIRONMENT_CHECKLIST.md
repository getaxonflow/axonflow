# Serko Demo Environment Checklist

**Purpose:** Pre-demo verification to ensure all systems are operational
**Recommended:** Run through this checklist 30 minutes before demo

---

## Quick Health Check (5 minutes)

Run these commands to verify infrastructure:

```bash
# EU Staging Agent Health
curl -s https://staging-eu.getaxonflow.com/health | jq .

# Expected output:
# {
#   "status": "healthy",
#   "version": "X.X.X",
#   "region": "eu-central-1"
# }

# Customer Portal Health
curl -s https://app.getaxonflow.com/api/health | jq .

# Expected output:
# {
#   "status": "ok"
# }
```

---

## 30 Minutes Before Demo

### Infrastructure Checks

- [ ] **EU Staging Agent**
  - URL: `https://staging-eu.getaxonflow.com/health`
  - Expected: `{"status":"healthy"}`
  - Action if failing: Contact on-call, use US fallback

- [ ] **Travel Demo Application**
  - URL: `https://travel-eu.getaxonflow.com`
  - Expected: Homepage loads, form visible
  - Action if failing: Try staging URL `https://travel-staging-eu.getaxonflow.com`

- [ ] **Customer Portal**
  - URL: `https://app.getaxonflow.com`
  - Expected: Login page loads
  - Action if failing: Use `https://app-staging.getaxonflow.com`

- [ ] **Documentation Site**
  - URL: `https://docs.getaxonflow.com`
  - Expected: Docs load normally
  - Action if failing: Proceed without docs reference

### Demo Mode Verification

- [ ] **Demo Mode Toggle Visible**
  - Navigate to Travel Demo homepage
  - Verify toggle in top-right corner shows "Demo Mode"
  - Toggle ON - should change to "EU AI Act Demo Mode"

- [ ] **Sarah Thompson User Card**
  - With Demo Mode ON, verify user card appears
  - Card shows: "Corporate Travel Manager" at "TechGlobal NZ"
  - Scenario: "High-Value Transaction Oversight"

- [ ] **James Wilson User Card**
  - Verify second user card appears
  - Card shows: "Sales Director" at "Kiwi Exports Ltd"
  - Scenario: "Cross-Border PII Minimization"

### Scenario Test Run

Run both scenarios once to:
1. Verify they execute correctly
2. Seed audit logs with recent data
3. Time the execution (should be 5-15 seconds each)

- [ ] **Execute Sarah Thompson Scenario**
  - Click Sarah's card
  - Click "Execute High-Value Transaction Oversight Scenario"
  - Expected: Green checkmark, ALERT action shown
  - Expected: Message mentions "€5,000 threshold"
  - Time taken: ______ seconds

- [ ] **Execute James Wilson Scenario**
  - Click "Plan Another Trip"
  - Click James's card
  - Click "Execute Cross-Border PII Minimization Scenario"
  - Expected: Green checkmark, REDACT action shown
  - Expected: Message shows "LA****54" redacted passport
  - Time taken: ______ seconds

### Customer Portal Verification

- [ ] **Login to Customer Portal**
  - URL: `https://app.getaxonflow.com`
  - Use demo credentials (see SERKO_DEMO_URLS.md)
  - Expected: Dashboard loads

- [ ] **Audit Logs Page**
  - Navigate to Audit Logs
  - Verify compliance summary panel loads
  - Verify recent entries visible (from test runs)

- [ ] **Filter Functionality**
  - Test date filter (set to today)
  - Test action filter (select "Alerted")
  - Test action filter (select "Modified")
  - Expected: Filters work, results update

- [ ] **Export Functionality**
  - Click "Export CSV"
  - Expected: File downloads
  - Verify file contains recent entries

---

## 15 Minutes Before Demo

### Browser Setup

- [ ] **Close unnecessary tabs**
  - Only keep demo-related tabs open
  - Clear browser history if sharing screen

- [ ] **Open required tabs in order:**
  1. Tab 1: Travel Demo - `https://travel-eu.getaxonflow.com`
  2. Tab 2: Customer Portal Audit - `https://app.getaxonflow.com/audit`
  3. Tab 3: AxonFlow Docs (optional) - `https://docs.getaxonflow.com`

- [ ] **Browser zoom level**
  - Set to 100% or 125% for visibility
  - Test with screen share preview if possible

- [ ] **Dark mode / light mode**
  - Ensure consistent theme across all tabs
  - Light mode recommended for visibility

### Connectivity

- [ ] **Stable internet connection**
  - Run speed test: > 10 Mbps upload recommended
  - Disable VPN if causing latency issues

- [ ] **Backup connection ready**
  - Mobile hotspot charged and available
  - Know how to switch quickly if needed

### Screen Sharing

- [ ] **Test screen share**
  - Share browser window (not full screen)
  - Verify notifications are disabled
  - Verify no sensitive tabs visible

### Audio/Video

- [ ] **Microphone working**
- [ ] **Camera working (if video demo)**
- [ ] **Headphones to avoid echo**

---

## 5 Minutes Before Demo

### Final Verification

- [ ] **Refresh all browser tabs**
  - Travel Demo loads fresh
  - Customer Portal shows recent data
  - No error messages visible

- [ ] **Demo Mode OFF initially**
  - Start with Demo Mode toggle OFF
  - You'll enable it during the demo for effect

- [ ] **Customer Portal logged in**
  - Verify session hasn't expired
  - Navigate to Audit Logs page ready

### Materials Ready

- [ ] **Demo script open**
  - In separate window/screen
  - Not visible during screen share

- [ ] **Backup screenshots ready**
  - Prepare screenshots of each demo step before the meeting
  - Know how to access quickly

- [ ] **FAQ document accessible**
  - For quick reference during Q&A

---

## Fallback Checklist

If primary systems fail, use these fallbacks:

### Travel Demo Fallback

| Issue | Fallback |
|-------|----------|
| Production down | Use `https://travel-staging-eu.getaxonflow.com` |
| Staging down | Use pre-recorded video or screenshots |
| Demo mode not working | Use screenshots with verbal walkthrough |

### Customer Portal Fallback

| Issue | Fallback |
|-------|----------|
| Production down | Use `https://app-staging.getaxonflow.com` |
| Staging down | Show sample CSV export (prepare before demo) |
| Login fails | Use screenshots of audit page |

### General Fallback Protocol

1. Acknowledge the issue briefly: "We're experiencing a technical issue with our demo environment."
2. Don't apologize excessively - stay professional
3. Pivot to prepared materials: "Let me show you recorded screenshots that demonstrate the same functionality."
4. Continue the narrative - the story is more important than live clicks
5. Offer live follow-up: "I'll schedule a follow-up call once our environment is restored."

---

## Post-Demo Verification

After the demo, verify no issues occurred:

- [ ] Check EU staging logs for errors
- [ ] Verify no real customer data was exposed
- [ ] Log any issues encountered for improvement
- [ ] Clear browser cache if using shared machine

---

## Emergency Contacts

| Role | Contact | When to Use |
|------|---------|-------------|
| On-Call Engineer | #eng-oncall Slack | Infrastructure down |
| Demo Support | #sales-engineering Slack | Demo-specific issues |
| Product Manager | @pm-team Slack | Feature questions |

---

## Sample Health Check Script

Save this as `demo-health-check.sh` for quick verification:

```bash
#!/bin/bash

echo "=== AxonFlow Demo Health Check ==="
echo ""

# Check EU Staging
echo "1. EU Staging Agent..."
STAGING=$(curl -s -o /dev/null -w "%{http_code}" https://staging-eu.getaxonflow.com/health)
if [ "$STAGING" = "200" ]; then
  echo "   OK"
else
  echo "   FAILED (HTTP $STAGING)"
fi

# Check Travel Demo
echo "2. Travel Demo..."
TRAVEL=$(curl -s -o /dev/null -w "%{http_code}" https://travel-eu.getaxonflow.com)
if [ "$TRAVEL" = "200" ]; then
  echo "   OK"
else
  echo "   FAILED (HTTP $TRAVEL)"
fi

# Check Customer Portal
echo "3. Customer Portal..."
PORTAL=$(curl -s -o /dev/null -w "%{http_code}" https://app.getaxonflow.com)
if [ "$PORTAL" = "200" ]; then
  echo "   OK"
else
  echo "   FAILED (HTTP $PORTAL)"
fi

echo ""
echo "=== Check Complete ==="
```

---

*Last updated: December 3, 2025*
