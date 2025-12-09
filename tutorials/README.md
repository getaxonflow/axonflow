# AxonFlow Video Tutorial Scripts

**Purpose:** Production-ready scripts for creating video tutorials

**Status:** Ready for video production team

---

## Available Tutorial Scripts

| # | Tutorial | Duration | Status | Audience |
|---|----------|----------|--------|----------|
| 01 | [First Agent in 10 Minutes](./01-first-agent-10-minutes.md) | 10:00 | ✅ Ready | Beginner |
| 02 | [Adding LLM Integration](./02-llm-integration.md) | 12:00 | ✅ Ready | Intermediate |
| 03 | Connecting to Your Database | 15:00 | 📋 Outlined | Intermediate |
| 04 | Deploying to AWS Production | 15:00 | 📋 Outlined | Advanced |

---

## Tutorial 03: Connecting to Your Database (Outline)

**Duration:** 15 minutes
**Topics Covered:**
- MCP connector overview
- PostgreSQL connector setup
- Snowflake connector setup
- Salesforce connector integration
- Permission-aware queries
- Policy enforcement on data access

**Key Demonstrations:**
- Query customer data with RBAC
- Column-level security
- Row-level filtering based on user permissions
- Audit logging for compliance

**Code Examples:** TypeScript and Go

---

## Tutorial 04: Deploying to AWS Production (Outline)

**Duration:** 15 minutes
**Topics Covered:**
- Production deployment checklist
- Multi-AZ setup
- Auto-scaling configuration
- Monitoring with CloudWatch
- Backup and disaster recovery
- Security best practices
- Cost optimization

**Key Demonstrations:**
- Deploy via CloudFormation
- Configure auto-scaling
- Set up alarms
- Test failover
- Monitor performance

**Code Examples:** CloudFormation templates, deployment scripts

---

## Production Guidelines

### Recording Standards

**Video:**
- Resolution: 1920x1080 minimum (4K preferred)
- Frame rate: 30fps or 60fps
- Format: MP4 (H.264 codec)

**Audio:**
- Sample rate: 48kHz
- Bit depth: 16-bit or 24-bit
- Format: Stereo
- Microphone: USB condenser (Blue Yeti or better)

**Screen Recording:**
- Terminal: Dark theme, 18pt font
- Editor: VS Code with Material Theme, 16-18pt font
- Browser: 125% zoom for AWS Console
- Software: OBS Studio or ScreenFlow

### Branding

**Colors:**
- Primary: #0066CC (AxonFlow Blue)
- Secondary: #00CC66 (Success Green)
- Accent: #FF6600 (Warning Orange)

**Fonts:**
- Headings: Inter Bold
- Body: Inter Regular
- Code: Fira Code

**Logo:** Use official AxonFlow logo (provided separately)

### Post-Production

**Required:**
- Intro animation (3 seconds)
- Outro with call-to-action (5 seconds)
- On-screen text for key points
- Code highlighting/arrows
- Smooth transitions between sections
- Background music (optional, low volume)

**Captions:**
- Auto-generate with YouTube
- Review and correct technical terms
- Add timestamps in description

---

## Distribution Checklist

**YouTube:**
- [ ] Upload in 1080p or higher
- [ ] Add chapters/timestamps
- [ ] Include code links in description
- [ ] Add to AxonFlow playlist
- [ ] Enable comments

**Documentation Site:**
- [ ] Embed video
- [ ] Add written transcript
- [ ] Link to code examples
- [ ] Add related tutorials

**Social Media:**
- [ ] LinkedIn post
- [ ] Twitter/X thread
- [ ] Reddit r/devops (if relevant)
- [ ] Hacker News (if high engagement)

**Email:**
- [ ] Newsletter announcement
- [ ] Onboarding email sequence
- [ ] Customer success team notification

---

## Maintenance Schedule

**Quarterly Review:**
- Check for SDK updates
- Update AWS Console screenshots if UI changed
- Verify all commands still work
- Update model names (LLM providers)
- Check CloudFormation template versions

**Update Triggers:**
- Major SDK version release
- Breaking API changes
- New feature launches
- Customer feedback

---

## Metrics to Track

**Engagement:**
- Video completion rate (target: >70%)
- Average watch time (target: >70% of duration)
- Click-through rate to docs (target: >15%)
- Comments and questions

**Business Impact:**
- Time to first deployment (target: <30 min after watching)
- Support ticket reduction (target: 20% decrease)
- Trial-to-paid conversion improvement
- Customer satisfaction scores

---

## Video Production Team Contact

**Questions or feedback on scripts:**
- Email: support@getaxonflow.com
- Slack: #video-production
- Project Manager: [Name]

---

**All scripts follow AxonFlow brand guidelines and development principles.**
**Ready for filming!** 🎬
