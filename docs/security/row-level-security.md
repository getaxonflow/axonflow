# Row-Level Security (RLS) - Data Protection

**Last Updated:** November 13, 2025
**Status:** Active in Production
**Applies To:** All AxonFlow tenants

---

## What is Row-Level Security?

Row-Level Security (RLS) is a database-level security feature that ensures **your data is always isolated from other customers**, even if there's a bug in our application code.

Think of it as an extra lock on your data that the database itself enforces - not just the application.

---

## Why It Matters

### Before RLS

**Application-level filtering only:**
- Your data was separated by adding `WHERE org_id = 'your-org'` to every database query
- If we accidentally forgot that filter in our code, data could leak
- ⚠️ Security depends on perfect code (and humans make mistakes)

### With RLS (Now)

**Database-level enforcement:**
- The database automatically adds the filter to EVERY query
- Even if our code has a bug, your data stays private
- ✅ Defense-in-depth: Two layers of protection instead of one

---

## How It Works

```
┌─────────────────────────────────────────────────────┐
│ Your Request                                        │
│ (with your license key or session)                 │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ AxonFlow Application                                │
│ • Validates your license/session                    │
│ • Sets org_id = "your-organization"                │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ Database (with RLS)                                 │
│ • Automatically adds: WHERE org_id = "your-org"     │
│ • Returns only YOUR data                            │
│ • Blocks access to other customers' data            │
└─────────────────────────────────────────────────────┘
```

---

## What Data is Protected?

RLS protects **all your tenant-specific data**:

| Data Type | Protected |
|-----------|-----------|
| **Usage metrics** | ✅ Your API calls, token usage, costs |
| **Agent heartbeats** | ✅ Your node activity, health status |
| **API keys** | ✅ Your authentication credentials |
| **User sessions** | ✅ Your user logins and activities |
| **Audit logs** | ✅ Your compliance and security events |
| **Policies** | ✅ Your custom rules and configurations |
| **MCP connectors** | ✅ Your data source connections |

**Total:** 26 database tables with RLS protection

---

## Performance Impact

**Good news:** RLS has **minimal performance impact**.

- **Average query latency:** Minimal additional overhead
- **P95 latency:** <10ms additional overhead
- **Tested:** 1,000 queries/second with no degradation

Your application performance remains the same. The security benefit far outweighs the tiny latency cost.

---

## Frequently Asked Questions

### Q: Do I need to change anything?

**A:** No! RLS is completely transparent to you.

- Your existing API calls work exactly the same
- Your SDK code doesn't need updates
- Your queries return the same data

The only difference: Enhanced security behind the scenes.

### Q: Can I disable RLS for my tenant?

**A:** No. RLS is a core security feature for all customers.

This protects you AND other customers from accidental data exposure.

### Q: What happens if I query another customer's data?

**A:** The database returns zero rows.

```sql
-- Example: You try to see another customer's usage
SELECT * FROM usage_events WHERE org_id = 'other-customer'

-- Result: 0 rows (RLS blocks it)
```

RLS ensures you can ONLY see your own data, period.

### Q: How is this different from encryption?

**A:** They solve different problems:

| Feature | Encryption | RLS |
|---------|-----------|-----|
| **Protects against** | Data theft from disk | Data leaks between tenants |
| **When active** | Data at rest | Data in use (queries) |
| **Performance impact** | Moderate | Minimal |
| **Complements each other** | ✅ Yes - we use both |

AxonFlow uses **both** encryption (data at rest + in transit) **and** RLS (tenant isolation).

### Q: Is my data encrypted too?

**A:** Yes! We use multiple layers of security:

1. **Encryption at rest:** All database storage is encrypted (AES-256)
2. **Encryption in transit:** All connections use TLS 1.2+
3. **Row-Level Security:** Tenant data isolation (this feature)
4. **Access controls:** Role-based permissions for our team

---

## Compliance & Certifications

RLS helps us maintain:

- **SOC 2 Type II:** Industry standard for service organizations
- **HIPAA:** Protected Health Information (PHI) isolation
- **GDPR:** Data isolation and privacy by design
- **ISO 27001:** Information security management

---

## Monitoring & Alerts

Our security team continuously monitors RLS:

- **Health checks:** Every 5 minutes
- **Policy count:** 104 active policies (4 per table × 26 tables)
- **Violations:** Zero tolerance - automatic alerts
- **Audit logs:** All RLS activity logged for compliance

---

## Support

### If you see issues:

1. **Check your license key:** Ensure it's valid and not expired
2. **Check API responses:** Look for `401 Unauthorized` errors
3. **Contact support:** support@getaxonflow.com

### Common error messages:

| Error | Meaning | Solution |
|-------|---------|----------|
| "org_id not set in session" | Session expired or invalid | Re-authenticate with valid license |
| "Permission denied for table" | License key issue | Verify license key is correct |
| "No rows returned" | Normal - you have no data yet | Check your query filters |

---

## Additional Resources

- **Technical Documentation:** See `technical-docs/RLS_ARCHITECTURE.md`
- **Security Whitepaper:** [axonflow.com/security](https://axonflow.com/security)
- **Compliance Docs:** [axonflow.com/compliance](https://axonflow.com/compliance)

---

## Summary

Row-Level Security (RLS) provides **database-level tenant isolation** to ensure your data is always private, even if there's a bug in our code.

**Key Benefits:**
- ✅ Enhanced security (defense-in-depth)
- ✅ Automatic enforcement (no human error)
- ✅ Minimal performance impact (<10ms)
- ✅ Compliance-ready (SOC 2, HIPAA, GDPR)
- ✅ Zero configuration (it just works)

Your data is safe with AxonFlow.

---

**Questions?** Contact support@getaxonflow.com
