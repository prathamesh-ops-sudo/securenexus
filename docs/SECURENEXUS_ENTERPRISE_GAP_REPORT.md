# SecureNexus: Enterprise Security, Access Control & UI/UX Gap Report
## Gaps, Bugs, and Missing Pieces ONLY — Nothing That Already Works

**Date**: February 2026
**Scope**: Enterprise security audit, access control audit, admin/developer platform audit, UI/UX gaps, and development plan.

---

## Table of Contents

1. [Critical Security Bugs](#1-critical-security-bugs)
2. [Access Control & RBAC Gaps](#2-access-control--rbac-gaps)
3. [Admin Platform Gaps](#3-admin-platform-gaps)
4. [Developer Platform Gaps](#4-developer-platform-gaps)
5. [Authentication & Session Gaps](#5-authentication--session-gaps)
6. [Org Security Policy — Schema Exists, Not Enforced](#6-org-security-policy--schema-exists-not-enforced)
7. [Plan Enforcement Gaps](#7-plan-enforcement-gaps)
8. [UI/UX Gaps & Bugs](#8-uiux-gaps--bugs)
9. [Route-Level Security Audit](#9-route-level-security-audit)
10. [Development Plan](#10-development-plan)

---

## 1. Critical Security Bugs

### BUG-1: Any New User Joins First Org as OWNER (CRITICAL)

**File**: `/app/server/auth/routes.ts` lines 59-68
**Impact**: Complete organization takeover

```typescript
// CURRENT CODE — THE BUG:
const orgs = await storage.getOrganizations();
if (orgs.length > 0) {
  await storage.createOrgMembership({
    orgId: orgs[0].id,
    userId: user.id,
    role: "owner",          // <-- ANY new user becomes OWNER of the first org
    status: "active",
    joinedAt: new Date(),
  });
}
```

**What happens**: When a new user registers and doesn't match any domain auto-join rule, they are automatically added to the **first organization in the database** with the **owner** role. This means:
- Any stranger who signs up becomes an owner of your organization
- They can delete members, change settings, access all data
- This is a complete access control bypass

**Fix**: New users without a domain match should be placed in onboarding flow to create their OWN organization, or be denied access. They should NEVER be auto-joined to an existing org, let alone as owner.

---

### BUG-2: No Email Validation — Anyone Can Sign Up (HIGH)

**File**: `/app/server/auth/routes.ts` lines 125-172
**Impact**: Spam accounts, abuse, competitors snooping

The registration endpoint accepts ANY email — gmail.com, yahoo.com, mailinator.com, temp-mail.org. For an enterprise SOC platform, only work/corporate emails should be allowed.

**What's missing**: A blocklist of free email providers. The schema already has domain verification (`org_domain_verifications`) and domain auto-join (`org_autojoin_domains`), but registration itself has zero email validation.

**Fix**: Add a check against a blocklist of ~400 free email providers (gmail.com, yahoo.com, outlook.com, protonmail.com, etc.). Return 400 if email domain is on the blocklist.

---

### BUG-3: No Password Complexity (HIGH)

**File**: `/app/server/auth/routes.ts` line 128
**Impact**: Weak credentials, credential stuffing vulnerability

```typescript
// CURRENT: Only checks if password exists, not its quality
if (!email || !password) {
  return replyValidation(res, [
    { message: "Email and password are required" }
  ]);
}
```

The org security policy schema defines `passwordMinLength: 12`, `passwordRequireUppercase: true`, `passwordRequireNumber: true`, `passwordRequireSpecial: true` — but these are **never checked** during registration or password changes.

**Fix**: Enforce password complexity at registration. Default: min 8 chars, 1 uppercase, 1 number, 1 special char. If org has custom policy, use that instead.

---

### BUG-4: isSuperAdmin Cannot Be Set — Admin Platform Inaccessible (HIGH)

**File**: `/app/shared/models/auth.ts` line 25
**Impact**: Entire platform admin and developer portal are unreachable

The user schema has `isSuperAdmin: boolean("is_super_admin").default(false).notNull()`, and the platform admin + dev portal are gated behind `requireSuperAdmin` middleware. But there is **NO mechanism** to set `isSuperAdmin = true`:
- No API endpoint to promote a user to super admin
- No seed script that creates a super admin
- No CLI command
- No environment variable

**Result**: The platform admin dashboard (977 lines, 18 endpoints) and developer portal (1,277 lines, 10 endpoints) are **completely inaccessible** to everyone.

**Fix**: Add a seed command or env var `SUPER_ADMIN_EMAIL` that promotes the first matching user. Also add a platform-admin route for existing super admins to promote others.

---

## 2. Access Control & RBAC Gaps

### GAP-1: 18 Route Files Have Auth But ZERO Role Checks

The RBAC system (`rbac.ts`) is well-implemented with `requireOrgRole()`, `requireMinRole()`, and `requirePermission()`. But it's only used in some route files. **18 route files** have authentication but **no role-based access control**:

| Route File | Endpoints | Auth | RBAC | Org Scope | Risk |
|-----------|-----------|------|------|-----------|------|
| autonomous.ts | 13 | YES (`requireAuth`) | NONE | NONE | HIGH — any authenticated user can create/execute response policies |
| predictive.ts | 10 | YES (`requireAuth`) | NONE | NONE | HIGH — any user can trigger predictions, access attack surface |
| investigations.ts | 32 auth refs | YES | NONE | NONE | HIGH — any user can trigger AI investigations |
| playbooks.ts | 26 auth refs | YES | NONE | 17 org refs | MEDIUM — org-scoped but any role can create/execute playbooks |
| threat-intel.ts | 40 auth refs | YES | NONE | NONE | HIGH — any user can manage IOC feeds |
| report-governance.ts | 17 auth refs | YES | NONE | NONE | MEDIUM — any user can manage report templates |
| reports.ts | 20 auth refs | YES | NONE | NONE | MEDIUM — any user can generate/export reports |
| entities.ts | 24 auth refs | YES | NONE | NONE | LOW — read-heavy, but write ops unprotected |
| endpoints.ts | 21 auth refs | YES | NONE | NONE | MEDIUM — any user can manage endpoint assets |
| webhooks.ts | 12 auth refs | YES | NONE | NONE | HIGH — any user can create outbound webhooks (data exfil risk) |
| integrations.ts | 26 auth refs | YES | NONE | 9 org refs | MEDIUM — any user can configure integrations |
| dashboard.ts | 4 auth refs | YES | NONE | NONE | LOW — read-only |
| stunning-dashboard.ts | 2 auth refs | YES | NONE | NONE | LOW — read-only |
| events.ts | 3 auth refs | YES | NONE | NONE | LOW — SSE stream |
| files.ts | 5 auth refs | YES | NONE | NONE | MEDIUM — any user can upload/download files |
| onboarding.ts | 11 auth refs | YES | NONE | NONE | LOW — self-service |
| usage.ts | 4 auth refs | YES | NONE | 7 org refs | LOW — read-only |
| api-versioning.ts | 8 auth refs | YES | NONE | NONE | LOW — metadata |

**What this means**: A `read_only` user can:
- Create and execute autonomous response policies (could isolate hosts, block IPs)
- Trigger AI investigations (costs money)
- Manage IOC threat feeds
- Create outbound webhooks (exfiltrate data)
- Upload/download files
- Execute playbooks (could take automated actions)

**Fix**: Add `requireMinRole("analyst")` for read/write operations and `requireMinRole("admin")` for admin operations on all 18 route files.

---

### GAP-2: Autonomous Response Routes Use Custom `requireAuth` Not `isAuthenticated`

**File**: `/app/server/routes/autonomous.ts`

These routes import a local `requireAuth` function instead of the global `isAuthenticated` from the auth module. Need to verify this is the same middleware and not a weaker check.

**Fix**: Verify or replace with the global `isAuthenticated` + add proper RBAC.

---

### GAP-3: No Org-Scope Isolation on Many Routes

Even routes with auth may return data from ALL organizations, not just the user's. Routes missing `resolveOrgContext` + `requireOrgId`:
- autonomous.ts — no org scoping
- predictive.ts — no org scoping
- investigations.ts — no org scoping
- entities.ts — no org scoping
- endpoints.ts — no org scoping
- webhooks.ts — no org scoping
- report-governance.ts — no org scoping
- events.ts — no org scoping
- files.ts — no org scoping

**Impact**: User from Org A could potentially see data from Org B.

**Fix**: Add `resolveOrgContext, requireOrgId` middleware to all org-scoped routes.

---

## 3. Admin Platform Gaps

### What EXISTS (working code):
- Platform admin backend: 1,018 lines, 18 endpoints, protected by `requireSuperAdmin`
- Platform admin UI: 977 lines, full dashboard with org management, user management, system health
- Impersonation system: schema + session tracking for admin impersonation
- Feature flags system: schema + API
- Audit log viewer for platform-wide actions

### What's MISSING:

| # | Gap | Description | Priority |
|---|-----|-------------|----------|
| A-1 | No way to become super admin | `isSuperAdmin` field exists but cannot be set (see BUG-4) | CRITICAL |
| A-2 | No first-time admin setup | No bootstrap/seed flow for initial platform admin | CRITICAL |
| A-3 | No super admin promotion API | Existing super admins can't promote others | HIGH |
| A-4 | No data-testid on platform-admin.tsx | 0 testids across 977 lines | MEDIUM |
| A-5 | Revenue dashboard data source unknown | `/api/platform-admin/revenue` exists but unclear if connected to Stripe | MEDIUM |
| A-6 | No admin notification system | Admin not alerted on security events (failed logins, privilege escalation) | LOW |

---

## 4. Developer Platform Gaps

### What EXISTS (working code):
- Developer portal backend: 709 lines, 10 endpoints, protected by `requireSuperAdmin`
- Developer portal UI: 1,277 lines with API docs, key management, webhook testing, DB explorer
- OpenAPI spec generation: 2,254 lines
- Webhook management with logging

### What's MISSING:

| # | Gap | Description | Priority |
|---|-----|-------------|----------|
| D-1 | Inaccessible — blocked by BUG-4 | Only super admins can access, but no one can become super admin | CRITICAL |
| D-2 | No data-testid on dev-portal.tsx | 0 testids across 1,277 lines | MEDIUM |
| D-3 | DB query explorer is a security risk | `/api/dev-portal/db/query` allows raw SQL — needs audit logging + read-only enforcement | HIGH |
| D-4 | SDK examples may be outdated | Generated SDK examples reference internal schemas | LOW |
| D-5 | No API rate limit documentation | Dev portal doesn't show rate limits per endpoint | LOW |

---

## 5. Authentication & Session Gaps

### What EXISTS (working code):
- Email/password auth with bcrypt (scrypt) hashing
- Passport.js with Local, Google, GitHub strategies
- Session management with PostgreSQL store
- CSRF token protection (both backend and frontend)
- Session TTL of 7 days

### What's MISSING:

| # | Gap | Current State | Required | Priority |
|---|-----|--------------|----------|----------|
| AU-1 | No rate limiting on login/register | Zero rate limiting on `/api/login` and `/api/register` | 5 req/min per IP | CRITICAL |
| AU-2 | No account lockout | No tracking of failed login attempts | Lock after 5 failed attempts for 15 min | HIGH |
| AU-3 | No MFA implementation | Schema has `mfaRequired` field, UI has toggle, but no actual TOTP/OTP flow | TOTP-based MFA for admin+ roles | HIGH |
| AU-4 | Password reset has no rate limit | `/api/auth/forgot-password` can be spammed | 3 req/hour per email | HIGH |
| AU-5 | No login activity logging | Successful/failed logins not tracked | Log all auth events to audit_logs | MEDIUM |
| AU-6 | No concurrent session limit | User can have unlimited active sessions | Enforce `maxConcurrentSessions` from org policy | MEDIUM |
| AU-7 | Google OAuth not configured | Strategy code exists but `GOOGLE_CLIENT_ID` not set | Configure Emergent Google Auth | MEDIUM |
| AU-8 | GitHub OAuth not configured | Strategy code exists but `GITHUB_CLIENT_ID` not set | Configure if needed | LOW |
| AU-9 | No password expiry enforcement | Schema has `passwordExpiryDays: 90` but never checked | Force password change after expiry | LOW |
| AU-10 | No "remember me" option | Session always 7 days | Short session default, longer with "remember me" | LOW |

---

## 6. Org Security Policy — Schema Exists, Not Enforced

The `org_security_policies` table defines comprehensive security policies:

```
mfaRequired: boolean (default false)
sessionTimeoutMinutes: integer (default 480)
maxConcurrentSessions: integer (default 5)
passwordMinLength: integer (default 12)
passwordRequireUppercase: boolean (default true)
passwordRequireNumber: boolean (default true)
passwordRequireSpecial: boolean (default true)
passwordExpiryDays: integer (default 90)
ipAllowlistEnabled: boolean (default false)
ipAllowlistCidrs: text[]
deviceTrustRequired: boolean (default false)
```

**NONE of these are enforced at runtime.** They are stored in the database and displayed in the UI (`team-management.tsx` has the toggle for MFA), but:
- Password complexity is not checked during registration
- Session timeout is hardcoded to 7 days, not from policy
- MFA toggle saves to DB but no MFA flow exists
- IP allowlist is never checked
- Concurrent sessions are not limited
- Device trust is not implemented

| # | Policy | Schema | UI Toggle | Backend Enforcement | Status |
|---|--------|--------|-----------|-------------------|--------|
| P-1 | MFA Required | YES | YES (team-management) | NO | NOT ENFORCED |
| P-2 | Session Timeout | YES | YES | NO (hardcoded 7 days) | NOT ENFORCED |
| P-3 | Max Concurrent Sessions | YES | NO | NO | NOT ENFORCED |
| P-4 | Password Min Length | YES (12) | YES | NO | NOT ENFORCED |
| P-5 | Password Uppercase | YES | YES | NO | NOT ENFORCED |
| P-6 | Password Number | YES | YES | NO | NOT ENFORCED |
| P-7 | Password Special Char | YES | YES | NO | NOT ENFORCED |
| P-8 | Password Expiry Days | YES (90) | NO | NO | NOT ENFORCED |
| P-9 | IP Allowlist | YES | NO | NO | NOT ENFORCED |
| P-10 | Device Trust | YES | NO | NO | NOT ENFORCED |

**Fix**: Create enforcement middleware that reads org policy and validates against it during auth flows.

---

## 7. Plan Enforcement Gaps

### What EXISTS:
- Plan enforcement middleware at `/app/server/middleware/plan-enforcement.ts` (190 lines)
- Enhanced plan enforcement at `/app/server/middleware/plan-enforcement-enhanced.ts` (381 lines)
- Plan schema with tier definitions (plans table + subscriptions table)

### What's ENFORCED (5 metrics):
| Metric | Route | Status |
|--------|-------|--------|
| ai_analyses | ai.ts (7 checks) | ENFORCED |
| alerts_ingested | alerts.ts (1 check) | ENFORCED |
| connectors | connectors.ts (1 check) | ENFORCED |
| api_keys | ingestion.ts (1 check) | ENFORCED |
| playbooks | playbooks.ts (1 check) | ENFORCED |

### What's NOT ENFORCED (should be):
| Metric | Route | Risk | Priority |
|--------|-------|------|----------|
| incidents | incidents.ts | Unlimited incident creation | HIGH |
| reports | reports.ts | Unlimited report generation | MEDIUM |
| threat_intel_feeds | threat-intel.ts | Unlimited IOC feed subscriptions | MEDIUM |
| response_policies | autonomous.ts | Unlimited autonomous policies | MEDIUM |
| predictions | predictive.ts | Unlimited prediction runs | MEDIUM |
| endpoints_monitored | endpoints.ts | Unlimited endpoint tracking | MEDIUM |
| webhooks | webhooks.ts | Unlimited outbound webhooks | HIGH |
| integrations | integrations.ts | Unlimited integrations | MEDIUM |
| investigations | investigations.ts | Unlimited AI investigations (costs $$) | HIGH |
| users | orgs.ts | Unlimited team members per org | HIGH |
| teams | orgs.ts | Unlimited teams | LOW |

---

## 8. UI/UX Gaps & Bugs

### 8.1 Pages Missing data-testid Entirely

These critical pages have 0 or 1 data-testid attributes, making them untestable:

| Page | Lines | testids | Priority to Fix |
|------|-------|---------|----------------|
| dashboard.tsx | 1,325 | 0 | CRITICAL — primary user page |
| billing.tsx | 784 | 0 | HIGH — revenue-critical |
| dev-portal.tsx | 1,277 | 0 | HIGH — developer experience |
| platform-admin.tsx | 977 | 0 | HIGH — admin tooling |
| landing.tsx | 1,031 | 0 | MEDIUM — public page |
| mssp-dashboard.tsx | 634 | 0 | MEDIUM |
| dashboard-stunning.tsx | 504 | 0 | LOW — alternate dashboard |
| usage-billing.tsx | 532 | 0 | MEDIUM — billing page |
| forgot-password.tsx | 147 | 0 | HIGH — auth flow |
| reset-password.tsx | 268 | 0 | HIGH — auth flow |
| org-settings.tsx | 1,425 | 1 | HIGH — critical settings |
| onboarding-wizard.tsx | 801 | 1 | HIGH — first-time experience |

### 8.2 Pages With Potentially Incomplete API Integration

These pages have very few API calls compared to their complexity:

| Page | Lines | API Calls | Concern |
|------|-------|-----------|---------|
| analytics.tsx | 543 | 2 | May rely on mock/computed data |
| audit-log.tsx | 499 | 2 | Basic query only, filtering may not work |
| dashboard-stunning.tsx | 504 | 2 | Minimal data fetch for a dashboard variant |
| mitre-attack.tsx | 379 | 2 | May show static MITRE matrix without live data |
| onboarding.tsx | 221 | 2 | Simple redirect, OK |

### 8.3 Marketing/Content Pages (Static — Expected)

These 9 pages have no API calls because they're static content. No action needed:
- about.tsx, agentic-soc.tsx, ai-soc-analyst.tsx, product-overview.tsx
- solutions-compliance.tsx, solutions-india.tsx, solutions-mssp.tsx
- content-layout.tsx, not-found.tsx

### 8.4 UI Features That Exist in Schema/Backend But Have No Frontend Button/Trigger

| Feature | Backend | UI Exists | UI Gap |
|---------|---------|-----------|--------|
| Suppress/unsuppress alerts | `/api/alerts/:id/suppress` | Partial | Button may not be wired |
| Archive alerts | `/api/alerts/archive` | Unknown | No visible archive action |
| Incident escalation | `/api/incidents/:id/escalate` | In detail page | Verify button wired |
| Incident containment | `/api/incidents/:id/contain` | In detail page | Verify button wired |
| Playbook blast radius | `/api/playbooks/:id/blast-radius` | References exist | May not be fully wired |
| Playbook simulation | `/api/playbooks/:id/simulate` | References exist | May not be fully wired |
| Rollback response action | `/api/autonomous/rollbacks/:id/execute` | Unknown | Needs verification |
| Evidence chain verification | `/api/compliance/audit/verify` | Unknown | Needs verification |

### 8.5 Dashboard Not Connected to Real Data

Both `dashboard.tsx` and `dashboard-stunning.tsx` exist but:
- `dashboard.tsx` has 3 API calls (basic)
- `dashboard-stunning.tsx` has 2 API calls + mock references
- The stunning dashboard backend (`stunning-dashboard.ts`) has 3 mock references

**Risk**: Dashboard shows fabricated metrics instead of real SOC data.

---

## 9. Route-Level Security Audit

### Fully Secured Routes (GOOD — no action needed):
| Route File | Auth | RBAC | Org Scope | Plan Limit |
|-----------|------|------|-----------|-----------|
| admin.ts | YES | requireMinRole("admin") | YES | — |
| alerts.ts | YES | requirePermission | YES | YES |
| ai.ts | YES | requirePermission | YES | YES |
| billing.ts | YES | requireMinRole | YES | — |
| compliance.ts | YES | requireMinRole | YES | — |
| connectors.ts | YES | requirePermission | YES | YES |
| incidents.ts | YES | requirePermission | YES | — |
| ingestion.ts | YES | requirePermission | YES | YES |
| orgs.ts | YES | requireMinRole | YES | — |
| platform-admin.ts | YES | requireSuperAdmin | — | — |
| dev-portal.ts | YES | requireSuperAdmin | — | — |
| sso.ts | YES | requireMinRole("admin") | YES | — |
| enterprise-org.ts | YES | requireMinRole | YES | — |
| domain-autojoin.ts | YES | requireMinRole | YES | — |
| mssp.ts | YES | requireMinRole | YES | — |
| shared.ts | YES | requireMinRole | YES | — |
| tenant-isolation.ts | YES | requireMinRole | YES | — |
| commercial.ts | YES | requireMinRole | YES | — |
| operations.ts | YES | requireMinRole | YES | — |

### Partially Secured Routes (need RBAC):
| Route File | Auth | Missing | Fix Needed |
|-----------|------|---------|-----------|
| playbooks.ts | YES | RBAC role checks | Add requireMinRole("analyst") for read, requireMinRole("admin") for write/execute |
| integrations.ts | YES | RBAC role checks | Add requireMinRole("admin") for configuration |
| usage.ts | YES | RBAC role checks | Add requireMinRole("analyst") for read |

### Unsecured Routes (need RBAC + Org Scope):
| Route File | Auth | Missing | Fix Needed |
|-----------|------|---------|-----------|
| autonomous.ts | YES (custom) | RBAC + Org Scope | Add requireMinRole("admin") + resolveOrgContext |
| predictive.ts | YES (custom) | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| investigations.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| threat-intel.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") for read, admin for write |
| entities.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| endpoints.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| webhooks.ts | YES | RBAC + Org Scope | Add requireMinRole("admin") + resolveOrgContext |
| report-governance.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| reports.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| files.ts | YES | RBAC + Org Scope | Add requireMinRole("analyst") + resolveOrgContext |
| events.ts | YES | Org Scope | Add resolveOrgContext (already filters by orgId) |
| dashboard.ts | YES | Org Scope | Add resolveOrgContext |
| stunning-dashboard.ts | YES | Org Scope | Add resolveOrgContext |
| onboarding.ts | YES | Org Scope | Add resolveOrgContext (self-service is OK) |
| api-versioning.ts | YES | Org Scope | Add resolveOrgContext |

### Properly Public Routes (no fix needed):
| Route | Reason |
|-------|--------|
| health.ts | Health check, expected to be public |
| password-reset.ts | Public by design (forgot password flow) |

---

## 10. Development Plan

### Phase 1: Critical Security Fixes (MUST DO FIRST)

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 1 | Fix BUG-1: Remove auto-join-as-owner logic | auth/routes.ts lines 59-68 | Small | P0-CRITICAL |
| 2 | Fix BUG-2: Add work email validation blocklist | auth/routes.ts, new: `email-validator.ts` | Small | P0-CRITICAL |
| 3 | Fix BUG-3: Add password complexity validation | auth/routes.ts | Small | P0-CRITICAL |
| 4 | Fix BUG-4: Add super admin bootstrap mechanism | seed.ts or new env var `SUPER_ADMIN_EMAIL` | Small | P0-CRITICAL |
| 5 | Add rate limiting on auth endpoints | auth/routes.ts, security-middleware.ts | Small | P0-HIGH |
| 6 | Add account lockout after failed attempts | auth/routes.ts, new: login attempt tracking | Medium | P0-HIGH |
| 7 | Add login activity audit logging | auth/routes.ts | Small | P1 |

### Phase 2: RBAC & Org Scope Enforcement

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 8 | Add RBAC to autonomous.ts (13 endpoints) | routes/autonomous.ts | Medium | P0-HIGH |
| 9 | Add RBAC to predictive.ts (10 endpoints) | routes/predictive.ts | Medium | P0-HIGH |
| 10 | Add RBAC to investigations.ts | routes/investigations.ts | Medium | P0-HIGH |
| 11 | Add RBAC to threat-intel.ts (40 auth refs) | routes/threat-intel.ts | Medium | P0-HIGH |
| 12 | Add RBAC to webhooks.ts | routes/webhooks.ts | Small | P0-HIGH |
| 13 | Add RBAC to endpoints.ts | routes/endpoints.ts | Small | P1 |
| 14 | Add RBAC to entities.ts | routes/entities.ts | Small | P1 |
| 15 | Add RBAC to playbooks.ts | routes/playbooks.ts | Small | P1 |
| 16 | Add RBAC to reports.ts + report-governance.ts | routes/reports.ts, routes/report-governance.ts | Small | P1 |
| 17 | Add RBAC to integrations.ts | routes/integrations.ts | Small | P1 |
| 18 | Add RBAC to files.ts | routes/files.ts | Small | P1 |
| 19 | Add org scope to all routes missing it | 15 route files (listed in Section 9) | Medium | P1 |

### Phase 3: Security Policy Enforcement

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 20 | Enforce password complexity from org policy | auth/routes.ts + new middleware | Medium | P1 |
| 21 | Enforce session timeout from org policy | auth/session.ts | Small | P1 |
| 22 | Implement MFA (TOTP) flow | New: `mfa.ts` route + UI component | Large | P2 |
| 23 | Enforce max concurrent sessions | auth/session.ts | Medium | P2 |
| 24 | Implement IP allowlist enforcement | New middleware | Medium | P2 |
| 25 | Implement password expiry check | auth middleware | Small | P2 |

### Phase 4: Plan Enforcement Expansion

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 26 | Add plan limits for incidents | routes/incidents.ts | Small | P1 |
| 27 | Add plan limits for users/team members | routes/orgs.ts | Small | P1 |
| 28 | Add plan limits for investigations (AI cost) | routes/investigations.ts | Small | P1 |
| 29 | Add plan limits for webhooks | routes/webhooks.ts | Small | P1 |
| 30 | Add plan limits for reports | routes/reports.ts | Small | P2 |
| 31 | Add plan limits for threat intel feeds | routes/threat-intel.ts | Small | P2 |
| 32 | Add plan limits for integrations | routes/integrations.ts | Small | P2 |
| 33 | Add plan limits for endpoints monitored | routes/endpoints.ts | Small | P2 |
| 34 | Add plan limits for autonomous policies | routes/autonomous.ts | Small | P2 |
| 35 | Add plan limits for predictions | routes/predictive.ts | Small | P2 |

### Phase 5: Admin & Developer Platform Activation

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 36 | Bootstrap super admin from env var | seed.ts or new bootstrap script | Small | P0 (blocked until BUG-4 fixed) |
| 37 | Add "promote to super admin" API | routes/platform-admin.ts | Small | P1 |
| 38 | Add data-testid to platform-admin.tsx | pages/platform-admin.tsx | Medium | P1 |
| 39 | Add data-testid to dev-portal.tsx | pages/dev-portal.tsx | Medium | P1 |
| 40 | Audit dev-portal raw SQL endpoint | routes/dev-portal.ts | Small | P1 |
| 41 | Connect revenue dashboard to Stripe data | routes/platform-admin.ts | Medium | P2 |

### Phase 6: UI/UX Testability & Polish

| # | Task | File(s) | Effort | Priority |
|---|------|---------|--------|----------|
| 42 | Add data-testid to dashboard.tsx (1,325 lines) | pages/dashboard.tsx | Medium | P1 |
| 43 | Add data-testid to billing.tsx (784 lines) | pages/billing.tsx | Medium | P1 |
| 44 | Add data-testid to org-settings.tsx (1,425 lines) | pages/org-settings.tsx | Medium | P1 |
| 45 | Add data-testid to onboarding-wizard.tsx (801 lines) | pages/onboarding-wizard.tsx | Medium | P1 |
| 46 | Add data-testid to forgot/reset password | pages/forgot-password.tsx, reset-password.tsx | Small | P1 |
| 47 | Add data-testid to usage-billing.tsx | pages/usage-billing.tsx | Small | P2 |
| 48 | Add data-testid to mssp-dashboard.tsx | pages/mssp-dashboard.tsx | Small | P2 |
| 49 | Add data-testid to landing.tsx | pages/landing.tsx | Small | P2 |
| 50 | Verify dashboard shows real data (not mocks) | pages/dashboard.tsx, routes/dashboard.ts | Medium | P1 |
| 51 | Verify all incident lifecycle buttons are wired | pages/incident-detail.tsx | Medium | P1 |
| 52 | Verify playbook simulation/blast radius UI works | pages/playbooks.tsx | Medium | P2 |

---

## Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Security Bugs | 4 | 2 | 1 | 0 | 7 |
| RBAC/Access Control | 5 | 6 | 4 | 0 | 15 |
| Org Security Policy | 0 | 2 | 3 | 5 | 10 |
| Plan Enforcement | 0 | 3 | 7 | 0 | 10 |
| Admin Platform | 2 | 2 | 2 | 0 | 6 |
| Developer Platform | 1 | 1 | 1 | 2 | 5 |
| Auth & Sessions | 2 | 3 | 3 | 2 | 10 |
| UI/UX Testability | 0 | 6 | 6 | 3 | 15 |
| **TOTAL** | **14** | **25** | **27** | **12** | **78** |

**14 critical issues, 25 high, 27 medium, 12 low = 78 total gaps to close.**
