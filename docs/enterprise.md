# SecureNexus Enterprise Implementation Roadmap

> Comprehensive phase-by-phase plan for transforming SecureNexus from a single-tenant SOC platform into a fully enterprise-ready, multi-tenant SaaS product with subscription billing, client onboarding, organizational hierarchy, and platform administration.

---

## Table of Contents

- [Current State Audit](#current-state-audit)
- [Phase 1: Organization Management & Settings](#phase-1-organization-management--settings)
- [Phase 2: Business Onboarding Wizard](#phase-2-business-onboarding-wizard)
- [Phase 3: Subscription & Billing (Stripe)](#phase-3-subscription--billing-stripe)
- [Phase 4: Invitation System & Email (SES)](#phase-4-invitation-system--email-ses)
- [Phase 5: Platform Super-Admin Dashboard](#phase-5-platform-super-admin-dashboard)
- [Phase 6: Domain Auto-Join & SSO](#phase-6-domain-auto-join--sso)
- [Phase 7: MSSP / Parent-Child Organizations](#phase-7-mssp--parent-child-organizations)
- [Phase 8: Usage Metering & Plan Enforcement](#phase-8-usage-metering--plan-enforcement)
- [Phase 9: Security Hardening for Multi-Tenancy](#phase-9-security-hardening-for-multi-tenancy)
- [Phase 10: Audit, Compliance & Data Residency](#phase-10-audit-compliance--data-residency)
- [Infrastructure Reference](#infrastructure-reference)

---

## Current State Audit

### What Already Exists

| Component | Location | Status |
|---|---|---|
| **Organizations table** | `shared/schema.ts` line 87 | `id, name, slug, industry, contactEmail, maxUsers` |
| **Organization Memberships** | `shared/schema.ts` line 1113 | `orgId, userId, role, status, invitedBy, invitedEmail, joinedAt, suspendedAt` |
| **Org Invitations** | `shared/schema.ts` line 1131 | Token-based with email, role, expiry, acceptedAt |
| **RBAC Roles** | `shared/schema.ts` line 52 | 4 roles: `owner`, `admin`, `analyst`, `read_only` |
| **Permission Matrix** | `shared/schema.ts` line 52 | Scopes: `incidents`, `connectors`, `api_keys`, `response_actions`, `settings`, `team` with `read/write/admin` actions |
| **RBAC Middleware** | `server/rbac.ts` | `resolveOrgContext`, `requireOrgRole`, `requireMinRole`, `requirePermission` |
| **Team Management UI** | `client/src/pages/team-management.tsx` | Members tab (list, change role, suspend, activate, remove), Invitations tab (create, cancel), Audit Trail tab |
| **Technical Onboarding** | `client/src/pages/onboarding.tsx` | 4-step checklist: integrations, ingestion, endpoints, CSPM |
| **Settings Page** | `client/src/pages/settings.tsx` | Profile, roles display, hardcoded plan cards (Free/Pro/Enterprise), threat intel keys, webhooks |
| **Auth Routes** | `server/replit_integrations/auth/routes.ts` | Register, login, logout, Google OAuth, GitHub OAuth, providers endpoint |
| **Auto-Provisioning** | `server/replit_integrations/auth/routes.ts` line 7 | `ensureOrgMembership()` — new user auto-creates org or joins first existing org |
| **Audit Logs** | `shared/schema.ts` line 227 | Full audit trail table with userId, action, resourceType, resourceId, details, ipAddress |
| **API Key Auth** | `server/routes.ts` line 59 | Alternative auth via `X-API-Key` header for programmatic access |

### What's Missing

| Gap | Impact | Phase |
|---|---|---|
| No subscription/billing tables | Cannot enforce plan limits or collect payment | Phase 3 |
| No Stripe integration | No payment processing | Phase 3 |
| No business onboarding wizard | Users land on technical onboarding without org setup or plan selection | Phase 2 |
| No org switcher UI | Users in multiple orgs cannot switch between them | Phase 1 |
| No org settings page | Cannot edit org name, logo, industry, contact info | Phase 1 |
| No invitation emails | Invitations exist in DB but no email is sent | Phase 4 |
| No plan limit enforcement | `maxUsers` exists but is never checked; no alert/connector limits enforced | Phase 8 |
| No platform admin panel | No way to view all orgs, subscriptions, platform metrics | Phase 5 |
| No domain auto-join | Cannot auto-assign users by email domain to an org | Phase 6 |
| No SSO/SAML | Enterprise clients need SSO — currently only email + Google + GitHub | Phase 6 |
| No parent-child orgs | MSSPs cannot manage multiple client orgs | Phase 7 |
| No usage metering | Cannot track alerts ingested, API calls, storage used per org | Phase 8 |
| No data residency controls | All data in us-east-1, no per-org region selection | Phase 10 |

---

## Phase 1: Organization Management & Settings

**Goal:** Let org owners manage their organization details and switch between orgs.

**Estimated Effort:** 2-3 days

### 1.1 Organization Settings Page

**New file:** `client/src/pages/org-settings.tsx`

**UI sections:**

| Section | Fields | Who Can Edit |
|---|---|---|
| **General** | Org name, slug (read-only), industry dropdown, company size | Owner, Admin |
| **Contact** | Contact email, billing email, phone, address | Owner, Admin |
| **Branding** | Logo upload (to S3), primary color hex | Owner, Admin |
| **Danger Zone** | Delete organization (owner only, requires confirmation + type org name) | Owner only |

**Backend routes to add in `server/routes.ts`:**

```
GET    /api/orgs/:orgId                    → Get org details (any member)
PATCH  /api/orgs/:orgId                    → Update org details (admin+)
DELETE /api/orgs/:orgId                    → Delete org (owner only)
POST   /api/orgs/:orgId/logo              → Upload logo to S3 (admin+)
POST   /api/orgs/:orgId/transfer-ownership → Transfer owner role (owner only)
```

**Schema changes in `shared/schema.ts`:**

```typescript
// Extend organizations table
export const organizations = pgTable("organizations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  industry: text("industry"),
  companySize: text("company_size"),         // NEW: "1-10", "11-50", "51-200", "201-1000", "1001+"
  contactEmail: text("contact_email"),
  billingEmail: text("billing_email"),       // NEW
  phone: text("phone"),                      // NEW
  address: jsonb("address"),                 // NEW: { line1, line2, city, state, country, zip }
  logoUrl: text("logo_url"),                 // NEW: S3 URL
  primaryColor: text("primary_color"),       // NEW: hex color for white-labeling
  timezone: text("timezone"),                // NEW: default timezone for the org
  maxUsers: integer("max_users").default(10),
  deletedAt: timestamp("deleted_at"),        // NEW: soft delete
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(), // NEW
});
```

**How it works with current infra:**

- Logo uploads go to existing S3 bucket `securenexus-platform-557845624595` under key `orgs/{orgId}/logo.{ext}`
- DB schema migration via Drizzle `npx drizzle-kit push` against RDS `securenexus-db.cspsu4cuei9t.us-east-1.rds.amazonaws.com`
- No new AWS resources needed

### 1.2 Organization Switcher

**Where:** Sidebar header (in `client/src/components/app-sidebar.tsx`)

**How it works:**

1. On app load, call `GET /api/auth/me` — returns all org memberships for the current user
2. Store `activeOrgId` in React context (and localStorage for persistence)
3. All API calls include `X-Org-Id: {activeOrgId}` header (already supported by `resolveOrgContext` middleware in `server/rbac.ts` line 29)
4. Sidebar header shows current org name + dropdown to switch
5. Switching orgs refreshes all queries via `queryClient.invalidateQueries()`

**New React context:** `client/src/contexts/org-context.tsx`

```typescript
interface OrgContextType {
  currentOrg: Organization | null;
  memberships: OrganizationMembership[];
  currentRole: string;
  switchOrg: (orgId: string) => void;
  isLoading: boolean;
}
```

**Frontend changes:**

- `app-sidebar.tsx`: Add org switcher dropdown in sidebar header
- `lib/queryClient.ts`: Add interceptor to attach `X-Org-Id` header to all API calls
- `hooks/use-auth.ts`: Expose org context alongside user context

### 1.3 Ownership Transfer

**Route:** `POST /api/orgs/:orgId/transfer-ownership`

**Body:** `{ newOwnerId: string }`

**Logic:**
1. Verify current user is owner
2. Verify target user is an active member of this org
3. Update current owner's role to `admin`
4. Update target user's role to `owner`
5. Create audit log entry
6. Return updated memberships

**Safeguard:** Require current owner to re-enter password before transfer.

---

## Phase 2: Business Onboarding Wizard

**Goal:** Guide new clients through a complete onboarding flow: create org → choose plan → invite team → connect first integration.

**Estimated Effort:** 3-4 days

### 2.1 Onboarding Flow Architecture

```
Sign Up (email/Google/GitHub)
  │
  ▼
Step 1: Create Organization
  │  Name, industry, company size
  ▼
Step 2: Choose Plan
  │  Free / Pro / Enterprise
  │  Stripe Checkout for paid plans
  ▼
Step 3: Invite Team
  │  Bulk email input + role assignment
  │  Skip option for solo users
  ▼
Step 4: Connect First Integration
  │  Pick from connector catalog
  │  Guided setup with test connection
  ▼
Step 5: Dashboard Tour
  │  Interactive overlay highlighting key features
  │  Can be dismissed and replayed from Settings
  ▼
Dashboard (fully onboarded)
```

### 2.2 New Files

| File | Purpose |
|---|---|
| `client/src/pages/onboarding-wizard.tsx` | Multi-step wizard container with progress bar |
| `client/src/components/onboarding/step-create-org.tsx` | Org creation form |
| `client/src/components/onboarding/step-choose-plan.tsx` | Plan selection cards with Stripe checkout |
| `client/src/components/onboarding/step-invite-team.tsx` | Bulk invite form with role dropdowns |
| `client/src/components/onboarding/step-connect-integration.tsx` | Connector catalog with guided setup |
| `client/src/components/onboarding/step-dashboard-tour.tsx` | Interactive feature tour overlay |

### 2.3 Backend Changes

**New routes:**

```
GET  /api/onboarding/wizard-status     → Returns current step + completion status
POST /api/onboarding/create-org        → Creates org with extended fields
POST /api/onboarding/select-plan       → Creates Stripe checkout session (or activates free plan)
POST /api/onboarding/invite-team       → Bulk create invitations
POST /api/onboarding/complete          → Mark onboarding as complete
```

**Schema addition:**

```typescript
export const onboardingProgress = pgTable("onboarding_progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id),
  userId: varchar("user_id").notNull(),
  currentStep: integer("current_step").notNull().default(1),
  stepsCompleted: jsonb("steps_completed").default({}),
  // { createOrg: true, choosePlan: true, inviteTeam: false, connectIntegration: false, dashboardTour: false }
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});
```

### 2.4 Auto-Provisioning Changes

**Current behavior** (`server/replit_integrations/auth/routes.ts` line 7):
- New user → auto-creates org with name `"{email}'s Organization"` → assigns owner role
- No plan, no onboarding

**New behavior:**
- New user → check if they have any org memberships
- If no memberships and no pending invitations → redirect to `/onboarding` wizard
- Wizard creates the org properly (with industry, size, etc.)
- After wizard completion → redirect to dashboard
- If user has pending invitation → accept it → skip org creation → redirect to dashboard

**How to detect first-time user in frontend:**

```typescript
// In App.tsx route guard
const { data: me } = useQuery({ queryKey: ["/api/auth/me"] });
if (me && me.memberships.length === 0) {
  return <Redirect to="/onboarding" />;
}
```

### 2.5 Dashboard Tour

**Implementation:** Use a lightweight library like `react-joyride` or build custom with Radix popover.

**Tour stops:**
1. Sidebar navigation overview
2. Dashboard metrics explanation
3. Alert trend chart
4. Command palette (Ctrl+K)
5. Notification bell
6. Settings link

**Persistence:** Store `tourCompleted: boolean` in `onboardingProgress.stepsCompleted` so it only shows once.

### 2.6 How This Works With Current Infra

- No new AWS resources — all stored in existing RDS database
- Wizard pages served by existing Vite frontend (client-side routing)
- Stripe Checkout redirects happen client-side (no new server infrastructure)
- CI/CD pipeline deploys wizard code alongside existing app via same Docker image → ECR → EKS flow

---

## Phase 3: Subscription & Billing (Stripe)

**Goal:** Implement a complete subscription lifecycle with Stripe: plan selection, checkout, upgrades/downgrades, invoices, and cancellation.

**Estimated Effort:** 4-5 days

### 3.1 Plan Definitions

| Feature | Free | Pro ($49/mo) | Enterprise ($199/mo) | Custom |
|---|---|---|---|---|
| **Alerts/month** | 100 | 10,000 | Unlimited | Custom |
| **Connectors** | 2 | 10 | Unlimited | Custom |
| **Users** | 1 | 5 | Unlimited | Custom |
| **Data retention** | 7 days | 30 days | 365 days | Custom |
| **API keys** | 1 | 10 | 50 | Custom |
| **AI Engine** | No | Yes | Yes | Yes |
| **SOAR Automation** | No | No | Yes | Yes |
| **CSPM Scanning** | No | Yes | Yes | Yes |
| **IOC Threat Intel** | No | Yes | Yes | Yes |
| **Custom playbooks** | No | 5 | Unlimited | Custom |
| **SSO/SAML** | No | No | Yes | Yes |
| **Compliance reports** | No | No | Yes | Yes |
| **Priority support** | No | No | Yes | Yes |
| **SLA guarantee** | No | No | 99.9% | Custom |

### 3.2 Database Schema

```typescript
export const PLAN_NAMES = ["free", "pro", "enterprise", "custom"] as const;
export const SUBSCRIPTION_STATUSES = ["trialing", "active", "past_due", "cancelled", "paused"] as const;
export const BILLING_CYCLES = ["monthly", "annual"] as const;

export const plans = pgTable("plans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),           // free, pro, enterprise, custom
  displayName: text("display_name").notNull(),
  description: text("description"),
  priceMonthly: integer("price_monthly").notNull(), // cents (e.g., 4900 = $49)
  priceAnnual: integer("price_annual").notNull(),   // cents (e.g., 47040 = $470.40 = $39.20/mo)
  stripePriceIdMonthly: text("stripe_price_id_monthly"),
  stripePriceIdAnnual: text("stripe_price_id_annual"),
  features: jsonb("features").notNull(),
  // { maxAlerts: 10000, maxConnectors: 10, maxUsers: 5, maxApiKeys: 10,
  //   retentionDays: 30, aiEnabled: true, soarEnabled: false, cspmEnabled: true,
  //   iocEnabled: true, maxPlaybooks: 5, ssoEnabled: false, complianceReports: false,
  //   prioritySupport: false, slaGuarantee: null }
  isActive: boolean("is_active").default(true),
  sortOrder: integer("sort_order").default(0),
  createdAt: timestamp("created_at").defaultNow(),
});

export const subscriptions = pgTable("subscriptions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id).unique(),
  planId: varchar("plan_id").notNull().references(() => plans.id),
  status: text("status").notNull().default("active"),  // trialing, active, past_due, cancelled, paused
  billingCycle: text("billing_cycle").notNull().default("monthly"),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  trialEndsAt: timestamp("trial_ends_at"),
  currentPeriodStart: timestamp("current_period_start"),
  currentPeriodEnd: timestamp("current_period_end"),
  cancelledAt: timestamp("cancelled_at"),
  cancelReason: text("cancel_reason"),
  customFeatureOverrides: jsonb("custom_feature_overrides"), // for custom plans
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_subscriptions_org").on(table.orgId),
  index("idx_subscriptions_stripe_customer").on(table.stripeCustomerId),
  index("idx_subscriptions_status").on(table.status),
]);

export const invoices = pgTable("invoices", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id),
  subscriptionId: varchar("subscription_id").notNull().references(() => subscriptions.id),
  stripeInvoiceId: text("stripe_invoice_id"),
  amountDue: integer("amount_due"),       // cents
  amountPaid: integer("amount_paid"),     // cents
  currency: text("currency").default("usd"),
  status: text("status").notNull(),       // draft, open, paid, void, uncollectible
  invoicePdfUrl: text("invoice_pdf_url"),
  hostedInvoiceUrl: text("hosted_invoice_url"),
  periodStart: timestamp("period_start"),
  periodEnd: timestamp("period_end"),
  paidAt: timestamp("paid_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_invoices_org").on(table.orgId),
  index("idx_invoices_subscription").on(table.subscriptionId),
]);
```

### 3.3 Stripe Integration

**New dependency:** `stripe` npm package

**New file:** `server/stripe.ts`

**Environment variables (stored in AWS Secrets Manager):**

```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PUBLISHABLE_KEY=pk_live_...   (sent to frontend via /api/config endpoint)
```

**Backend routes:**

```
POST /api/billing/create-checkout-session    → Create Stripe Checkout for plan upgrade
POST /api/billing/create-portal-session      → Create Stripe Customer Portal session
GET  /api/billing/subscription               → Get current subscription details
POST /api/billing/change-plan                → Upgrade/downgrade plan
POST /api/billing/cancel                     → Cancel subscription (end of period)
POST /api/billing/reactivate                 → Reactivate cancelled subscription
GET  /api/billing/invoices                   → List invoices for current org
GET  /api/billing/usage                      → Get current usage vs plan limits
POST /api/webhooks/stripe                    → Stripe webhook endpoint (no auth)
```

**Stripe webhook events to handle:**

| Event | Action |
|---|---|
| `checkout.session.completed` | Activate subscription, update plan |
| `invoice.paid` | Record invoice, update subscription period |
| `invoice.payment_failed` | Set subscription status to `past_due`, notify owner via email |
| `customer.subscription.updated` | Sync plan changes (upgrade/downgrade) |
| `customer.subscription.deleted` | Set status to `cancelled`, downgrade to free plan |
| `customer.subscription.trial_will_end` | Send email warning 3 days before trial ends |

**Webhook security:**
- Verify Stripe webhook signature using `stripe.webhooks.constructEvent(body, sig, webhookSecret)`
- Webhook endpoint is excluded from session auth (uses Stripe signature instead)
- Webhook endpoint is excluded from CSRF protection
- Webhook endpoint is excluded from rate limiting

### 3.4 Frontend: Billing Page

**New file:** `client/src/pages/billing.tsx`

**Sections:**

| Section | Content |
|---|---|
| **Current Plan** | Plan name, status badge, renewal date, usage meters (alerts, connectors, users, API keys) |
| **Plan Comparison** | 3 cards (Free/Pro/Enterprise) with feature comparison matrix, "Current" / "Upgrade" / "Contact Sales" buttons |
| **Payment Method** | Card on file (last 4 digits), "Manage" button opens Stripe Customer Portal |
| **Invoices** | Table: date, amount, status, PDF download link |
| **Cancel/Reactivate** | Red danger zone for cancellation, shows what access will be lost |

### 3.5 How This Works With Current Infra

- **Stripe API calls** happen server-side from EKS pods — no new AWS resources needed
- **Stripe webhook** endpoint receives POST from Stripe → needs to be publicly accessible → already is via ELB
- **Stripe keys** stored in AWS Secrets Manager (`securenexus/staging`, `securenexus/production`) → synced to K8s secrets by CI/CD pipeline (`.github/workflows/ci-cd.yml` lines 92-101)
- **Plans table** seeded via existing `server/seed.ts` mechanism
- **Frontend** adds billing page to existing React router — same Docker image, same deployment

**CI/CD pipeline change:** Add `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PUBLISHABLE_KEY` to the secrets sync step in `.github/workflows/ci-cd.yml` for all environments.

---

## Phase 4: Invitation System & Email (SES)

**Goal:** Send actual invitation emails, password reset emails, and billing notifications via Amazon SES.

**Estimated Effort:** 2-3 days

### 4.1 Amazon SES Setup

**AWS resources to provision:**

| Resource | Config | Notes |
|---|---|---|
| **SES verified domain** | `aricatech.xyz` | Verify via DNS TXT record |
| **SES sending identity** | `noreply@aricatech.xyz` | For transactional emails |
| **SES configuration set** | `securenexus-emails` | For tracking bounces/complaints |
| **IAM policy** | `ses:SendEmail`, `ses:SendRawEmail` | Attach to EKS pod IAM role |

**Environment variables:**

```
SES_FROM_EMAIL=noreply@aricatech.xyz
SES_REGION=us-east-1
```

**SES is already available in us-east-1 under account 557845624595.** No new infrastructure needed beyond domain verification and IAM policy.

### 4.2 Email Service

**New file:** `server/email.ts`

```typescript
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(options: EmailOptions): Promise<void> {
  const ses = new SESv2Client({ region: process.env.SES_REGION || "us-east-1" });
  await ses.send(new SendEmailCommand({
    FromEmailAddress: process.env.SES_FROM_EMAIL,
    Destination: { ToAddresses: Array.isArray(options.to) ? options.to : [options.to] },
    Content: {
      Simple: {
        Subject: { Data: options.subject },
        Body: {
          Html: { Data: options.html },
          ...(options.text ? { Text: { Data: options.text } } : {}),
        },
      },
    },
  }));
}
```

### 4.3 Email Templates

**New directory:** `server/email-templates/`

| Template | Trigger | Content |
|---|---|---|
| `invitation.html` | `POST /api/orgs/:orgId/invitations` | "You've been invited to join {orgName} on SecureNexus. Click here to accept." |
| `welcome.html` | User completes registration | "Welcome to SecureNexus! Here's how to get started." |
| `password-reset.html` | `POST /api/auth/forgot-password` | "Click here to reset your password. Link expires in 1 hour." |
| `payment-failed.html` | Stripe `invoice.payment_failed` webhook | "Your payment for SecureNexus failed. Please update your payment method." |
| `trial-ending.html` | Stripe `customer.subscription.trial_will_end` webhook | "Your trial ends in 3 days. Upgrade to keep full access." |
| `subscription-cancelled.html` | Stripe `customer.subscription.deleted` webhook | "Your subscription has been cancelled. Access continues until {periodEnd}." |
| `member-suspended.html` | `POST /api/orgs/:orgId/members/:memberId/suspend` | "Your access to {orgName} has been suspended by an administrator." |
| `member-role-changed.html` | `PATCH /api/orgs/:orgId/members/:memberId/role` | "Your role in {orgName} has been changed to {newRole}." |

**Template engine:** Use simple string interpolation (no external dependency). Each template is a function that takes variables and returns HTML string.

### 4.4 Password Reset Flow

**Currently missing entirely. Routes to add:**

```
POST /api/auth/forgot-password       → Generate reset token, send email
POST /api/auth/reset-password         → Validate token, update password
```

**Schema addition:**

```typescript
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  usedAt: timestamp("used_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_reset_tokens_user").on(table.userId),
  index("idx_reset_tokens_token").on(table.token),
]);
```

**Frontend pages:**
- `client/src/pages/forgot-password.tsx` — email input form
- `client/src/pages/reset-password.tsx` — new password form (accessed via token in URL)

### 4.5 Invitation Email Flow

**Current flow** (broken):
1. Admin creates invitation → token stored in DB → nothing else happens
2. Invited user must manually navigate to the app and somehow know to accept

**New flow:**
1. Admin creates invitation → token stored in DB → email sent via SES
2. Email contains link: `https://nexus.aricatech.xyz/invite/accept?token={token}`
3. User clicks link → if logged in, auto-accepts → if not, redirected to signup with invitation context
4. After signup/login, invitation auto-accepted, user lands in the org's dashboard

**Frontend page:** `client/src/pages/accept-invitation.tsx`

### 4.6 How This Works With Current Infra

- **SES** is already available in the AWS account (us-east-1) — just needs domain verification
- **EKS pods** already have AWS credentials via K8s secrets — add `ses:SendEmail` permission to the IAM role
- **SES credentials** don't need separate keys — pods use the same `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` already in K8s secrets
- **DNS records** for SES verification added alongside existing CNAME records for `staging.aricatech.xyz` / `nexus.aricatech.xyz`
- **No new npm dependencies** — `@aws-sdk/client-sesv2` is included in the AWS SDK already available

---

## Phase 5: Platform Super-Admin Dashboard

**Goal:** Build an internal admin panel for platform operators to manage all organizations, subscriptions, and platform health.

**Estimated Effort:** 3-4 days

### 5.1 Super-Admin Role

**Schema change:**

```typescript
// Add to users table in shared/models/auth.ts
isSuperAdmin: boolean("is_super_admin").default(false),
```

**Middleware:**

```typescript
// server/rbac.ts
export function requireSuperAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user?.isSuperAdmin) {
    return res.status(403).json({ error: "Super admin access required" });
  }
  next();
}
```

**Security:** Super-admin flag is ONLY set directly in the database by a DBA. It cannot be set via any API endpoint. This prevents privilege escalation.

### 5.2 Admin API Routes

All routes prefixed with `/api/admin/` and protected by `requireSuperAdmin` middleware.

```
GET  /api/admin/stats                        → Platform-wide metrics
GET  /api/admin/organizations                → List all orgs with pagination, search, filters
GET  /api/admin/organizations/:orgId         → Full org details including subscription, members, usage
PATCH /api/admin/organizations/:orgId        → Update org (e.g., custom plan limits)
POST /api/admin/organizations/:orgId/suspend → Suspend an entire org
POST /api/admin/organizations/:orgId/activate → Reactivate suspended org
GET  /api/admin/users                        → List all users across all orgs
GET  /api/admin/users/:userId                → User details + all org memberships
POST /api/admin/users/:userId/impersonate    → Generate impersonation session
POST /api/admin/users/:userId/disable        → Disable user account
POST /api/admin/users/:userId/reset-password → Force password reset
GET  /api/admin/subscriptions                → All subscriptions with status filters
GET  /api/admin/subscriptions/mrr            → Monthly Recurring Revenue breakdown
GET  /api/admin/audit-logs                   → Platform-wide audit log
GET  /api/admin/health                       → Platform health (RDS, EKS, S3, SES status)
```

### 5.3 Admin Dashboard UI

**New route:** `/admin` (only visible to super-admins)

**New file:** `client/src/pages/admin/admin-dashboard.tsx`

**Layout:** Full-width layout (no sidebar) with its own nav tabs.

**Tabs:**

| Tab | Content |
|---|---|
| **Overview** | Total orgs, total users, total alerts (all orgs), MRR, growth charts |
| **Organizations** | Searchable table: name, plan, status, users, alerts, created date, actions |
| **Users** | Searchable table: name, email, orgs, last login, status, actions (impersonate, disable) |
| **Subscriptions** | Table: org, plan, status, amount, renewal date, payment method status |
| **Revenue** | MRR chart, plan distribution pie chart, churn rate, upgrade/downgrade trends |
| **Audit Log** | Platform-wide audit log with filters (org, user, action type, date range) |
| **Health** | Real-time status of RDS, EKS pods, S3, SES, Stripe API |

### 5.4 Impersonation

**How it works:**
1. Super-admin clicks "Impersonate" on a user
2. Backend creates a temporary session for that user with `impersonatedBy: superAdminId` flag
3. Super-admin sees the app exactly as that user sees it
4. Yellow banner at top: "You are impersonating {userName}. Click here to exit."
5. All actions taken while impersonating are logged in audit trail with `impersonatedBy` field

**Security:**
- Impersonation sessions expire after 1 hour
- Cannot impersonate other super-admins
- All impersonation events logged
- Impersonation creates a NEW session — does not modify the super-admin's session

### 5.5 How This Works With Current Infra

- **No new AWS resources** — admin dashboard is just more React pages + API routes in the same app
- **Admin access** controlled by `isSuperAdmin` flag in existing `users` table in RDS
- **Grafana** (already deployed at `http://a8afc157eacc24326b394e8a1dea8465-1678634722.us-east-1.elb.amazonaws.com`) provides infrastructure monitoring — admin health tab can link to it
- **RDS query performance** for admin stats: add materialized views or caching with Redis (or use PostgreSQL's built-in `pg_stat_statements` for now)

---

## Phase 6: Domain Auto-Join & SSO

**Goal:** Allow enterprise clients to configure automatic org membership for users from their email domain, and support SAML/OIDC SSO.

**Estimated Effort:** 3-4 days

### 6.1 Domain Auto-Join

**Schema:**

```typescript
export const orgDomains = pgTable("org_domains", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id),
  domain: text("domain").notNull(),           // e.g., "aricatech.xyz"
  verified: boolean("verified").default(false),
  verificationToken: text("verification_token"),
  verificationMethod: text("verification_method").default("dns_txt"),
  // dns_txt: add TXT record securenexus-verify={token} to domain DNS
  defaultRole: text("default_role").default("analyst"),
  autoJoinEnabled: boolean("auto_join_enabled").default(false),
  verifiedAt: timestamp("verified_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  uniqueIndex("idx_org_domains_domain").on(table.domain),
  index("idx_org_domains_org").on(table.orgId),
]);
```

**Routes:**

```
POST /api/orgs/:orgId/domains                    → Add domain claim
GET  /api/orgs/:orgId/domains                    → List claimed domains
POST /api/orgs/:orgId/domains/:domainId/verify   → Verify domain ownership (checks DNS)
DELETE /api/orgs/:orgId/domains/:domainId         → Remove domain claim
PATCH /api/orgs/:orgId/domains/:domainId          → Update default role, auto-join toggle
```

**Auto-join logic (modify `ensureOrgMembership` in `server/replit_integrations/auth/routes.ts`):**

```
1. User signs up with email user@aricatech.xyz
2. Check orgDomains for domain "aricatech.xyz" where verified=true AND autoJoinEnabled=true
3. If found → auto-create membership with defaultRole
4. If not found → proceed with normal flow (create personal org)
```

**Domain verification:**

1. Owner adds domain `aricatech.xyz`
2. System generates verification token: `securenexus-verify=abc123def456`
3. Owner adds TXT record to DNS: `securenexus-verify=abc123def456`
4. Owner clicks "Verify" → backend does DNS lookup for TXT records → if match, set `verified=true`

### 6.2 SAML/OIDC SSO (Enterprise Plan Only)

**New dependency:** `passport-saml` or `@node-saml/passport-saml`

**Schema:**

```typescript
export const ssoConfigs = pgTable("sso_configs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id).unique(),
  protocol: text("protocol").notNull(),          // "saml" or "oidc"
  // SAML fields
  entryPoint: text("entry_point"),               // IdP SSO URL
  issuer: text("issuer"),                        // SP Entity ID
  cert: text("cert"),                            // IdP certificate (PEM)
  // OIDC fields
  oidcClientId: text("oidc_client_id"),
  oidcClientSecret: text("oidc_client_secret"),  // encrypted at rest
  oidcDiscoveryUrl: text("oidc_discovery_url"),  // e.g., https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration
  // Common
  defaultRole: text("default_role").default("analyst"),
  enforced: boolean("enforced").default(false),   // if true, only SSO login allowed (no email/password)
  enabled: boolean("enabled").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_sso_configs_org").on(table.orgId),
]);
```

**Routes:**

```
GET  /api/auth/sso/:orgSlug                      → Initiate SSO login (redirects to IdP)
POST /api/auth/sso/:orgSlug/callback              → SAML assertion consumer / OIDC callback
GET  /api/orgs/:orgId/sso-config                  → Get SSO config (admin+)
PUT  /api/orgs/:orgId/sso-config                  → Create/update SSO config (owner only)
POST /api/orgs/:orgId/sso-config/test             → Test SSO connection
DELETE /api/orgs/:orgId/sso-config                → Remove SSO config (owner only)
```

**SSO login flow:**

```
User navigates to https://nexus.aricatech.xyz/sso/{orgSlug}
  │
  ▼
Backend looks up SSO config for orgSlug
  │
  ▼ SAML                          ▼ OIDC
  Redirect to IdP entryPoint      Redirect to OIDC authorize URL
  │                                │
  ▼                                ▼
  User authenticates at IdP        User authenticates at IdP
  │                                │
  ▼                                ▼
  IdP POSTs SAML assertion to      IdP redirects with auth code to
  /api/auth/sso/{slug}/callback    /api/auth/sso/{slug}/callback
  │                                │
  ▼                                ▼
  Validate assertion/token → Extract email → Find/create user → Create session → Redirect to dashboard
```

**Landing page change:** Add "Sign in with SSO" button that shows org slug input → redirects to SSO flow.

### 6.3 How This Works With Current Infra

- **DNS verification** uses Node.js `dns.resolveTxt()` — no external service needed
- **SAML certificates** stored encrypted in RDS — no need for certificate management service
- **SSO endpoints** served by existing Express app in EKS
- **Passport strategies** dynamically loaded per-org (not at startup) since each org has different IdP config
- **Enterprise plan gate**: SSO config UI only shown if org subscription plan has `ssoEnabled: true`

---

## Phase 7: MSSP / Parent-Child Organizations

**Goal:** Allow Managed Security Service Providers (MSSPs) to manage multiple client organizations from a single parent account.

**Estimated Effort:** 2-3 days

### 7.1 Schema Changes

```typescript
// Extend organizations table
parentOrgId: varchar("parent_org_id").references(() => organizations.id),
orgType: text("org_type").default("standard"),   // "standard", "mssp_parent", "mssp_child"
```

```typescript
export const msspAccessGrants = pgTable("mssp_access_grants", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  parentOrgId: varchar("parent_org_id").notNull().references(() => organizations.id),
  childOrgId: varchar("child_org_id").notNull().references(() => organizations.id),
  grantedRole: text("granted_role").notNull().default("analyst"),
  // what role MSSP analysts get in the child org
  scope: jsonb("scope").default({}),
  // which permission scopes are granted: { incidents: ["read", "write"], connectors: ["read"] }
  grantedAt: timestamp("granted_at").defaultNow(),
  grantedBy: varchar("granted_by"),
  revokedAt: timestamp("revoked_at"),
}, (table) => [
  uniqueIndex("idx_mssp_access_parent_child").on(table.parentOrgId, table.childOrgId),
  index("idx_mssp_access_parent").on(table.parentOrgId),
  index("idx_mssp_access_child").on(table.childOrgId),
]);
```

### 7.2 Routes

```
POST /api/orgs/:parentOrgId/clients                    → Create child org for MSSP client
GET  /api/orgs/:parentOrgId/clients                    → List all child orgs
POST /api/orgs/:parentOrgId/clients/:childOrgId/grant  → Grant MSSP team access to child org
DELETE /api/orgs/:parentOrgId/clients/:childOrgId/grant → Revoke access
GET  /api/orgs/:parentOrgId/clients/overview            → Aggregated stats across all child orgs
```

### 7.3 MSSP Dashboard

**New file:** `client/src/pages/mssp-dashboard.tsx`

**Content:**
- List of all client orgs with health status, alert counts, open incidents
- Aggregated metrics across all clients
- Quick switch to any client org (using org switcher)
- Consolidated alert view across all client orgs
- Per-client SLA tracking

### 7.4 How This Works With Current Infra

- **Same database** — parent-child relationship is a self-referential FK on `organizations` table
- **Org switcher** (Phase 1) already supports switching — MSSP users just have more orgs to switch between
- **RBAC middleware** already reads `X-Org-Id` header — no changes needed
- **Data isolation** maintained — each child org has its own `orgId` on all tables

---

## Phase 8: Usage Metering & Plan Enforcement

**Goal:** Track resource consumption per org and enforce plan limits at the API level.

**Estimated Effort:** 2-3 days

### 8.1 Usage Tracking Schema

```typescript
export const usageRecords = pgTable("usage_records", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orgId: varchar("org_id").notNull().references(() => organizations.id),
  metric: text("metric").notNull(),
  // "alerts_ingested", "api_calls", "ai_analyses", "storage_bytes", "connector_syncs"
  value: integer("value").notNull().default(0),
  periodStart: timestamp("period_start").notNull(),
  periodEnd: timestamp("period_end").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_usage_org_metric").on(table.orgId, table.metric),
  index("idx_usage_period").on(table.periodStart, table.periodEnd),
  uniqueIndex("idx_usage_org_metric_period").on(table.orgId, table.metric, table.periodStart),
]);
```

### 8.2 Enforcement Middleware

**New file:** `server/plan-enforcement.ts`

```typescript
export function enforcePlanLimit(metric: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const orgId = (req as any).orgId;
    if (!orgId) return next();

    const subscription = await storage.getSubscriptionByOrgId(orgId);
    if (!subscription) return next(); // free plan with defaults

    const plan = await storage.getPlan(subscription.planId);
    const features = plan.features;
    const currentUsage = await storage.getCurrentUsage(orgId, metric);

    const limitMap: Record<string, number | null> = {
      alerts_ingested: features.maxAlerts,
      connectors: features.maxConnectors,
      users: features.maxUsers,
      api_keys: features.maxApiKeys,
      playbooks: features.maxPlaybooks,
    };

    const limit = limitMap[metric];
    if (limit !== null && limit !== undefined && currentUsage >= limit) {
      return res.status(429).json({
        error: "Plan limit reached",
        metric,
        current: currentUsage,
        limit,
        upgradeUrl: "/settings/billing",
      });
    }

    next();
  };
}
```

**Apply to routes:**

| Route | Metric Enforced |
|---|---|
| `POST /api/alerts/ingest` | `alerts_ingested` |
| `POST /api/connectors` | `connectors` |
| `POST /api/orgs/:orgId/invitations` | `users` |
| `POST /api/api-keys` | `api_keys` |
| `POST /api/playbooks` | `playbooks` |
| `POST /api/ai/*` | `ai_analyses` (if `aiEnabled` is false, return 403) |

### 8.3 Usage Dashboard Widget

**In Settings → Plan & Usage section (existing `client/src/pages/settings.tsx`):**

Replace hardcoded progress bars with real data from `GET /api/billing/usage`:

```json
{
  "alerts": { "used": 3247, "limit": 10000, "percent": 32.5 },
  "connectors": { "used": 4, "limit": 10, "percent": 40 },
  "users": { "used": 3, "limit": 5, "percent": 60 },
  "apiKeys": { "used": 2, "limit": 10, "percent": 20 },
  "storage": { "used": "1.2 GB", "limit": "10 GB", "percent": 12 },
  "aiAnalyses": { "used": 47, "limit": 500, "percent": 9.4 }
}
```

### 8.4 Approaching-Limit Notifications

When usage hits 80% of a limit:
1. Show yellow warning banner in dashboard
2. Send email to org owner/admins: "You've used 80% of your monthly alert quota"
3. Show upgrade CTA in the warning

When usage hits 100%:
1. Show red banner: "Plan limit reached — upgrade to continue"
2. API returns 429 with upgrade URL
3. Existing data is NOT deleted — just new ingestion/creation blocked

### 8.5 How This Works With Current Infra

- **Usage counters** stored in RDS — simple `INSERT ... ON CONFLICT DO UPDATE SET value = value + 1`
- **Usage check** on every relevant API call adds ~1ms (single indexed query)
- **Background job** to roll over usage periods: run a CronJob in EKS (`k8s/base/usage-rollover-cronjob.yml`) at midnight UTC on the 1st of each month
- **No Redis needed** — PostgreSQL is fast enough for single-row lookups with proper indexes
- **Grafana** can visualize usage trends using the existing Prometheus + PostgreSQL exporter setup

---

## Phase 9: Security Hardening for Multi-Tenancy

**Goal:** Ensure complete data isolation between organizations, prevent cross-tenant access, and harden the application for enterprise deployment.

**Estimated Effort:** 2-3 days

### 9.1 Data Isolation Audit

Every query that touches org-scoped data MUST include `WHERE org_id = ?`. Audit all storage methods in `server/storage.ts`:

| Check | Current State | Action Needed |
|---|---|---|
| Alerts always filtered by orgId | Most queries include orgId | Audit all 40+ alert methods |
| Incidents always filtered by orgId | Most queries include orgId | Audit all 20+ incident methods |
| Connectors always filtered by orgId | Yes | Verify |
| API keys always filtered by orgId | Yes | Verify |
| Audit logs always filtered by orgId | No — some queries are global | Fix: add orgId filter for non-admin routes |
| AI feedback always filtered by orgId | Partial | Fix |

**Implementation:** Add a `withOrgScope` helper that wraps all queries:

```typescript
function withOrgScope<T>(query: T, orgId: string | null): T {
  if (!orgId) throw new Error("orgId is required for tenant-scoped queries");
  return query.where(eq(table.orgId, orgId));
}
```

### 9.2 API Security Hardening

Based on security best practices:

| Hardening | Implementation | Where |
|---|---|---|
| **Helmet** | Already using `helmet()` in `server/index.ts` | Verify CSP, X-Frame-Options, HSTS |
| **Rate limiting** | Already using `express-rate-limit` (100 req/15min global, stricter on auth) | Add per-org rate limiting |
| **Body size limit** | Already using `express.json({ limit: '1mb' })` | Verify |
| **X-Powered-By** | Already disabled | Verify |
| **CORS** | Not configured (same-origin only) | Add CORS for API-key-authenticated requests |
| **CSRF** | Not implemented | Add `csurf` middleware for all mutating endpoints |
| **Input validation** | Using Zod schemas via `createInsertSchema` | Verify all routes use validation |
| **SQL injection** | Drizzle ORM parameterizes all queries | Safe |
| **XSS** | React auto-escapes output | Verify no `dangerouslySetInnerHTML` usage |
| **Session security** | `httpOnly: true`, `secure: true` in production | Verify `sameSite: 'strict'` |

### 9.3 Per-Org Rate Limiting

```typescript
import rateLimit from "express-rate-limit";

const orgRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (req) => {
    const plan = (req as any).planFeatures;
    if (!plan) return 100;
    return plan.name === "enterprise" ? 10000 : plan.name === "pro" ? 5000 : 1000;
  },
  keyGenerator: (req) => (req as any).orgId || req.ip,
  message: { error: "Rate limit exceeded for your organization" },
});
```

### 9.4 Secrets Management

**Current state:** Secrets stored in AWS Secrets Manager and synced to K8s secrets by CI/CD pipeline.

**Enhancement:**
- Rotate `SESSION_SECRET` every 90 days via a scheduled Lambda
- Rotate RDS password every 90 days via RDS automatic rotation
- Stripe webhook secret rotated when regenerated in Stripe dashboard
- OAuth client secrets rotation procedure documented

### 9.5 Audit Log Enhancement

Add to every audit log entry:

```typescript
ipAddress: text("ip_address"),      // already exists
userAgent: text("user_agent"),      // NEW
orgId: varchar("org_id"),           // already exists
impersonatedBy: varchar("impersonated_by"), // NEW (for super-admin impersonation)
requestId: text("request_id"),      // NEW (for correlating with application logs)
```

### 9.6 How This Works With Current Infra

- **All changes are application-level** — no new AWS resources
- **Rate limiting state** stored in-memory (existing `express-rate-limit` behavior) — fine for single-pod-per-namespace deployments
- **For multi-pod scaling**, use `rate-limit-redis` with an ElastiCache Redis instance — provision only when needed
- **Audit logs** already stored in RDS — just add new columns via Drizzle migration

---

## Phase 10: Audit, Compliance & Data Residency

**Goal:** Meet enterprise compliance requirements (SOC 2, ISO 27001, GDPR) with audit trails, data retention policies, and regional data residency.

**Estimated Effort:** 3-4 days

### 10.1 Compliance Dashboard

**New file:** `client/src/pages/compliance-center.tsx`

**Sections:**

| Section | Content |
|---|---|
| **Framework Coverage** | SOC 2, ISO 27001, NIST CSF, PCI DSS — show coverage % per framework |
| **Control Mapping** | Which SecureNexus features map to which compliance controls |
| **Evidence Locker** | Already exists (`evidence_locker_items` table) — needs UI |
| **Data Retention** | Per-org retention policies — already exists (`compliance_policies` table) |
| **DSAR Processing** | Already exists (`dsar_requests` table) — needs better UI |
| **Audit Export** | Export audit logs as CSV/PDF for auditor review |

### 10.2 Data Retention Enforcement

**Current state:** `compliance_policies` table has `retentionDays` but enforcement is not automated.

**Add K8s CronJob:** `k8s/base/retention-cronjob.yml`

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: data-retention-cleanup
  namespace: production
spec:
  schedule: "0 2 * * *"    # 2 AM UTC daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: retention-cleanup
            image: ${ECR_IMAGE}
            command: ["node", "dist/retention-cleanup.js"]
            envFrom:
            - secretRef:
                name: securenexus-secrets
          restartPolicy: OnFailure
```

**Cleanup script:** `server/retention-cleanup.ts`

```typescript
// For each org:
// 1. Get org's retention policy (from compliance_policies or plan default)
// 2. Delete alerts older than retentionDays
// 3. Delete audit logs older than retentionDays (archive to S3 first)
// 4. Delete ingestion logs older than retentionDays
// 5. Log cleanup stats
```

### 10.3 Data Residency (Future)

**Current:** All data stored in `us-east-1` (RDS, S3, EKS).

**For EU clients (GDPR):**
- Provision separate RDS instance in `eu-west-1`
- Provision separate S3 bucket in `eu-west-1`
- Route EU org traffic to EU infrastructure via Kubernetes namespace isolation
- Store `dataResidency` field on `organizations` table (already exists on `aiDeploymentConfigs`)

**Implementation approach:**
- Add `dataResidency: text("data_residency").default("us")` to `organizations` table
- During onboarding, enterprise clients choose region
- Application reads org's region and connects to the correct database/S3 bucket
- This is a significant architectural change — implement only when EU clients require it

### 10.4 Audit Log Export

**Routes:**

```
GET  /api/audit-logs/export?format=csv&startDate=&endDate=    → Stream CSV download
GET  /api/audit-logs/export?format=pdf&startDate=&endDate=    → Generate PDF report
POST /api/audit-logs/archive                                   → Archive old logs to S3
```

**S3 archive path:** `s3://securenexus-platform-557845624595/audit-archives/{orgId}/{year}/{month}.json.gz`

### 10.5 How This Works With Current Infra

- **CronJobs** run in the existing EKS cluster — same namespace, same image
- **S3 archival** uses existing bucket `securenexus-platform-557845624595`
- **PDF generation** use `pdfkit` or `puppeteer` (if complex layout needed) — runs in EKS pod
- **EU data residency** requires new RDS + S3 in eu-west-1 — only provision when needed

---

## Infrastructure Reference

### Current AWS Resources

| Resource | Identifier | Region |
|---|---|---|
| **AWS Account** | `557845624595` | — |
| **EKS Cluster** | `securenexus` | us-east-1 |
| **RDS PostgreSQL** | `securenexus-db.cspsu4cuei9t.us-east-1.rds.amazonaws.com` | us-east-1 |
| **ECR Repository** | `557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus` | us-east-1 |
| **S3 Bucket** | `securenexus-platform-557845624595` | us-east-1 |
| **Secrets Manager** | `securenexus/staging`, `securenexus/uat`, `securenexus/production` | us-east-1 |
| **VPC Connector** | For App Runner (legacy) | us-east-1 |

### Current EKS Namespaces

| Namespace | URL | Purpose |
|---|---|---|
| `staging` | `http://a04e0b6e1e6064d8087b9efeea03ad62-2085941450.us-east-1.elb.amazonaws.com` | Staging environment |
| `production` | `http://aee5203ae785c4ebab01261c0f93eba4-294515603.us-east-1.elb.amazonaws.com` | Production (canary rollout via Argo) |
| `uat` | UAT environment | User acceptance testing |
| `monitoring` | Prometheus + Grafana | Metrics and dashboards |
| `argo-rollouts` | Argo Rollouts controller | Canary deployment management |

### Custom Domains

| Domain | Points To | Purpose |
|---|---|---|
| `staging.aricatech.xyz` | Staging ELB | Staging access |
| `nexus.aricatech.xyz` | Production ELB | Production access |

### CI/CD Pipeline

```
Push to main
  │
  ▼
GitHub Actions (.github/workflows/ci-cd.yml)
  │
  ├─► Build Docker image
  │   └─► Push to ECR (tagged with commit SHA + latest)
  │
  ├─► Deploy to Staging
  │   ├─► Sync secrets from AWS Secrets Manager
  │   └─► kubectl apply rollout.yml + service.yml
  │
  ├─► Deploy to UAT
  │   ├─► Sync secrets from AWS Secrets Manager
  │   └─► kubectl apply rollout.yml + service.yml
  │
  └─► Deploy to Production
      ├─► Sync secrets from AWS Secrets Manager
      ├─► kubectl apply rollout.yml (Argo Rollout)
      └─► Canary: 20% → 40% → 60% → 80% → 100%
```

### Monitoring

| Tool | URL | Credentials |
|---|---|---|
| **Grafana** | `http://a8afc157eacc24326b394e8a1dea8465-1678634722.us-east-1.elb.amazonaws.com` | admin / SecureNexusGrafana2026 |
| **Prometheus** | Internal (ClusterIP) | Scraped by Grafana |

---

## New AWS Resources Needed (by Phase)

| Phase | Resource | Type | Estimated Cost |
|---|---|---|---|
| Phase 4 | SES verified domain | SES | ~$0.10/1000 emails |
| Phase 4 | SES sending identity | SES | Free |
| Phase 8 | ElastiCache Redis (optional) | ElastiCache | ~$15/month (cache.t3.micro) |
| Phase 10 | EU RDS instance (optional) | RDS | ~$30/month (db.t3.micro) |
| Phase 10 | EU S3 bucket (optional) | S3 | ~$5/month |

**Total additional AWS cost:** ~$0.10/month minimum (SES only), up to ~$50/month with all optional resources.

---

## Implementation Priority Summary

| Phase | Name | Effort | Dependencies |
|---|---|---|---|
| **Phase 1** | Organization Management & Settings | 2-3 days | None |
| **Phase 2** | Business Onboarding Wizard | 3-4 days | Phase 1 |
| **Phase 3** | Subscription & Billing (Stripe) | 4-5 days | Phase 1 |
| **Phase 4** | Invitation System & Email (SES) | 2-3 days | None |
| **Phase 5** | Platform Super-Admin Dashboard | 3-4 days | Phase 3 |
| **Phase 6** | Domain Auto-Join & SSO | 3-4 days | Phase 1 |
| **Phase 7** | MSSP / Parent-Child Organizations | 2-3 days | Phase 1 |
| **Phase 8** | Usage Metering & Plan Enforcement | 2-3 days | Phase 3 |
| **Phase 9** | Security Hardening for Multi-Tenancy | 2-3 days | Phase 1 |
| **Phase 10** | Audit, Compliance & Data Residency | 3-4 days | Phase 8 |

**Critical path:** Phase 1 → Phase 2 → Phase 3 → Phase 5 → Phase 8

**Parallel tracks:**
- Phase 4 (Email) can start in parallel with Phase 1
- Phase 6 (SSO) can start after Phase 1
- Phase 9 (Security) can start after Phase 1

**Total estimated effort:** 27-36 days for all phases.

---

## Quick Reference: Who Can Do What (Final State)

| Action | Owner | Admin | Analyst | Read-Only | Super-Admin |
|---|---|---|---|---|---|
| View dashboard | Y | Y | Y | Y | Y |
| View alerts & incidents | Y | Y | Y | Y | Y |
| Edit alerts & incidents | Y | Y | Y | N | Y |
| Run AI analysis | Y | Y | Y | N | Y |
| Manage connectors | Y | Y | N | N | Y |
| Manage API keys | Y | Y | N | N | Y |
| Execute response actions | Y | Y | Y | N | Y |
| Manage playbooks | Y | Y | Y (limited) | N | Y |
| Invite team members | Y | Y | N | N | Y |
| Change member roles | Y | Y | N | N | Y |
| Suspend/remove members | Y | Y | N | N | Y |
| Edit org settings | Y | Y | N | N | Y |
| Manage billing/subscription | Y | N | N | N | Y |
| Transfer ownership | Y | N | N | N | N |
| Delete organization | Y | N | N | N | Y |
| Configure SSO/SAML | Y | N | N | N | Y |
| Manage domain auto-join | Y | Y | N | N | Y |
| View platform admin panel | N | N | N | N | Y |
| Impersonate users | N | N | N | N | Y |
| View all organizations | N | N | N | N | Y |
| Modify plan limits | N | N | N | N | Y |
