# SecureNexus Enterprise Implementation Roadmap

> Comprehensive phase-by-phase plan for transforming SecureNexus from a single-tenant SOC platform into a fully enterprise-ready, multi-tenant SaaS product with subscription billing, client onboarding, organizational hierarchy, and platform administration.

This document is written as plain descriptive language (no code snippets, no schema definitions) and is meant to be a persistent backlog for product, engineering, and infrastructure work.

For every item below, the structure is:
- Current state (what exists today / what is missing)
- Why it matters (risk, cost, user impact, scalability)
- What to do (exactly what should be implemented or changed)

Scope assumptions (based on current repo + infra conventions):
- Backend: Node.js + Express, Drizzle ORM, PostgreSQL on RDS
- Frontend: React + Vite + Tailwind + Radix
- Deploy: EKS (staging/uat/production), Argo Rollouts, GitHub Actions, AWS Secrets Manager, S3
- Platform: Multi-tenant org model + RBAC + connectors + ingestion + correlation + AI-assisted workflows

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
- [Implementation Priority Summary](#implementation-priority-summary)
- [RBAC Permission Matrix](#quick-reference-who-can-do-what-final-state)

---

## Current State Audit

### What Already Exists

- **Organizations table** in the shared schema with fields for id, name, slug, industry, contactEmail, and maxUsers.
- **Organization Memberships** with orgId, userId, role, status, invitedBy, invitedEmail, joinedAt, and suspendedAt.
- **Org Invitations** with token-based invitations including email, role, expiry, and acceptedAt tracking.
- **RBAC Roles** with four roles defined: owner, admin, analyst, and read_only. Permission scopes cover incidents, connectors, api_keys, response_actions, settings, and team with read/write/admin actions.
- **RBAC Middleware** providing resolveOrgContext, requireOrgRole, requireMinRole, and requirePermission helpers.
- **Team Management UI** with Members tab (list, change role, suspend, activate, remove), Invitations tab (create, cancel), and Audit Trail tab.
- **Technical Onboarding** with a 4-step checklist covering integrations, ingestion, endpoints, and CSPM.
- **Settings Page** with profile section, roles display, hardcoded plan cards (Free/Pro/Enterprise), threat intel keys, and webhooks.
- **Auth Routes** for register, login, logout, Google OAuth, GitHub OAuth, and a providers endpoint.
- **Auto-Provisioning** where new users auto-create an org or join the first existing org via ensureOrgMembership.
- **Audit Logs** with a full audit trail table tracking userId, action, resourceType, resourceId, details, and ipAddress.
- **API Key Auth** as an alternative auth mechanism via X-API-Key header for programmatic access.

### What's Missing

- **No subscription/billing tables** — cannot enforce plan limits or collect payment (addressed in Phase 3).
- **No Stripe integration** — no payment processing (addressed in Phase 3).
- **No business onboarding wizard** — users land on technical onboarding without org setup or plan selection (addressed in Phase 2).
- **No org switcher UI** — users in multiple orgs cannot switch between them (addressed in Phase 1).
- **No org settings page** — cannot edit org name, logo, industry, or contact info (addressed in Phase 1).
- **No invitation emails** — invitations exist in DB but no email is sent (addressed in Phase 4).
- **No plan limit enforcement** — maxUsers exists but is never checked; no alert/connector limits enforced (addressed in Phase 8).
- **No platform admin panel** — no way to view all orgs, subscriptions, or platform metrics (addressed in Phase 5).
- **No domain auto-join** — cannot auto-assign users by email domain to an org (addressed in Phase 6).
- **No SSO/SAML** — enterprise clients need SSO, currently only email + Google + GitHub (addressed in Phase 6).
- **No parent-child orgs** — MSSPs cannot manage multiple client orgs (addressed in Phase 7).
- **No usage metering** — cannot track alerts ingested, API calls, or storage used per org (addressed in Phase 8).
- **No data residency controls** — all data in us-east-1, no per-org region selection (addressed in Phase 10).

---

## Phase 1: Organization Management & Settings

**Goal:** Let org owners manage their organization details and switch between orgs.

**Estimated Effort:** 2-3 days

### 1.1 Organization Settings Page

- Current state: No dedicated org settings page exists. Org details cannot be edited after creation.
- Why it matters: Org owners need to manage their organization's identity, contact information, and branding without asking a platform admin. This is table stakes for any multi-tenant SaaS product.
- What to do:
  - Create a new org settings page with sections for General (org name, slug as read-only, industry dropdown, company size), Contact (contact email, billing email, phone, address), Branding (logo upload to S3, primary color hex for white-labeling), and a Danger Zone (delete organization, owner-only with confirmation requiring the user to type the org name).
  - Add backend routes for getting org details (any member), updating org details (admin+), deleting org (owner only), uploading logo to S3 (admin+), and transferring ownership (owner only).
  - Extend the organizations table with new columns for companySize, billingEmail, phone, address (as JSON), logoUrl, primaryColor, timezone, deletedAt (soft delete), and updatedAt.
  - Logo uploads go to the existing S3 bucket under the key path orgs/{orgId}/logo.{ext}. DB schema migration via Drizzle against the existing RDS instance. No new AWS resources needed.

### 1.2 Organization Switcher

- Current state: Users who belong to multiple orgs have no way to switch between them in the UI.
- Why it matters: Enterprise users, consultants, and MSSP analysts often belong to multiple organizations and need seamless context switching.
- What to do:
  - On app load, fetch all org memberships for the current user from the auth endpoint.
  - Store the active org ID in React context and localStorage for persistence.
  - Attach X-Org-Id header to all API calls (already supported by the resolveOrgContext middleware in the RBAC module).
  - Add a dropdown in the sidebar header showing the current org name with the ability to switch. Switching orgs refreshes all queries via query client invalidation.
  - Create an org context provider exposing the current org, memberships, current role, switch function, and loading state.

### 1.3 Ownership Transfer

- Current state: No mechanism to transfer org ownership to another member.
- Why it matters: When founders leave, teams restructure, or companies get acquired, ownership must be transferable without losing continuity.
- What to do:
  - Add a transfer-ownership route that verifies the current user is the owner, verifies the target user is an active member, updates the current owner's role to admin, updates the target user's role to owner, and creates an audit log entry.
  - Require the current owner to re-enter their password before transfer as a safeguard.

---

## Phase 2: Business Onboarding Wizard

**Goal:** Guide new clients through a complete onboarding flow: create org, choose plan, invite team, connect first integration.

**Estimated Effort:** 3-4 days

### 2.1 Onboarding Flow Architecture

- Current state: New users are auto-provisioned into an org with a generic name and land on a technical onboarding checklist. There is no plan selection, no team invitation step, and no guided tour.
- Why it matters: First impressions determine activation. Without a structured business onboarding, users miss critical setup steps and churn before seeing value.
- What to do:
  - Build a multi-step wizard with five steps: (1) Create Organization with name, industry, and company size; (2) Choose Plan from Free, Pro, or Enterprise with Stripe Checkout for paid plans; (3) Invite Team with bulk email input and role assignment, plus a skip option for solo users; (4) Connect First Integration by picking from the connector catalog with guided setup and test connection; (5) Dashboard Tour with an interactive overlay highlighting key features that can be dismissed and replayed from Settings.
  - Create new frontend files: a wizard container page with progress bar, and separate step components for org creation, plan selection, team invitation, integration connection, and the dashboard tour.
  - Add backend routes for getting wizard status (current step + completion), creating org with extended fields, selecting a plan (Stripe checkout or free activation), bulk-creating invitations, and marking onboarding as complete.
  - Track onboarding progress per org/user with a schema storing the current step, which steps are completed (as a JSON blob), and a completion timestamp.

### 2.2 Auto-Provisioning Changes

- Current state: New users automatically create an org named after their email and are assigned the owner role. No plan is selected, no onboarding happens.
- Why it matters: The auto-provisioning shortcut skips critical business setup steps that determine long-term engagement and revenue.
- What to do:
  - Change the flow so new users without memberships or pending invitations are redirected to the onboarding wizard instead of being auto-assigned to a generic org.
  - Users with pending invitations should auto-accept and skip org creation, going straight to the dashboard.
  - Detect first-time users in the frontend by checking if the authenticated user has zero memberships, and redirect to the onboarding route.

### 2.3 Dashboard Tour

- Current state: No guided tour exists for new users.
- Why it matters: Enterprise SOC platforms are complex. A tour reduces time-to-value and support tickets.
- What to do:
  - Implement an interactive tour (using a lightweight library or custom Radix popovers) with stops covering sidebar navigation overview, dashboard metrics explanation, alert trend chart, command palette shortcut, notification bell, and settings link.
  - Persist tour completion status in the onboarding progress record so it only shows once per user.

### 2.4 Infrastructure Notes

- No new AWS resources needed. All data stored in existing RDS database. Wizard pages served by existing Vite frontend via client-side routing. Stripe Checkout redirects happen client-side with no new server infrastructure. CI/CD pipeline deploys wizard code alongside existing app via same Docker image to ECR to EKS flow.

---

## Phase 3: Subscription & Billing (Stripe)

**Goal:** Implement a complete subscription lifecycle with Stripe: plan selection, checkout, upgrades/downgrades, invoices, and cancellation.

**Estimated Effort:** 4-5 days

### 3.1 Plan Definitions

- Current state: Plan cards exist in the settings page but are hardcoded with no backend enforcement.
- Why it matters: Revenue collection and feature gating are fundamental to SaaS viability.
- What to do:
  - Define four plan tiers: Free, Pro ($49/month), Enterprise ($199/month), and Custom.
  - Feature limits per plan: alerts per month (100 / 10,000 / unlimited / custom), connectors (2 / 10 / unlimited / custom), users (1 / 5 / unlimited / custom), data retention (7 / 30 / 365 days / custom), API keys (1 / 10 / 50 / custom), custom playbooks (none / 5 / unlimited / custom).
  - Feature flags per plan: AI engine (no / yes / yes / yes), SOAR automation (no / no / yes / yes), CSPM scanning (no / yes / yes / yes), IOC threat intel (no / yes / yes / yes), SSO/SAML (no / no / yes / yes), compliance reports (no / no / yes / yes), priority support (no / no / yes / yes), SLA guarantee (none / none / 99.9% / custom).

### 3.2 Database Schema

- Current state: No plans, subscriptions, or invoices tables exist.
- Why it matters: Without persistent billing state, the platform cannot track who is on which plan, when payments are due, or what limits apply.
- What to do:
  - Create a plans table storing plan name (unique), display name, description, monthly and annual prices (in cents), Stripe price IDs for both billing cycles, a features JSON blob containing all limits and flags, active status, and sort order.
  - Create a subscriptions table linking each org (unique) to a plan with status tracking (trialing, active, past_due, cancelled, paused), billing cycle (monthly or annual), Stripe customer and subscription IDs, trial end date, current period start/end, cancellation date and reason, custom feature overrides for custom plans, and proper indexes on orgId, stripeCustomerId, and status.
  - Create an invoices table storing org and subscription references, Stripe invoice ID, amounts due and paid (in cents), currency, status (draft, open, paid, void, uncollectible), PDF and hosted URLs, period dates, and payment date, with indexes on orgId and subscriptionId.

### 3.3 Stripe Integration

- Current state: No payment processing exists.
- Why it matters: Without Stripe, there is no way to collect revenue from paid plans or manage the subscription lifecycle.
- What to do:
  - Add the Stripe npm package and create a Stripe service module.
  - Store Stripe keys (secret key, webhook secret, publishable key) in AWS Secrets Manager and sync them to K8s secrets via the CI/CD pipeline.
  - Add backend routes for creating a Stripe Checkout session, creating a Stripe Customer Portal session, getting current subscription details, changing plans (upgrade/downgrade), cancelling (end of period), reactivating cancelled subscriptions, listing invoices, getting usage vs limits, and a Stripe webhook endpoint.
  - Handle webhook events: checkout.session.completed (activate subscription), invoice.paid (record invoice, update period), invoice.payment_failed (set status to past_due, notify owner via email), customer.subscription.updated (sync plan changes), customer.subscription.deleted (set cancelled, downgrade to free), and customer.subscription.trial_will_end (send warning email 3 days before).
  - Webhook security: verify Stripe signature, exclude from session auth (uses Stripe signature instead), exclude from CSRF, and exclude from rate limiting.

### 3.4 Frontend: Billing Page

- Current state: Settings page has hardcoded plan cards with no real billing functionality.
- Why it matters: Users need self-service plan management, payment visibility, and upgrade paths.
- What to do:
  - Create a billing page with sections for Current Plan (plan name, status badge, renewal date, usage meters for alerts, connectors, users, API keys), Plan Comparison (three cards with feature matrix and Current/Upgrade/Contact Sales buttons), Payment Method (card on file with last 4 digits, Manage button opens Stripe Customer Portal), Invoices (table with date, amount, status, PDF download), and Cancel/Reactivate (danger zone showing what access will be lost).

### 3.5 Infrastructure Notes

- Stripe API calls happen server-side from EKS pods with no new AWS resources needed. The Stripe webhook endpoint receives POSTs from Stripe and is already publicly accessible via the ELB. Plans table is seeded via the existing seed mechanism. The frontend adds a billing page to the existing React router in the same Docker image and deployment.

---

## Phase 4: Invitation System & Email (SES)

**Goal:** Send actual invitation emails, password reset emails, and billing notifications via Amazon SES.

**Estimated Effort:** 2-3 days

### 4.1 Amazon SES Setup

- Current state: Invitations exist in the database but no email is ever sent. There is no password reset flow.
- Why it matters: Without email delivery, invitations are useless, password resets are impossible, and billing notifications cannot reach users. Email is a critical communication channel for any SaaS product.
- What to do:
  - Verify the aricatech.xyz domain in SES via DNS TXT record.
  - Set up a sending identity (noreply@aricatech.xyz) for transactional emails.
  - Create an SES configuration set for tracking bounces and complaints.
  - Add ses:SendEmail and ses:SendRawEmail permissions to the EKS pod IAM role.
  - SES is already available in us-east-1 under the existing AWS account. No new infrastructure needed beyond domain verification and IAM policy.

### 4.2 Email Service

- Current state: No email sending capability exists in the application.
- Why it matters: Transactional email is a foundational SaaS capability that enables invitations, notifications, and security flows.
- What to do:
  - Create an email service module using the AWS SES v2 client that accepts recipient(s), subject, HTML body, and optional plain text.
  - Use the existing AWS credentials already available in K8s secrets (no separate SES keys needed).
  - The AWS SES v2 client is included in the AWS SDK already available in the project, so no new npm dependencies are required.

### 4.3 Email Templates

- Current state: No email templates exist.
- Why it matters: Consistent, branded emails build trust and reduce support burden.
- What to do:
  - Create templates using simple string interpolation (no external dependency) for: invitation (triggered when an admin creates an invitation), welcome (triggered on registration completion), password reset (triggered on forgot-password request, link expires in 1 hour), payment failed (triggered by Stripe webhook), trial ending (triggered 3 days before trial ends), subscription cancelled (triggered by Stripe webhook, shows access end date), member suspended (triggered when an admin suspends a member), and member role changed (triggered on role update).

### 4.4 Password Reset Flow

- Current state: No password reset mechanism exists at all.
- Why it matters: Users who forget their password are completely locked out. This is a critical security and usability gap.
- What to do:
  - Add routes for forgot-password (generates a reset token, sends email) and reset-password (validates token, updates password).
  - Create a password_reset_tokens table with userId, token (unique), expiresAt, usedAt, and createdAt, with indexes on userId and token.
  - Create frontend pages for forgot-password (email input form) and reset-password (new password form accessed via token in URL).

### 4.5 Invitation Email Flow

- Current state: Admin creates invitation, token is stored in DB, but nothing else happens. The invited user must manually navigate to the app and somehow know to accept.
- Why it matters: Invitations without email delivery have near-zero conversion. This is the primary bottleneck for team growth.
- What to do:
  - When an admin creates an invitation, send an email via SES containing a link to accept the invitation at the production domain.
  - When the user clicks the link: if logged in, auto-accept the invitation; if not logged in, redirect to signup with invitation context preserved.
  - After signup/login with invitation context, auto-accept the invitation and land the user in the org's dashboard.
  - Create a frontend page for accepting invitations that handles both authenticated and unauthenticated states.

### 4.6 Infrastructure Notes

- SES is already available in the AWS account (us-east-1) and just needs domain verification. EKS pods already have AWS credentials via K8s secrets; just add SES permissions to the IAM role. DNS records for SES verification are added alongside existing CNAME records for the custom domains.

---

## Phase 5: Platform Super-Admin Dashboard

**Goal:** Build an internal admin panel for platform operators to manage all organizations, subscriptions, and platform health.

**Estimated Effort:** 3-4 days

### 5.1 Super-Admin Role

- Current state: No platform-level admin role exists. There is no way to manage all organizations from a single view.
- Why it matters: Platform operators need visibility into all tenants for support, billing management, and incident response. Without this, every admin action requires direct database access.
- What to do:
  - Add an isSuperAdmin boolean flag to the users table, defaulting to false.
  - Create a requireSuperAdmin middleware that checks this flag and returns 403 if not set.
  - The super-admin flag is ONLY set directly in the database by a DBA. No API endpoint can set it. This prevents privilege escalation.

### 5.2 Admin API Routes

- Current state: No admin-specific routes exist.
- Why it matters: Platform operators need programmatic access to all tenant data for support, compliance, and business intelligence.
- What to do:
  - Create routes under /api/admin/ protected by the requireSuperAdmin middleware for: platform-wide stats, listing all orgs with pagination/search/filters, getting full org details including subscription/members/usage, updating orgs (custom plan limits), suspending/activating entire orgs, listing all users across all orgs, getting user details with all org memberships, generating impersonation sessions, disabling user accounts, forcing password resets, viewing all subscriptions with status filters, getting MRR breakdown, viewing platform-wide audit logs, and checking platform health (RDS, EKS, S3, SES status).

### 5.3 Admin Dashboard UI

- Current state: No admin UI exists.
- Why it matters: A visual admin panel makes platform operations efficient and reduces the risk of direct database mistakes.
- What to do:
  - Create an admin dashboard at /admin (only visible to super-admins) with a full-width layout and its own nav tabs.
  - Include tabs for Overview (total orgs, total users, total alerts, MRR, growth charts), Organizations (searchable table with name, plan, status, users, alerts, created date, actions), Users (searchable table with name, email, orgs, last login, status, actions for impersonate and disable), Subscriptions (table with org, plan, status, amount, renewal date, payment method status), Revenue (MRR chart, plan distribution pie chart, churn rate, upgrade/downgrade trends), Audit Log (platform-wide log with filters for org, user, action type, date range), and Health (real-time status of RDS, EKS pods, S3, SES, Stripe API).

### 5.4 Impersonation

- Current state: No way for platform operators to see the app as a specific user sees it.
- Why it matters: Support engineers need to reproduce user-reported issues without asking users for credentials.
- What to do:
  - When a super-admin clicks "Impersonate" on a user, the backend creates a temporary session for that user with an impersonatedBy flag referencing the super-admin.
  - The super-admin sees the app exactly as that user sees it, with a yellow banner at top showing who they are impersonating and a button to exit.
  - All actions taken while impersonating are logged in the audit trail with the impersonatedBy field.
  - Security: impersonation sessions expire after 1 hour, cannot impersonate other super-admins, all impersonation events are logged, and impersonation creates a NEW session without modifying the super-admin's existing session.

### 5.5 Infrastructure Notes

- No new AWS resources needed. The admin dashboard is just more React pages and API routes in the same app. Admin access is controlled by the isSuperAdmin flag in the existing users table in RDS. The existing Grafana deployment provides infrastructure monitoring and the admin health tab can link to it. For admin stats query performance, use materialized views or caching, or leverage PostgreSQL's built-in pg_stat_statements initially.

---

## Phase 6: Domain Auto-Join & SSO

**Goal:** Allow enterprise clients to configure automatic org membership for users from their email domain, and support SAML/OIDC SSO.

**Estimated Effort:** 3-4 days

### 6.1 Domain Auto-Join

- Current state: No mechanism for automatic org membership based on email domain.
- Why it matters: Enterprise clients with hundreds of employees need frictionless onboarding. Manually inviting every user is not scalable.
- What to do:
  - Create an org_domains table with orgId, domain, verified status, verification token, verification method (DNS TXT), default role for auto-joined users, auto-join toggle, verification timestamp, and creation timestamp. Add a unique index on domain and an index on orgId.
  - Add routes for claiming a domain, listing claimed domains, verifying domain ownership via DNS lookup, removing domain claims, and updating default role and auto-join toggle.
  - Modify the auto-provisioning logic so that when a user signs up, the system checks for a verified domain with auto-join enabled matching their email domain. If found, auto-create membership with the configured default role. If not found, proceed with the normal flow of creating a personal org.
  - Domain verification works by: owner adds a domain, system generates a verification token, owner adds a TXT record to their DNS with that token, and the backend does a DNS lookup to confirm the match.

### 6.2 SAML/OIDC SSO (Enterprise Plan Only)

- Current state: Authentication is limited to email/password, Google OAuth, and GitHub OAuth. No SAML or OIDC support exists.
- Why it matters: Enterprise clients require SSO integration with their identity providers (Okta, Azure AD, etc.) for security compliance, centralized access control, and employee lifecycle management.
- What to do:
  - Create an sso_configs table with orgId (unique per org), protocol (SAML or OIDC), SAML-specific fields (entry point URL, issuer/SP entity ID, IdP certificate in PEM format), OIDC-specific fields (client ID, client secret encrypted at rest, discovery URL), common fields (default role, enforced flag to disable password login, enabled toggle), and timestamps. Add an index on orgId.
  - Add routes for initiating SSO login (redirects to IdP), handling the SAML assertion consumer or OIDC callback, getting SSO config (admin+), creating/updating SSO config (owner only), testing SSO connection, and removing SSO config (owner only).
  - The SSO login flow: user navigates to the SSO URL for their org slug, backend looks up the SSO config, redirects to the IdP (SAML entry point or OIDC authorize URL), user authenticates at the IdP, IdP posts back the SAML assertion or redirects with an auth code, backend validates the assertion/token, extracts the email, finds or creates the user, creates a session, and redirects to the dashboard.
  - Add a "Sign in with SSO" button on the landing page that shows an org slug input and redirects to the SSO flow.
  - SSO config UI is only shown if the org's subscription plan has SSO enabled.

### 6.3 Infrastructure Notes

- DNS verification uses Node.js built-in dns.resolveTxt with no external service needed. SAML certificates are stored encrypted in RDS with no certificate management service required. SSO endpoints are served by the existing Express app in EKS. Passport strategies are dynamically loaded per-org (not at startup) since each org has different IdP config.

---

## Phase 7: MSSP / Parent-Child Organizations

**Goal:** Allow Managed Security Service Providers (MSSPs) to manage multiple client organizations from a single parent account.

**Estimated Effort:** 2-3 days

### 7.1 Parent-Child Org Model

- Current state: All organizations are flat peers with no hierarchy.
- Why it matters: MSSPs are a major market segment for SOC platforms. They need to manage dozens of client orgs from a single account with controlled access and aggregated visibility.
- What to do:
  - Extend the organizations table with a parentOrgId (self-referential foreign key) and an orgType field (standard, mssp_parent, mssp_child).
  - Create an mssp_access_grants table defining what access the parent org's team gets in each child org, with fields for parentOrgId, childOrgId, granted role, scope (JSON defining which permission scopes are granted per resource type), grant metadata (who granted, when), and revocation tracking. Add a unique composite index on parentOrgId + childOrgId, plus individual indexes on each.
  - Add routes for creating a child org for an MSSP client, listing all child orgs, granting MSSP team access to a child org with specific role and scope, revoking access, and getting aggregated stats across all child orgs.

### 7.2 MSSP Dashboard

- Current state: No aggregated view across multiple organizations exists.
- Why it matters: MSSP analysts need a single pane of glass to monitor all their clients without constantly switching contexts.
- What to do:
  - Create an MSSP dashboard page showing a list of all client orgs with health status, alert counts, and open incidents; aggregated metrics across all clients; quick switch to any client org via the org switcher; a consolidated alert view across all client orgs; and per-client SLA tracking.

### 7.3 Infrastructure Notes

- Same database with parent-child relationship as a self-referential FK on the organizations table. The org switcher from Phase 1 already supports switching, and MSSP users just have more orgs to switch between. The RBAC middleware already reads the X-Org-Id header with no changes needed. Data isolation is maintained since each child org has its own orgId on all tables.

---

## Phase 8: Usage Metering & Plan Enforcement

**Goal:** Track resource consumption per org and enforce plan limits at the API level.

**Estimated Effort:** 2-3 days

### 8.1 Usage Tracking

- Current state: The maxUsers field exists on organizations but is never checked. No usage tracking or limit enforcement exists.
- Why it matters: Without metering and enforcement, paid plans have no teeth. Users on free plans can consume unlimited resources, and there is no data to drive upgrade conversations.
- What to do:
  - Create a usage_records table with orgId, metric name (alerts_ingested, api_calls, ai_analyses, storage_bytes, connector_syncs), value counter, period start/end timestamps, and indexes on org+metric, period, and a unique composite index on org+metric+period to enable upsert operations.
  - Usage counters are incremented via upsert (insert on conflict update) for efficient single-row operations.

### 8.2 Enforcement Middleware

- Current state: No plan limit enforcement exists at the API level.
- Why it matters: Without enforcement, plan limits are purely advisory and there is no incentive to upgrade.
- What to do:
  - Create a plan enforcement middleware that looks up the current org's subscription and plan, queries current usage for the relevant metric, and returns a 429 response with the current usage, limit, and upgrade URL if the limit is reached.
  - Apply enforcement to: alert ingestion (alerts_ingested limit), connector creation (connectors limit), team invitation (users limit), API key creation (api_keys limit), playbook creation (playbooks limit), and AI analysis endpoints (ai_analyses limit, or 403 if AI is disabled for the plan).

### 8.3 Usage Dashboard Widget

- Current state: Settings page shows hardcoded progress bars for plan usage.
- Why it matters: Users need real-time visibility into their consumption to plan upgrades and manage resources.
- What to do:
  - Replace hardcoded progress bars with real data from the billing usage endpoint, showing used vs limit counts and percentages for alerts, connectors, users, API keys, storage, and AI analyses.

### 8.4 Approaching-Limit Notifications

- Current state: No usage threshold notifications exist.
- Why it matters: Users should be warned before they hit hard limits so they can proactively upgrade rather than being blocked mid-workflow.
- What to do:
  - At 80% usage: show a yellow warning banner in the dashboard, send email to org owner/admins, and show an upgrade CTA.
  - At 100% usage: show a red banner ("Plan limit reached"), API returns 429 with upgrade URL, and existing data is NOT deleted (only new ingestion/creation is blocked).

### 8.5 Infrastructure Notes

- Usage counters stored in RDS with simple upsert operations. Usage checks on relevant API calls add approximately 1ms (single indexed query). A background CronJob in EKS rolls over usage periods at midnight UTC on the 1st of each month. No Redis needed since PostgreSQL is fast enough for single-row lookups with proper indexes. Grafana can visualize usage trends using the existing Prometheus + PostgreSQL exporter setup.

---

## Phase 9: Security Hardening for Multi-Tenancy

**Goal:** Ensure complete data isolation between organizations, prevent cross-tenant access, and harden the application for enterprise deployment.

**Estimated Effort:** 2-3 days

### 9.1 Data Isolation Audit

- Current state: Most queries include orgId filtering, but coverage is not 100% and there is no systematic enforcement.
- Why it matters: Cross-tenant data exposure is an existential risk for a SOC platform. A single leaking query can expose one customer's security data to another.
- What to do:
  - Audit every storage method that touches org-scoped data (40+ alert methods, 20+ incident methods, connectors, API keys, audit logs, AI feedback) to ensure all include orgId filtering.
  - Fix known gaps: audit logs have some global queries that should be org-scoped for non-admin routes, and AI feedback filtering is partial.
  - Implement a withOrgScope helper that wraps all tenant-scoped queries, throwing an error if orgId is not provided rather than silently returning unscoped data.

### 9.2 API Security Hardening

- Current state: Some security measures exist (Helmet, rate limiting, body size limits, X-Powered-By disabled, Zod validation, Drizzle ORM parameterization, React auto-escaping) but coverage is incomplete.
- Why it matters: Enterprises expect baseline OWASP protections and security headers. Gaps increase exploitability and block security reviews.
- What to do:
  - Verify and strengthen existing protections: CSP headers, X-Frame-Options, and HSTS via Helmet; rate limiting with per-org limits added; body size limit verification; CORS configuration for API-key-authenticated requests.
  - Add missing protections: CSRF middleware for all mutating endpoints; verification that all routes use Zod validation; verification of no dangerouslySetInnerHTML usage; session security with sameSite set to strict.

### 9.3 Per-Org Rate Limiting

- Current state: Global rate limiting exists (100 req/15min) but is not plan-aware.
- Why it matters: Enterprise customers need higher limits, while free-tier abuse must be prevented. One-size-fits-all limits either throttle paying customers or leave the platform open to abuse.
- What to do:
  - Implement plan-aware rate limiting: enterprise gets 10,000 requests per 15 minutes, pro gets 5,000, and free gets 1,000. Use orgId as the rate limit key (falling back to IP for unauthenticated requests).

### 9.4 Secrets Management

- Current state: Secrets are stored in AWS Secrets Manager and synced to K8s secrets by the CI/CD pipeline.
- Why it matters: Credential rotation is a compliance requirement and reduces blast radius of any compromise.
- What to do:
  - Rotate SESSION_SECRET every 90 days via a scheduled Lambda.
  - Rotate RDS password every 90 days via RDS automatic rotation.
  - Rotate Stripe webhook secret when regenerated in the Stripe dashboard.
  - Document OAuth client secrets rotation procedure.

### 9.5 Audit Log Enhancement

- Current state: Audit logs capture userId, action, resourceType, resourceId, details, and ipAddress.
- Why it matters: Enterprise compliance and forensics require richer context for every audited event.
- What to do:
  - Add new fields to audit log entries: userAgent, impersonatedBy (for super-admin impersonation tracking), and requestId (for correlating with application logs).

### 9.6 Infrastructure Notes

- All changes are application-level with no new AWS resources. Rate limiting state is stored in-memory (existing express-rate-limit behavior), which is fine for single-pod-per-namespace deployments. For multi-pod scaling, use rate-limit-redis with an ElastiCache Redis instance, provisioned only when needed. Audit log changes are just new columns via Drizzle migration.

---

## Phase 10: Audit, Compliance & Data Residency

**Goal:** Meet enterprise compliance requirements (SOC 2, ISO 27001, GDPR) with audit trails, data retention policies, and regional data residency.

**Estimated Effort:** 3-4 days

### 10.1 Compliance Dashboard

- Current state: Compliance-related tables exist (evidence_locker_items, compliance_policies, dsar_requests) but lack comprehensive UI.
- Why it matters: Enterprise buyers require visible compliance posture, evidence management, and audit export capabilities.
- What to do:
  - Create a compliance center page with sections for Framework Coverage (SOC 2, ISO 27001, NIST CSF, PCI DSS with coverage percentage per framework), Control Mapping (which SecureNexus features map to which compliance controls), Evidence Locker (UI for the existing evidence_locker_items table), Data Retention (per-org retention policies using the existing compliance_policies table), DSAR Processing (better UI for the existing dsar_requests table), and Audit Export (export audit logs as CSV/PDF for auditor review).

### 10.2 Data Retention Enforcement

- Current state: The compliance_policies table has a retentionDays field but enforcement is not automated.
- Why it matters: Without automated retention enforcement, data accumulates indefinitely, increasing storage costs and compliance risk.
- What to do:
  - Create a K8s CronJob that runs daily at 2 AM UTC to enforce retention policies. For each org: get the org's retention policy (from compliance_policies or plan default), delete alerts older than retentionDays, archive audit logs to S3 before deleting, delete ingestion logs older than retentionDays, and log cleanup stats.

### 10.3 Data Residency (Future)

- Current state: All data is stored in us-east-1 (RDS, S3, EKS).
- Why it matters: EU clients under GDPR may require data to reside within EU borders. This is a common enterprise procurement blocker.
- What to do:
  - Provision separate RDS instance and S3 bucket in eu-west-1 for EU clients.
  - Route EU org traffic to EU infrastructure via Kubernetes namespace isolation.
  - Add a dataResidency field to the organizations table.
  - During onboarding, enterprise clients choose their region.
  - The application reads the org's region and connects to the correct database/S3 bucket.
  - This is a significant architectural change and should be implemented only when EU clients require it.

### 10.4 Audit Log Export

- Current state: Audit logs exist in the database but cannot be exported.
- Why it matters: External auditors require downloadable, immutable audit records. This is a hard requirement for SOC 2 and ISO 27001 certification.
- What to do:
  - Add routes for streaming CSV export (with date range filters), generating PDF reports, and archiving old logs to S3.
  - S3 archive path follows the pattern: audit-archives/{orgId}/{year}/{month}.json.gz in the existing S3 bucket.

### 10.5 Infrastructure Notes

- CronJobs run in the existing EKS cluster using the same namespace and image. S3 archival uses the existing bucket. PDF generation uses pdfkit or puppeteer (if complex layout is needed) running in EKS pods. EU data residency requires new RDS + S3 in eu-west-1, provisioned only when needed.

---

## Infrastructure Reference

### Current AWS Resources

- **AWS Account:** 557845624595
- **EKS Cluster:** securenexus in us-east-1
- **RDS PostgreSQL:** securenexus-db.cspsu4cuei9t.us-east-1.rds.amazonaws.com in us-east-1
- **ECR Repository:** 557845624595.dkr.ecr.us-east-1.amazonaws.com/securenexus in us-east-1
- **S3 Bucket:** securenexus-platform-557845624595 in us-east-1
- **Secrets Manager:** securenexus/staging, securenexus/uat, securenexus/production in us-east-1
- **VPC Connector:** For App Runner (legacy) in us-east-1

### Current EKS Namespaces

- **staging** — Staging environment accessible via the staging ELB
- **production** — Production environment with canary rollout via Argo Rollouts, accessible via the production ELB
- **uat** — User acceptance testing environment
- **monitoring** — Prometheus + Grafana for metrics and dashboards
- **argo-rollouts** — Argo Rollouts controller for canary deployment management

### Custom Domains

- **staging.aricatech.xyz** — Points to the staging ELB for staging access
- **nexus.aricatech.xyz** — Points to the production ELB for production access

### CI/CD Pipeline

The pipeline is triggered on every push to main. GitHub Actions builds the Docker image, pushes to ECR tagged with commit SHA and latest, then deploys sequentially: first to staging (sync secrets from Secrets Manager, apply rollout and service manifests), then to UAT (same process), then to production (same process but using Argo Rollout with canary progression at 20%, 40%, 60%, 80%, 100%).

### Monitoring

- **Grafana** is deployed and accessible via the monitoring namespace ELB with admin credentials.
- **Prometheus** runs as a ClusterIP service scraped by Grafana.

---

## New AWS Resources Needed (by Phase)

- **Phase 4:** SES verified domain and sending identity. Estimated cost: approximately $0.10 per 1,000 emails.
- **Phase 8 (optional):** ElastiCache Redis instance for distributed rate limiting. Estimated cost: approximately $15/month for cache.t3.micro.
- **Phase 10 (optional):** EU RDS instance. Estimated cost: approximately $30/month for db.t3.micro.
- **Phase 10 (optional):** EU S3 bucket. Estimated cost: approximately $5/month.

Total additional AWS cost: approximately $0.10/month minimum (SES only), up to approximately $50/month with all optional resources.

---

## Implementation Priority Summary

- **Phase 1** — Organization Management & Settings: 2-3 days, no dependencies.
- **Phase 2** — Business Onboarding Wizard: 3-4 days, depends on Phase 1.
- **Phase 3** — Subscription & Billing (Stripe): 4-5 days, depends on Phase 1.
- **Phase 4** — Invitation System & Email (SES): 2-3 days, no dependencies.
- **Phase 5** — Platform Super-Admin Dashboard: 3-4 days, depends on Phase 3.
- **Phase 6** — Domain Auto-Join & SSO: 3-4 days, depends on Phase 1.
- **Phase 7** — MSSP / Parent-Child Organizations: 2-3 days, depends on Phase 1.
- **Phase 8** — Usage Metering & Plan Enforcement: 2-3 days, depends on Phase 3.
- **Phase 9** — Security Hardening for Multi-Tenancy: 2-3 days, depends on Phase 1.
- **Phase 10** — Audit, Compliance & Data Residency: 3-4 days, depends on Phase 8.

**Critical path:** Phase 1 then Phase 2 then Phase 3 then Phase 5 then Phase 8.

**Parallel tracks:**
- Phase 4 (Email) can start in parallel with Phase 1.
- Phase 6 (SSO) can start after Phase 1.
- Phase 9 (Security) can start after Phase 1.

**Total estimated effort:** 27-36 days for all phases.

---

## Quick Reference: Who Can Do What (Final State)

- **View dashboard:** Owner, Admin, Analyst, Read-Only, Super-Admin.
- **View alerts & incidents:** Owner, Admin, Analyst, Read-Only, Super-Admin.
- **Edit alerts & incidents:** Owner, Admin, Analyst, Super-Admin.
- **Run AI analysis:** Owner, Admin, Analyst, Super-Admin.
- **Manage connectors:** Owner, Admin, Super-Admin.
- **Manage API keys:** Owner, Admin, Super-Admin.
- **Execute response actions:** Owner, Admin, Analyst, Super-Admin.
- **Manage playbooks:** Owner, Admin, Analyst (limited), Super-Admin.
- **Invite team members:** Owner, Admin, Super-Admin.
- **Change member roles:** Owner, Admin, Super-Admin.
- **Suspend/remove members:** Owner, Admin, Super-Admin.
- **Edit org settings:** Owner, Admin, Super-Admin.
- **Manage billing/subscription:** Owner, Super-Admin.
- **Transfer ownership:** Owner only.
- **Delete organization:** Owner, Super-Admin.
- **Configure SSO/SAML:** Owner, Super-Admin.
- **Manage domain auto-join:** Owner, Admin, Super-Admin.
- **View platform admin panel:** Super-Admin only.
