# Phase 15-16 Combined: Advanced Features and Payment/Billing Detailed Report

## 1. Purpose of Combined Document
This file keeps the requested count aligned while covering Phase 16 billing implementation in depth and referencing Phase 15 advanced features.

## 2. Billing Strategy Overview
- Stripe-hosted checkout and billing portal to reduce PCI scope.
- Subscription plans mapped directly to feature entitlements.
- Usage-aware limits enforced by middleware and UI messaging.

## 3. Plan and Entitlement Model
- Plans: `starter`, `growth`, `enterprise`.
- Entitlements example:
- max analysts.
- max connectors.
- AI generation monthly quota.
- advanced features toggle (graph/rules/automation tiers).

## 4. Data Model
- `billing_customers`
- `id`, `orgId`, `stripeCustomerId`, `createdAt`.
- `billing_subscriptions`
- `id`, `orgId`, `stripeSubscriptionId`, `status`, `priceId`, `currentPeriodStart`, `currentPeriodEnd`, `cancelAtPeriodEnd`.
- `billing_invoices`
- `id`, `orgId`, `stripeInvoiceId`, `amountDue`, `currency`, `status`, `hostedInvoiceUrl`.
- `feature_entitlements`
- `orgId`, `featureKey`, `limitValue`, `isEnabled`, `sourcePlan`.

## 5. API Endpoints
- `POST /api/billing/checkout-session`
- `POST /api/billing/portal-session`
- `POST /api/billing/webhook`
- `GET /api/billing/subscription`
- `GET /api/billing/entitlements`

## 6. Webhook Processing
- Verify Stripe signature using endpoint secret.
- Handle events:
- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_failed`
- Idempotent processing by event ID table.

## 7. Feature Gating
- Server middleware checks entitlement before executing paid feature routes.
- UI surfaces plan limitations before action attempts.
- Soft and hard limit strategies configurable per feature.

## 8. UI/UX
- Billing page with:
- current plan.
- renewal date.
- invoice history.
- usage meters.
- upgrade/downgrade flows using Stripe Checkout.

## 9. Security and Compliance
- No card data stored in app database.
- Webhook signature validation mandatory.
- Minimal PII retention.

## 10. Testing
- Webhook signature tests.
- Subscription lifecycle tests.
- Entitlement enforcement tests.

## 11. Rollout
- Launch with manual plan migration fallback.
- Backfill existing orgs to default plan.
- Monitor payment failures and entitlement sync lag.

## 12. Definition of Done
- Subscriptions managed end to end.
- Entitlements enforced on backend and frontend.
- Billing events audited and reliable.
