# Phase 16: Payment and Billing (Stripe) Detailed Report

## Goal
Implement reliable subscription billing with Stripe and enforce feature entitlements by plan.

## What Must Be Fixed
- Billing lifecycle is not integrated end-to-end.
- Plan limits and feature gates are not enforced centrally.
- Subscription events are not synchronized via webhooks.

## Required Work
- Integrate Stripe Checkout for new subscriptions and upgrades.
- Integrate Stripe Customer Portal for self-service billing.
- Process webhook events idempotently and update local subscription state.
- Enforce entitlement checks in backend middleware and frontend UX.

## Data and API Scope
- Tables: `billing_customers`, `billing_subscriptions`, `billing_invoices`, `feature_entitlements`, `billing_events`.
- APIs: `checkout-session`, `portal-session`, `webhook`, `subscription status`, `entitlements`.

## Plan and Entitlement Model
- Plans: starter, growth, enterprise.
- Entitlements: analyst seats, connector limits, AI usage quota, premium feature toggles.
- Support soft-limit warnings and hard-limit enforcement.

## UI Scope
- Billing page with plan details, renewal date, usage meters, and invoice history.
- Upgrade/downgrade controls via Stripe-hosted flows.

## Security and Compliance
- Verify Stripe webhook signatures.
- Keep card data out of application storage.
- Log billing state transitions for auditability.

## Testing
- Webhook signature and idempotency tests.
- Subscription lifecycle state transition tests.
- Entitlement enforcement tests across protected APIs.

## Rollout
- Backfill existing organizations to default plan.
- Enable feature gating in monitor mode first, then enforce.
- Track payment failures and entitlement sync lag metrics.

## Definition of Done
- Billing flow works end-to-end for subscribe/upgrade/downgrade/cancel.
- Entitlements are consistently enforced.
- Billing events are auditable and reliable.
