# Phase 16: Payment and Billing (Stripe) Detailed Implementation Report

## Objective
Deploy production-grade subscription billing and entitlement enforcement for SaaS monetization.

## Current Baseline
- Billing is not fully integrated with feature gating.

## Critical Gaps
- No complete subscription lifecycle in-app.
- No idempotent webhook sync layer.
- Plan limits are not centrally enforced.

## Required Fixes
- Integrate Stripe Checkout and Billing Portal.
- Persist customer/subscription/invoice data.
- Process Stripe webhooks with signature verification and idempotency keys.
- Enforce feature entitlements in API middleware and UI.

## Data Model
- `billing_customers`
- `billing_subscriptions`
- `billing_invoices`
- `feature_entitlements`
- `billing_events`

## API Plan
- `POST /api/billing/checkout-session`
- `POST /api/billing/portal-session`
- `POST /api/billing/webhook`
- `GET /api/billing/subscription`
- `GET /api/billing/entitlements`

## UI Plan
- Billing page with plan details, usage, renew date, and invoices.
- Upgrade/downgrade/cancel workflows.

## Security and Compliance
- No card data in application DB.
- Mandatory webhook signature checks.
- Audit billing state transitions.

## Testing
- Webhook signature and idempotency tests.
- Subscription state transition tests.
- Entitlement enforcement tests.

## Definition of Done
- Subscription lifecycle and feature gating work reliably in production.
