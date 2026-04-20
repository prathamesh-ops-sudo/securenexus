/**
 * Canonical pricing-plan tier identifier used across tenant-isolation,
 * tenant throttling, data-lifecycle retention, and org rate limiting.
 *
 * Previously declared verbatim in four server modules; consolidated here so
 * the set of valid tiers can be changed in one place without drift.
 */
export type PlanTier = "free" | "pro" | "enterprise";
